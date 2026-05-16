package workshop.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.*;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.minidev.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Java port of Kubernetes
 * apiserver/plugin/pkg/authenticator/token/oidc/oidc.go.
 *
 * Thread-safe. Initialize once at startup; reuse for the process lifetime.
 * Closes underlying executors via {@link #close()}.
 */
public final class OidcAuthenticator implements AutoCloseable {

	private static final Logger log = LoggerFactory.getLogger(OidcAuthenticator.class);

	private static final String DEFAULT_USERNAME_PREFIX_FOR_EMAIL = "";
	private static final String DEFAULT_USERNAME_PREFIX_OTHER = "oidc:";
	private static final String DISABLE_PREFIX_SENTINEL = "-";

	private final OidcAuthenticatorOptions opts;
	private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
		Thread t = new Thread(r, "oidc-init");
		t.setDaemon(true);
		return t;
	});

	private final AtomicReference<Verifier> verifier = new AtomicReference<>();
	private final AtomicReference<Throwable> healthError = new AtomicReference<>(
			new OidcException("oidc: authenticator not initialized"));

	/** Holds the wired verifier once discovery has succeeded. */
	private record Verifier(ConfigurableJWTProcessor<SecurityContext> processor, String issuer, Set<String> audiences) {
	}

	/** Public factory — kicks off async initialization. */
	public static OidcAuthenticator create(OidcAuthenticatorOptions opts) {
		OidcAuthenticator a = new OidcAuthenticator(opts);
		a.startAsyncInit();
		return a;
	}

	private OidcAuthenticator(OidcAuthenticatorOptions opts) {
		this.opts = opts;
	}

	// ---------------------------------------------------------------- Init

	private void startAsyncInit() {
		scheduler.execute(() -> {
			// Mirrors Go's wait.PollUntilContextCancel with 10s interval.
			long delaySec = 10;
			while (!Thread.currentThread().isInterrupted()) {
				try {
					initVerifier();
					healthError.set(null);
					log.info("oidc: authenticator initialized for issuer {}", opts.issuerUrl);
					return;
				} catch (Throwable t) {
					healthError.set(t);
					log.warn("oidc: init failed for issuer {} ({}); retrying in {}s", opts.issuerUrl, t.getMessage(),
							delaySec);
					try {
						Thread.sleep(delaySec * 1000L);
					} catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
						return;
					}
				}
			}
		});
	}

	private void initVerifier() throws Exception {
		String discoveryIssuer = opts.discoveryUrlOverride != null ? opts.discoveryUrlOverride : opts.issuerUrl;

		ResourceRetriever retriever = buildResourceRetriever();
		OIDCProviderMetadata metadata = fetchMetadata(discoveryIssuer, retriever);

		// The issuer in the metadata MUST match the configured issuer URL (RFC 8414).
		// For discovery overrides, we still verify against the original issuer URL.
		if (!opts.issuerUrl.equals(metadata.getIssuer().getValue())) {
			throw new OidcException("oidc: issuer mismatch (configured=" + opts.issuerUrl + ", discovered="
					+ metadata.getIssuer().getValue() + ")");
		}

		// Build a cached, auto-refreshing JWKS source.
		URL jwksUrl = metadata.getJWKSetURI().toURL();
		JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(jwksUrl, retriever).cache(true)
				.refreshAheadCache(opts.jwksRefreshAhead.toMillis(), true).rateLimited(15_000L) // do not refetch more
																								// than every 15s
				.retrying(true).build();

		Set<JWSAlgorithm> algs = new HashSet<>();
		for (String a : opts.supportedSigningAlgs)
			algs.add(JWSAlgorithm.parse(a));

		JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(algs, jwkSource);

		DefaultJWTProcessor<SecurityContext> p = new DefaultJWTProcessor<>();
		p.setJWSKeySelector(keySelector);

		// Audience: pass the full set so Nimbus enforces *exactly one* must match.
		// Issuer + exp/iat/nbf are validated here.
		p.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<SecurityContext>(opts.audiences,
				new JWTClaimsSet.Builder().issuer(opts.issuerUrl).build(),
				Set.of("sub", "exp", "iat", "iss"), Set.of()));

		verifier.set(new Verifier(p, opts.issuerUrl, opts.audiences));
	}

	private ResourceRetriever buildResourceRetriever() throws Exception {
		// Prefer custom HttpClient if provided; otherwise fall back to Nimbus's default
		// + custom SSL.
		// For simplicity here we use DefaultResourceRetriever, which uses URLConnection
		// but honors a custom SSLContext.
		DefaultResourceRetriever r = new DefaultResourceRetriever((int) opts.httpTimeout.toMillis(),
				(int) opts.httpTimeout.toMillis());
		// Nimbus DefaultResourceRetriever uses JDK URLConnection and honors the JVM
		// default SSLContext. For per-instance SSLContext, supply a custom
		// ResourceRetriever (e.g. wrapping java.net.http.HttpClient).
		return r;
	}

	private OIDCProviderMetadata fetchMetadata(String issuer, ResourceRetriever r) throws Exception {
		// Build {issuer}/.well-known/openid-configuration, fetch via the configured
		// retriever (so timeouts/HTTP client choice apply), then parse. Nimbus
		// caches nothing here — JWKS caching happens via the JWKSource builder.
		String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
		URL configURL = URI.create(base + "/.well-known/openid-configuration").toURL();
		Resource resource = r.retrieveResource(configURL);
		JSONObject json = JSONObjectUtils.parse(resource.getContent());
		return OIDCProviderMetadata.parse(json);
	}

	// ---------------------------------------------------------------- Auth

	/**
	 * @return user info on success, or {@code null} if the token's issuer does not
	 *         match this authenticator (caller should try the next configured
	 *         authenticator).
	 * @throws OidcException on any verification or claim-mapping failure (caller
	 *                       should reject).
	 */
	public AuthenticatorResponse authenticate(String token) throws OidcException {
		// Fast pre-check: do NOT call the verifier if the token's iss does not match.
		// This matches Go's hasCorrectIssuer() — lets you chain multiple authenticators
		// efficiently.
		if (!hasCorrectIssuer(token)) {
			return null;
		}
		if (opts.disallowedIssuers.contains(extractIssuerUnsafe(token))) {
			throw new OidcException("oidc: issuer is disallowed");
		}

		Verifier v = verifier.get();
		if (v == null) {
			throw new OidcException("oidc: authenticator not initialized");
		}

		JWTClaimsSet claims;
		try {
			claims = v.processor().process(token, null);
		} catch (BadJOSEException e) {
			throw new OidcException("oidc: token verification failed: " + e.getMessage(), e);
		} catch (Exception e) {
			throw new OidcException("oidc: token processing error", e);
		}

		// Required claims (exact string match, same as Go).
		for (ClaimValidationRule rule : opts.validationRules) {
			Object got = claims.getClaim(rule.claim());
			if (got == null) {
				throw new OidcException("oidc: required claim " + rule.claim() + " not present");
			}
			if (rule.requiredValue() != null && !rule.requiredValue().equals(got.toString())) {
				throw new OidcException("oidc: required claim " + rule.claim() + " value mismatch (got=" + got
						+ ", want=" + rule.requiredValue() + ")");
			}
		}

		UserInfo user = mapClaimsToUser(claims);
		return new AuthenticatorResponse(user, opts.audiences);
	}

	private boolean hasCorrectIssuer(String token) {
		String iss = extractIssuerUnsafe(token);
		return iss != null && iss.equals(opts.issuerUrl);
	}

	/**
	 * Parses iss WITHOUT verifying signature — only used for cheap pre-filtering.
	 */
	private static String extractIssuerUnsafe(String token) {
		try {
			return SignedJWT.parse(token).getJWTClaimsSet().getIssuer();
		} catch (ParseException e) {
			return null;
		}
	}

	// ---------------------------------------------------------------- Claim
	// mapping

	private UserInfo mapClaimsToUser(JWTClaimsSet claims) throws OidcException {
		String username = resolveUsername(claims);
		List<String> groups = resolveGroups(claims);
		String uid = resolveUid(claims);
		Map<String, List<String>> extra = resolveExtra(claims);
		return new UserInfo(username, uid, groups, extra);
	}

	private String resolveUsername(JWTClaimsSet claims) throws OidcException {
		ClaimMappings.ClaimMapping m = opts.claimMappings.username();
		Object raw = claims.getClaim(m.claim());
		if (raw == null) {
			throw new OidcException("oidc: username claim '" + m.claim() + "' not present");
		}
		String username = raw.toString();
		if (username.isBlank()) {
			throw new OidcException("oidc: username claim is empty");
		}

		// Special-case email: must be verified.
		if ("email".equals(m.claim())) {
			Object verified = claims.getClaim("email_verified");
			if (verified != null && !Boolean.parseBoolean(verified.toString())) {
				throw new OidcException("oidc: email not verified");
			}
		}

		return applyPrefix(username, m.prefix(),
				"email".equals(m.claim()) ? DEFAULT_USERNAME_PREFIX_FOR_EMAIL : DEFAULT_USERNAME_PREFIX_OTHER);
	}

	private List<String> resolveGroups(JWTClaimsSet claims) {
		if (opts.claimMappings.groups() == null)
			return List.of();
		ClaimMappings.ClaimMapping m = opts.claimMappings.groups();
		Object raw = claims.getClaim(m.claim());
		if (raw == null)
			return List.of();

		List<String> groups = coerceList(raw);
		String prefix = effectivePrefix(m.prefix(), "");
		List<String> out = new ArrayList<>(groups.size());
		for (String g : groups)
			out.add(prefix + g);
		return out;
	}

	private String resolveUid(JWTClaimsSet claims) {
		if (opts.claimMappings.uid() == null)
			return null;
		Object raw = claims.getClaim(opts.claimMappings.uid().claim());
		return raw == null ? null : raw.toString();
	}

	private Map<String, List<String>> resolveExtra(JWTClaimsSet claims) {
		Map<String, ClaimMappings.ClaimMapping> extra = opts.claimMappings.extra();
		if (extra == null || extra.isEmpty())
			return Map.of();
		Map<String, List<String>> out = new HashMap<>();
		for (var e : extra.entrySet()) {
			Object raw = claims.getClaim(e.getValue().claim());
			if (raw == null)
				continue;
			out.put(e.getKey(), coerceList(raw));
		}
		return out;
	}

	private static String applyPrefix(String value, String configured, String defaultPrefix) {
		return effectivePrefix(configured, defaultPrefix) + value;
	}

	private static String effectivePrefix(String configured, String defaultPrefix) {
		if (configured == null)
			return defaultPrefix;
		if (DISABLE_PREFIX_SENTINEL.equals(configured))
			return "";
		return configured;
	}

	@SuppressWarnings("unchecked")
	private static List<String> coerceList(Object raw) {
		if (raw instanceof List<?>l) {
			List<String> out = new ArrayList<>(l.size());
			for (Object o : l)
				out.add(String.valueOf(o));
			return out;
		}
		return List.of(raw.toString());
	}

	// ---------------------------------------------------------------- Health

	public void healthCheck() throws OidcException {
		Throwable t = healthError.get();
		if (t != null) {
			if (t instanceof OidcException oe)
				throw oe;
			throw new OidcException("oidc: not healthy: " + t.getMessage(), t);
		}
	}

	@Override
	public void close() {
		scheduler.shutdownNow();
	}
}
