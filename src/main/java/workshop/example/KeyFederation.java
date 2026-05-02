package example;

import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class KeyFederation {

	/**
	 * Issuer → JWKS URL mapping. Lazily fetch keys from each partner. Cache them
	 * for performance.
	 */
	private final Map<String, JWKSource<SecurityContext>> issuerToKeySource = new ConcurrentHashMap<>();

	/**
	 * Multi-tenanted validation: each issuer (partner) can have different
	 * algorithms, key sizes, rotation policies.
	 */
	public JWTClaimsSet validateFederatedToken(String token, KeyFederationRegistry registry) throws Exception {
		SignedJWT jwt = SignedJWT.parse(token);
		// Extract issuer from unverified claims (safe — we validate with the issuer's
		// own keys below)
		String issuer = jwt.getJWTClaimsSet().getIssuer();

		// Lazy load: fetch JWKS for this issuer only if not cached
		JWKSource<SecurityContext> keySource = issuerToKeySource.computeIfAbsent(issuer, iss -> {
			try {
				String jwksUrl = registry.getJwksUrlForIssuer(iss);
				if (jwksUrl == null) {
					throw new SecurityException("Unknown issuer: " + iss);
				}

				// Wrap with caching and retry
				return JWKSourceBuilder.create(new URL(jwksUrl)).refreshAheadCache(15 * 60 * 1000L, true).retrying(true)
						.build();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		});

		// Validate with partner's keys
		DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(jwt.getHeader().getAlgorithm(), keySource));

		return processor.process(token, null);
	}
}