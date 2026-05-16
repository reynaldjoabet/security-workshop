package workshop.oidc;

import javax.net.ssl.SSLContext;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.*;

public final class OidcAuthenticatorOptions {

	public final String issuerUrl;
	public final Set<String> audiences;
	public final ClaimMappings claimMappings;
	public final List<ClaimValidationRule> validationRules;
	public final Set<String> disallowedIssuers;
	public final Set<String> supportedSigningAlgs; // e.g. {"RS256","RS384","ES256"}
	public final HttpClient httpClient; // optional custom client
	public final SSLContext sslContext; // optional custom TLS
	public final String discoveryUrlOverride; // optional self-hosted override
	public final Duration httpTimeout;
	public final Duration jwksRefreshAhead;
	public final Clock clock;
	public final String apiServerId; // for metrics

	private OidcAuthenticatorOptions(Builder b) {
		this.issuerUrl = Objects.requireNonNull(b.issuerUrl, "issuerUrl");
		this.audiences = Set.copyOf(Objects.requireNonNull(b.audiences, "audiences"));
		if (audiences.isEmpty())
			throw new IllegalArgumentException("at least one audience required");
		this.claimMappings = Objects.requireNonNull(b.claimMappings, "claimMappings");
		if (claimMappings.username() == null)
			throw new IllegalArgumentException("username claim mapping is required");
		this.validationRules = List.copyOf(b.validationRules);
		this.disallowedIssuers = Set.copyOf(b.disallowedIssuers);
		this.supportedSigningAlgs = Set.copyOf(b.supportedSigningAlgs);
		this.httpClient = b.httpClient;
		this.sslContext = b.sslContext;
		this.discoveryUrlOverride = b.discoveryUrlOverride;
		this.httpTimeout = b.httpTimeout;
		this.jwksRefreshAhead = b.jwksRefreshAhead;
		this.clock = b.clock;
		this.apiServerId = b.apiServerId;

		if (disallowedIssuers.contains(issuerUrl))
			throw new IllegalArgumentException("issuerUrl is in disallowedIssuers");
		if (httpClient != null && sslContext != null)
			throw new IllegalArgumentException("httpClient and sslContext are mutually exclusive");
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {
		private String issuerUrl;
		private Set<String> audiences = new HashSet<>();
		private ClaimMappings claimMappings;
		private List<ClaimValidationRule> validationRules = new ArrayList<>();
		private Set<String> disallowedIssuers = new HashSet<>();
		private Set<String> supportedSigningAlgs = Set.of("RS256");
		private HttpClient httpClient;
		private SSLContext sslContext;
		private String discoveryUrlOverride;
		private Duration httpTimeout = Duration.ofSeconds(30);
		private Duration jwksRefreshAhead = Duration.ofMinutes(2);
		private Clock clock = Clock.systemUTC();
		private String apiServerId = "default";

		public Builder issuerUrl(String v) {
			this.issuerUrl = v;
			return this;
		}

		public Builder audience(String v) {
			this.audiences.add(v);
			return this;
		}

		public Builder audiences(Collection<String> v) {
			this.audiences.addAll(v);
			return this;
		}

		public Builder claimMappings(ClaimMappings v) {
			this.claimMappings = v;
			return this;
		}

		public Builder validationRule(ClaimValidationRule v) {
			this.validationRules.add(v);
			return this;
		}

		public Builder disallowedIssuer(String v) {
			this.disallowedIssuers.add(v);
			return this;
		}

		public Builder supportedSigningAlgs(Set<String> v) {
			this.supportedSigningAlgs = v;
			return this;
		}

		public Builder httpClient(HttpClient v) {
			this.httpClient = v;
			return this;
		}

		public Builder sslContext(SSLContext v) {
			this.sslContext = v;
			return this;
		}

		public Builder discoveryUrlOverride(String v) {
			this.discoveryUrlOverride = v;
			return this;
		}

		public Builder httpTimeout(Duration v) {
			this.httpTimeout = v;
			return this;
		}

		public Builder jwksRefreshAhead(Duration v) {
			this.jwksRefreshAhead = v;
			return this;
		}

		public Builder clock(Clock v) {
			this.clock = v;
			return this;
		}

		public Builder apiServerId(String v) {
			this.apiServerId = v;
			return this;
		}

		public OidcAuthenticatorOptions build() {
			return new OidcAuthenticatorOptions(this);
		}
	}
}
