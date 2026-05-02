package example;

import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;
import java.net.URL;
import java.util.concurrent.TimeUnit;

public class ResilientJWKSourceFactory {

	/**
	 * Production-grade JWKS source with: - Refresh-ahead caching (avoids latency
	 * spikes on expiry) - Retry on transient failures - Rate limiting (prevents
	 * hammering the IdP on unknown kid) - Outage tolerance (serves stale cache if
	 * endpoint is down) - Health status reporting
	 */
	public JWKSource<SecurityContext> buildResilientJWKSource(String jwksUrl) throws Exception {
		return JWKSourceBuilder.create(new URL(jwksUrl)).refreshAheadCache(15 * 60 * 1000L, // cache TTL: 15 minutes
				true // refresh ahead before expiry
		).rateLimited(30 * 1000L // min 30s between forced refreshes (on unknown kid)
		).retrying(true) // retry once on transient HTTP failure
				.outageTolerant(60 * 60 * 1000L // serve stale cache for up to 1 hour during outage
				).build();
	}

	/**
	 * With health status reporting — integrate with your observability stack
	 * (Prometheus, Datadog) to alert on JWKS endpoint degradation. Wire a
	 * JWKSetSourceWithHealthStatusReporting.Listener to your metrics system.
	 */
	public JWKSource<SecurityContext> buildWithHealthReporting(String jwksUrl) throws Exception {
		return JWKSourceBuilder.create(new URL(jwksUrl)).refreshAheadCache(15 * 60 * 1000L, true).retrying(true)
				.outageTolerant(60 * 60 * 1000L)
				// .withHealthStatusReporting(listener) — wire to your metrics system
				.build();
	}

	/**
	 * Failover: primary IdP → secondary IdP if primary is unreachable. Critical for
	 * active-active multi-region deployments.
	 */
	public JWKSource<SecurityContext> buildWithFailover(String primaryJwksUrl, String failoverJwksUrl)
			throws Exception {
		JWKSource<SecurityContext> primary = JWKSourceBuilder.create(new URL(primaryJwksUrl)).build();
		JWKSource<SecurityContext> failover = JWKSourceBuilder.create(new URL(failoverJwksUrl)).build();

		return new JWKSourceWithFailover<>(primary, failover);
	}
}