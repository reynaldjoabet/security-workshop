package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector;
import java.net.URL;
import java.security.Key;
import java.util.*;

public class MultiTenantKeySelector implements JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

	private final TenantRegistry tenantRegistry;

	public MultiTenantKeySelector(TenantRegistry tenantRegistry) {
		this.tenantRegistry = tenantRegistry;
	}

	@Override
	public List<? extends Key> selectKeys(JWSHeader header, JWTClaimsSet claimsSet, SecurityContext context)
			throws KeySourceException {
		String issuer = claimsSet.getIssuer();
		String jwksUrl = tenantRegistry.getJwksUrlForIssuer(issuer)
				.orElseThrow(() -> new KeySourceException("Unknown tenant: " + issuer));

		try {
			RemoteJWKSet<SecurityContext> keySource = new RemoteJWKSet<>(new URL(jwksUrl));
			List<JWK> matches = keySource
					.get(new JWKSelector(new JWKMatcher.Builder().keyID(header.getKeyID()).build()), context);

			List<Key> keys = new ArrayList<>();
			for (JWK jwk : matches) {
				keys.add(jwk.toECKey().toECPublicKey());
			}
			return keys;
		} catch (Exception e) {
			throw new KeySourceException("Failed to fetch JWKS for issuer: " + issuer, e);
		}
	}
}
// processor.setJWTClaimsSetAwareJWSKeySelector(new
// MultiTenantKeySelector(registry));
