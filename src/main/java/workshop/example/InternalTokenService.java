package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class InternalTokenService {

	private OctetSequenceKey activeKey; // from Vault / AWS Secrets Manager
	private OctetSequenceKey retiringKey; // retained during rotation window

	public String issueInternalToken(String fromService, String toService, Map<String, Object> claims)
			throws JOSEException {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().issuer(fromService).audience(toService)
				.jwtID(UUID.randomUUID().toString()).issueTime(Date.from(Instant.now()))
				.expirationTime(Date.from(Instant.now().plusSeconds(30))); // very short — internal only

		claims.forEach(builder::claim);

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(activeKey.getKeyID()).build(),
				builder.build());
		jwt.sign(new MACSigner(activeKey));
		return jwt.serialize();
	}

	/**
	 * Tries active key first, falls back to retiring key (supports zero-downtime
	 * rotation)
	 */
	public JWTClaimsSet verifyInternalToken(String token, String expectedAudience) throws Exception {
		SignedJWT jwt = SignedJWT.parse(token);
		String kid = jwt.getHeader().getKeyID();

		OctetSequenceKey key = kid.equals(activeKey.getKeyID()) ? activeKey : retiringKey;
		if (key == null || !jwt.verify(new MACVerifier(key))) {
			throw new SecurityException("Invalid internal service token");
		}

		JWTClaimsSet claims = jwt.getJWTClaimsSet();
		if (!claims.getAudience().contains(expectedAudience)) {
			throw new SecurityException("Token not intended for service: " + expectedAudience);
		}
		return claims;
	}
}