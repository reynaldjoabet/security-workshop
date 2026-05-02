package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class TokenIssuer {

	public String issueAccessToken(String subject, List<String> scopes, ECKey signingKey) throws JOSEException {
		JWSSigner signer = new ECDSASigner(signingKey);

		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://auth.fintech.com").subject(subject)
				.audience("https://api.fintech.com").claim("scope", String.join(" ", scopes))
				.claim("client_id", "mobile-app-v2").issueTime(Date.from(Instant.now()))
				.expirationTime(Date.from(Instant.now().plusSeconds(300))).jwtID(UUID.randomUUID().toString()).build();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID())
				.type(JOSEObjectType.JWT).build();

		SignedJWT jwt = new SignedJWT(header, claims);
		jwt.sign(signer);
		return jwt.serialize();
	}
}
