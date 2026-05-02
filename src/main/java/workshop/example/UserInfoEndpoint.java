package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class UserInfoEndpoint {

	/** Returns a signed-then-encrypted UserInfo JWT (FAPI requirement) */
	public String buildUserInfoResponse(String subject, Map<String, Object> userClaims, ECKey serverSigningKey,
			RSAKey clientEncryptionKey) throws Exception {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().issuer("https://auth.fintech.com").subject(subject)
				.issueTime(Date.from(Instant.now()));

		userClaims.forEach(builder::claim);

		SignedJWT signed = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(serverSigningKey.getKeyID()).build(), builder.build());
		signed.sign(new ECDSASigner(serverSigningKey));

		// Encrypt for the specific client (cty=JWT signals nested JWT)
		JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.contentType("JWT").keyID(clientEncryptionKey.getKeyID()).build(), new Payload(signed));
		jwe.encrypt(new RSAEncrypter(clientEncryptionKey));
		return jwe.serialize();
	}
}