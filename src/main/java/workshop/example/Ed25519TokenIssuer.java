package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class Ed25519TokenIssuer {

	public static OctetKeyPair generateEd25519Key() throws Exception {
		return new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).keyUse(KeyUse.SIGNATURE)
				.generate();
	}

	public String issueToken(JWTClaimsSet claims, OctetKeyPair signingKey) throws JOSEException {
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.Ed25519).keyID(signingKey.getKeyID()).build(),
				claims);
		jwt.sign(new Ed25519Signer(signingKey));
		return jwt.serialize();
	}

	public JWTClaimsSet verify(String token, OctetKeyPair publicKey) throws Exception {
		SignedJWT jwt = SignedJWT.parse(token);
		if (!jwt.verify(new Ed25519Verifier(publicKey))) {
			throw new SecurityException("Ed25519 signature verification failed");
		}
		return jwt.getJWTClaimsSet();
	}
}