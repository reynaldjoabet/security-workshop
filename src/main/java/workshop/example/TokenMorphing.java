package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;

public class TokenMorphing {

	/**
	 * JWS (signed, not encrypted) → JWE (encrypted) Useful: sending token through
	 * insecure channel where content must be hidden
	 */
	public String signThenEncrypt(JWTClaimsSet claims, ECKey signingKey, RSAKey encryptionKey) throws Exception {
		// 1. Sign (produces JWS)
		SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(),
				claims);
		signed.sign(new ECDSASigner(signingKey));

		// 2. The SIGNED JWT becomes the PAYLOAD of a JWE
		JWEObject jwe = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT") // signals:
																												// payload
																												// is a
																												// JWT
						.keyID(encryptionKey.getKeyID()).build(),
				new Payload(signed.serialize()) // the JWS string is the payload
		);
		jwe.encrypt(new RSAEncrypter(encryptionKey));

		return jwe.serialize(); // JWE(JWS)
	}

	/** Extract the original JWS from the encrypted wrapper */
	public SignedJWT decryptThenExtract(String encryptedJwt, RSAKey decryptionKey) throws Exception {
		// 1. Decrypt the JWE
		JWEObject jwe = JWEObject.parse(encryptedJwt);
		jwe.decrypt(new RSADecrypter(decryptionKey));

		// 2. Extract the JWS string from the payload
		String jwtString = jwe.getPayload().toString();

		// 3. Parse the JWS
		SignedJWT signed = SignedJWT.parse(jwtString);

		return signed;
	}

	/** Now verify the original signature */
	public JWTClaimsSet verifyDecrypted(SignedJWT signed, ECKey signingKey) throws Exception {
		if (!signed.verify(new ECDSAVerifier(signingKey.toECPublicKey()))) {
			throw new SecurityException("Original signature invalid — tampering detected");
		}
		return signed.getJWTClaimsSet();
	}
}
