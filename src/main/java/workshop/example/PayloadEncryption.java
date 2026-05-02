package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;

public class PayloadEncryption {

	public String encryptPayload(String jsonPayload, RSAKey recipientPublicKey) throws JOSEException {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.keyID(recipientPublicKey.getKeyID()).contentType("application/json").build();

		JWEObject jwe = new JWEObject(header, new Payload(jsonPayload));
		jwe.encrypt(new RSAEncrypter(recipientPublicKey));
		return jwe.serialize();
	}

	public String decryptPayload(String encryptedToken, RSAKey privateKey) throws Exception {
		JWEObject jwe = JWEObject.parse(encryptedToken);
		jwe.decrypt(new RSADecrypter(privateKey));
		return jwe.getPayload().toString();
	}
}