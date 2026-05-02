package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;

public class EphemeralEncryption {

	/** Nimbus auto-generates a fresh ephemeral key pair per encryption */
	public String encryptWithPFS(String payload, ECKey recipientStaticKey) throws JOSEException {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
				.keyID(recipientStaticKey.getKeyID()).build();

		JWEObject jwe = new JWEObject(header, new Payload(payload));
		jwe.encrypt(new ECDHEncrypter(recipientStaticKey));
		return jwe.serialize();
	}
}