package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;

public class AuthenticatedEncryption {

	/**
	 * ECDH-1PU: sender's static key + recipient's static key + ephemeral key.
	 * Recipient can verify the sender — without an outer JWS signature.
	 */
	public String encryptAuthenticated(String payload, ECKey senderStaticKey, ECKey recipientStaticKey)
			throws JOSEException {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256GCM)
				.keyID(recipientStaticKey.getKeyID()).agreementPartyUInfo(Base64URL.encode("sender"))
				.agreementPartyVInfo(Base64URL.encode("recipient")).build();

		JWEObject jwe = new JWEObject(header, new Payload(payload));
		jwe.encrypt(new ECDH1PUEncrypter(senderStaticKey.toECPrivateKey(), recipientStaticKey.toECPublicKey()));
		return jwe.serialize();
	}

	public String decrypt(String token, ECKey recipientPrivateKey, ECKey senderStaticKey) throws Exception {
		JWEObject jwe = JWEObject.parse(token);
		jwe.decrypt(new ECDH1PUDecrypter(recipientPrivateKey.toECPrivateKey(), senderStaticKey.toECPublicKey()));
		return jwe.getPayload().toString();
	}
}
