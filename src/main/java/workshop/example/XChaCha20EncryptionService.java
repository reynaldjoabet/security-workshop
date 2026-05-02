package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetKeyPair;

public class XChaCha20EncryptionService {

	/**
	 * XC20P — XChaCha20-Poly1305 content encryption. More nonce-misuse resistant
	 * than AES-GCM — use where nonce generation is not HSM-controlled (e.g., mobile
	 * devices, embedded systems).
	 */
	public String encrypt(String payload, OctetKeyPair recipientKey) throws JOSEException {
		JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.XC20P)
				.keyID(recipientKey.getKeyID()).build(), new Payload(payload));
		jwe.encrypt(new X25519Encrypter(recipientKey));
		return jwe.serialize();
	}
}