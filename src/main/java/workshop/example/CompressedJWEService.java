package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.RSAKey;

public class CompressedJWEService {

	/**
	 * Use when payload > ~1KB — especially ISO 20022 XMLds or large RAR
	 * authorization_details. Note: DEFLATE must only be used inside JWE (not JWS) —
	 * compression oracle attacks (CRIME/BREACH) are not applicable to
	 * encrypted-then-compressed JWE.
	 */
	public String encryptAndCompress(String largeJsonPayload, RSAKey recipientKey) throws JOSEException {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.keyID(recipientKey.getKeyID()).compressionAlgorithm(CompressionAlgorithm.DEF) // zip before encrypt
				.build();

		JWEObject jwe = new JWEObject(header, new Payload(largeJsonPayload));
		jwe.encrypt(new RSAEncrypter(recipientKey));
		return jwe.serialize();
		// Decryption automatically decompresses — no extra steps needed
	}
}