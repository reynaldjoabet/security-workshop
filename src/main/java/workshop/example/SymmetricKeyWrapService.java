package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import java.util.UUID;
import com.nimbusds.jose.jwk.KeyUse;

public class SymmetricKeyWrapService {

	/** Generate a 256-bit AES key for GCMKW (retrieved from Vault in production) */
	public OctetSequenceKey generateWrappingKey() throws Exception {
		return new OctetSequenceKeyGenerator(256).keyID(UUID.randomUUID().toString()).keyUse(KeyUse.ENCRYPTION)
				.algorithm(JWEAlgorithm.A256GCMKW).generate();
	}

	/**
	 * Encrypt an inter-service payload using A256GCMKW + A256GCM. The AES-GCM key
	 * wrap includes an IV and auth tag per key-wrap — stronger than AES-KeyWrap
	 * (A256KW) which lacks authentication.
	 */
	public String encryptInterServicePayload(String payload, OctetSequenceKey wrappingKey) throws JOSEException {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM)
				.keyID(wrappingKey.getKeyID()).compressionAlgorithm(CompressionAlgorithm.DEF) // DEFLATE for large
																								// payloads — see #34
				.build();

		JWEObject jwe = new JWEObject(header, new Payload(payload));
		jwe.encrypt(new AESEncrypter(wrappingKey));
		return jwe.serialize();
	}

	public String decryptInterServicePayload(String token, OctetSequenceKey wrappingKey) throws Exception {
		JWEObject jwe = JWEObject.parse(token);
		jwe.decrypt(new AESDecrypter(wrappingKey));
		return jwe.getPayload().toString();
	}

	/**
	 * A128GCMKW variant — 128-bit key, lower overhead, still AES-GCM authenticated
	 * wrap
	 */
	public String encryptWithA128GCMKW(String payload, OctetSequenceKey key128) throws JOSEException {
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128GCM),
				new Payload(payload));
		jwe.encrypt(new AESEncrypter(key128));
		return jwe.serialize();
	}
}