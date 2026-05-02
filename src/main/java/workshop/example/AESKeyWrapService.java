package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;

public class AESKeyWrapService {

	/**
	 * A256KW: AES Key Wrap (RFC 3394) without GCM authentication. Required by: PCI
	 * PIN Security §18, NIST SP 800-56C Rev 2. Simpler than GCMKW — no IV/tag per
	 * key wrap — widely supported by HSMs.
	 */
	public String encryptWithAESKW(String payload, OctetSequenceKey wrappingKey) throws JOSEException {
		JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.A256KW, EncryptionMethod.A256GCM)
				.keyID(wrappingKey.getKeyID()).build(), new Payload(payload));
		jwe.encrypt(new AESEncrypter(wrappingKey));
		return jwe.serialize();
	}

	/** A128KW — 128-bit AES Key Wrap. Lower overhead, FIPS 140-2 approved. */
	public String encryptWithA128KW(String payload, OctetSequenceKey key128) throws JOSEException {
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM),
				new Payload(payload));
		jwe.encrypt(new AESEncrypter(key128));
		return jwe.serialize();
	}
}