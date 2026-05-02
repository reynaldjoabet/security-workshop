package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import javax.crypto.SecretKey;

public class DirectEncryptionService {

	/**
	 * 'dir' algorithm: the shared key IS the CEK — zero key-wrapping overhead. ONLY
	 * use when the CEK is managed externally (Vault, KMS) and rotated frequently.
	 * The key MUST be exactly the right length for the enc algorithm (32 bytes for
	 * A256GCM).
	 */
	public String encryptDirect(String payload, OctetSequenceKey sharedKey) throws JOSEException {
		JWEObject jwe = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).keyID(sharedKey.getKeyID()).build(),
				new Payload(payload));
		jwe.encrypt(new DirectEncrypter(sharedKey));
		return jwe.serialize();
	}

	public String decryptDirect(String token, OctetSequenceKey sharedKey) throws Exception {
		JWEObject jwe = JWEObject.parse(token);
		jwe.decrypt(new DirectDecrypter(sharedKey));
		return jwe.getPayload().toString();
	}
}