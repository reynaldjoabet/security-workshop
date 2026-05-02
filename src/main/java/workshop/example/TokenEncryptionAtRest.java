package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import java.time.Instant;
import java.util.*;

public class TokenEncryptionAtRest {

	/**
	 * Store encrypted tokens in DB to defend against database breaches. Each token
	 * is wrapped with a key-encryption-key (KEK).
	 */
	public String encryptTokenForStorage(String token, OctetSequenceKey kek) throws JOSEException {
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM),
				new Payload(token));
		jwe.encrypt(new AESEncrypter(kek));
		return jwe.serialize();
	}

	/** Retrieve and decrypt token from DB */
	public String decryptTokenFromStorage(String encryptedToken, OctetSequenceKey kek) throws Exception {
		JWEObject jwe = JWEObject.parse(encryptedToken);
		jwe.decrypt(new AESDecrypter(kek));
		return jwe.getPayload().toString();
	}

	/**
	 * Usage in DAO layer:
	 */
	public class TokenDao {
		public void saveToken(String subject, String token, OctetSequenceKey kek) throws Exception {
			String encrypted = encryptTokenForStorage(token, kek);
			// db.insert("tokens", Map.of("subject", subject, "encrypted_token", encrypted,
			// "created_at", Instant.now()));
			System.out.printf("[%s] storing encrypted token for %s%n", Instant.now(), subject);
		}

		public String getToken(String subject, OctetSequenceKey kek) throws Exception {
			// Map row = db.query("SELECT encrypted_token FROM tokens WHERE subject=?",
			// subject);
			String encryptedToken = "<from-db>"; // placeholder
			return decryptTokenFromStorage(encryptedToken, kek);
		}
	}
}
