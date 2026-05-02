package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import java.security.SecureRandom;

public class PasswordBasedEncryptionExample {

	public void encryptWithPassword(String password, String plaintext) throws Exception {
		// Step 1: Generate random salt (unique per encryption)
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);
		// Note: PasswordBasedEncrypter generates salt internally, no need to pass it

		// Step 2: Define PBKDF2 parameters
		JWEAlgorithm keyManagementAlg = JWEAlgorithm.PBES2_HS512_A256KW;
		// ↑ ↑
		// iterations: 600,000 hash: SHA-512
		// key wrapping: A256KW (AES-256)

		EncryptionMethod contentEncAlg = EncryptionMethod.A256GCM;
		// A256GCM: AES-256-GCM encrypts payload

		// Step 3: Create encrypter (nimbus does PBKDF2 internally)
		PasswordBasedEncrypter encrypter = new PasswordBasedEncrypter(password, 2048, 600000); // password, saltLength,
																								// iterations

		// Step 4: Encrypt payload
		JWEObject jwe = new JWEObject(new JWEHeader(keyManagementAlg, contentEncAlg),
				new Payload(plaintext.getBytes()));
		jwe.encrypt(encrypter);

		// Step 5: Send to recipient (salt stored in JWE header)
		String serialized = jwe.serialize();
		System.out.println("Encrypted JWE: " + serialized);

		// Recipient receives encrypted data
		// Salt is inside the JWE header → no pre-sharing needed
	}

	public String decryptWithPassword(String jweString, String password) throws Exception {
		// Step 1: Parse JWE (automatically extracts salt from header)
		JWEObject jwe = JWEObject.parse(jweString);

		// Step 2: Create decrypter (nimbus re-derives key using same password+salt from
		// header)
		PasswordBasedDecrypter decrypter = new PasswordBasedDecrypter(password);

		// Step 3: Decrypt
		jwe.decrypt(decrypter);

		String plaintext = jwe.getPayload().toString();
		System.out.println("Decrypted: " + plaintext);

		return plaintext;
	}
}
