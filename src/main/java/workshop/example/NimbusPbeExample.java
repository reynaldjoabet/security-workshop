package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import java.security.SecureRandom;

public class NimbusPbeExample {

	public void demonstrateJwePbes2() throws Exception {
		String password = "MyPassword123";
		String plaintext = "Payment: $1000 to Account X";

		// Generate salt
		byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);

		// Create PBE encrypter (uses PBKDF2 internally)
		PasswordBasedEncrypter encrypter = new PasswordBasedEncrypter(password, 2048, 600000); // password, saltLength,
																								// iterations

		// Create JWE
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.PBES2_HS512_A256KW, EncryptionMethod.A256GCM),
				new Payload(plaintext.getBytes()));

		// Encrypt (internally does PBKDF2!)
		jwe.encrypt(encrypter);

		String serialized = jwe.serialize();
		System.out.println("Encrypted JWE: " + serialized.split("\\.")[0] + "...");
		System.out.println("Uses: PBKDF2 (key derivation) + AES (encryption)");
		System.out.println("This is PBE!");

		// Decrypt
		JWEObject received = JWEObject.parse(serialized);

		PasswordBasedDecrypter decrypter = new PasswordBasedDecrypter(password);

		received.decrypt(decrypter);
		String decrypted = received.getPayload().toString();
		System.out.println("Decrypted: " + decrypted);
	}
}