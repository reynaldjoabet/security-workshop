package example;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

public class PbeComplete {

	private static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	public void demonstratePbe() throws Exception {
		System.out.println("=== PBE Complete (Encryption + Derivation) ===\n");

		String password = "MyPassword123";
		String plaintext = "Account Balance: $50,000";

		// Step 1: Generate salt
		byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);
		System.out.println("Step 1: Generate salt: " + bytesToHex(salt));

		// Step 2: Derive key from password (PBKDF2)
		KeySpec spec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 600000, 256);

		javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

		javax.crypto.SecretKey derivedKey = factory.generateSecret(spec);
		System.out.println("Step 2: Derived key: " + bytesToHex(derivedKey.getEncoded()));

		// Step 3: Encrypt plaintext with derived key
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
		byte[] iv = new byte[12];
		new java.security.SecureRandom().nextBytes(iv);

		javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);

		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, derivedKey, gcmSpec);
		byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

		System.out.println("Step 3: Encrypt plaintext");
		System.out.println("  Plaintext: " + plaintext);
		System.out.println("  Ciphertext: " + bytesToHex(ciphertext));

		// Step 4: Store everything
		byte[] encrypted = new byte[salt.length + iv.length + ciphertext.length];
		System.arraycopy(salt, 0, encrypted, 0, salt.length);
		System.arraycopy(iv, 0, encrypted, salt.length, iv.length);
		System.arraycopy(ciphertext, 0, encrypted, salt.length + iv.length, ciphertext.length);

		System.out.println("Step 4: Store: salt || iv || ciphertext");
		System.out.println("  Stored bytes: " + bytesToHex(encrypted));
		System.out.println("\nResult: ENCRYPTED DATA (complete PBE)\n");

		// Decryption (reverse process)
		System.out.println("=== Decryption ===\n");

		// Extract components
		byte[] extractedSalt = new byte[16];
		byte[] extractedIv = new byte[12];
		byte[] extractedCiphertext = new byte[ciphertext.length];

		System.arraycopy(encrypted, 0, extractedSalt, 0, 16);
		System.arraycopy(encrypted, 16, extractedIv, 0, 12);
		System.arraycopy(encrypted, 28, extractedCiphertext, 0, ciphertext.length);

		// Derive key again (using STORED salt)
		KeySpec decryptSpec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(), extractedSalt, // ← Same salt!
				600000, 256);

		javax.crypto.SecretKey decryptedKey = factory.generateSecret(decryptSpec);

		// Decrypt
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, decryptedKey,
				new javax.crypto.spec.GCMParameterSpec(128, extractedIv));

		byte[] decrypted = cipher.doFinal(extractedCiphertext);
		System.out.println("Decrypted: " + new String(decrypted));
	}
}