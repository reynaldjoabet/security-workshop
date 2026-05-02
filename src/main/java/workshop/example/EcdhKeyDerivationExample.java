package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

public class EcdhKeyDerivationExample {

	public void demonstrateEcdhWithHkdf() throws Exception {
		// Step 1: Sender generates ephemeral keypair
		ECKey senderEphemeralKey = new ECKeyGenerator(Curve.P_256).generate();
		System.out
				.println("Sender ephemeral pubkey (will be sent): " + senderEphemeralKey.toPublicJWK().toJSONString());

		// Step 2: Recipient publishes static key
		ECKey recipientStaticKey = new ECKeyGenerator(Curve.P_256).generate();
		System.out.println("Recipient static pubkey (in JWKS): " + recipientStaticKey.toPublicJWK().toJSONString());

		// Step 3: Encryption using ECDH-ES+A256KW
		// This is what happens internally:
		JWEAlgorithm alg = JWEAlgorithm.ECDH_ES_A256KW;
		EncryptionMethod enc = EncryptionMethod.A256GCM;

		// Sender creates encrypter
		ECDHEncrypter encrypter = new ECDHEncrypter(recipientStaticKey);

		JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload("Payment order: $1000 to BankB"));

		// When sender encrypts:
		jwe.encrypt(encrypter);
		//
		// Internally, nimbus does:
		// 1. Generates ephemeral key (same as senderEphemeralKey above)
		// 2. ECDH: senderEphemeral_private + recipientStatic_public
		// = shared_secret (128-256 bits)
		// 3. HKDF-Extract: PRK = HMAC(salt="", shared_secret)
		// 4. HKDF-Expand(info="ECDH-ES+A256KW", length=256):
		// → derives CEK (Content Encryption Key)
		// 5. Encrypts payload with CEK using A256GCM
		// 6. Wraps CEK with A256KW (AES Key Wrap)
		// 7. Stores ephemeral public key in JWE header

		String serialized = jwe.serialize();
		System.out.println("\nEncrypted JWE sent to recipient:");
		System.out.println(serialized);

		// Step 4: Recipient decrypts
		JWEObject receivedJwe = JWEObject.parse(serialized);

		// Extract ephemeral public key from header
		ECKey ephemeralKeyFromHeader = (ECKey) receivedJwe.getHeader().getJWK();
		System.out.println("\nEphemeral key extracted from JWE header: " + ephemeralKeyFromHeader.toJSONString());

		// Recipient creates decrypter using their private key
		ECDHDecrypter decrypter = new ECDHDecrypter(recipientStaticKey);

		// When recipient decrypts:
		receivedJwe.decrypt(decrypter);
		//
		// Internally, nimbus does:
		// 1. Extracts ephemeral public key from JWE header
		// 2. ECDH: ephemeralPublic + recipientStatic_private
		// = SAME shared_secret (DH property!)
		// 3. HKDF-Extract: PRK = HMAC(salt="", shared_secret)
		// 4. HKDF-Expand(info="ECDH-ES+A256KW", length=256):
		// → derives SAME CEK
		// 5. Unwraps wrapped CEK with derived CEK
		// 6. Decrypts payload with CEK using A256GCM

		String plaintext = new String(receivedJwe.getPayload().toBytes());
		System.out.println("\nDecrypted: " + plaintext);
	}
}