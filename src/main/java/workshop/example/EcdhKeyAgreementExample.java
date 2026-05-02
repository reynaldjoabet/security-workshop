package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

public class EcdhKeyAgreementExample {

	public void demonstrateEcdhAgreement() throws Exception {
		// Step 1: Alice generates her keypair
		ECKey aliceKey = new ECKeyGenerator(Curve.P_256).generate();
		ECKey alicePublic = aliceKey.toPublicJWK();
		System.out.println("Alice public key:\n" + alicePublic.toJSONString());

		// Step 2: Bob generates his keypair
		ECKey bobKey = new ECKeyGenerator(Curve.P_256).generate();
		ECKey bobPublic = bobKey.toPublicJWK();
		System.out.println("\nBob public key:\n" + bobPublic.toJSONString());

		// Step 3: Alice encrypts message to Bob
		// Alice uses her private key + Bob's public key
		JWEHeader header = new JWEHeader(JWEAlgorithm.ECDH_ES_A256KW, // ← ECDH key agreement
				EncryptionMethod.A256GCM);

		ECDHEncrypter aliceEncrypter = new ECDHEncrypter(bobPublic);

		JWEObject jwe = new JWEObject(header, new Payload("Secret message: Buy BTC at $50k"));
		jwe.encrypt(aliceEncrypter);

		String encrypted = jwe.serialize();
		System.out.println("\nAlice encrypts to Bob: " + encrypted.split("\\.")[0] + "...");

		// Internally Alice did:
		// 1. Generated ephemeral keypair (ephemeralPrivate, ephemeralPublic)
		// 2. Computed: shared_secret = ephemeralPrivate · bobPublic
		// 3. HKDF: shared_secret → CEK
		// 4. Encrypted payload with CEK
		// 5. Sent: ephemeralPublic in JWE header

		// Step 4: Bob receives and decrypts
		JWEObject receivedJwe = JWEObject.parse(encrypted);

		// Bob extracts Alice's ephemeral public key
		ECKey ephemeralAlicePublic = (ECKey) receivedJwe.getHeader().getJWK();
		System.out.println("\nBob extracts ephemeral public key from header");

		// Bob uses his private key + Alice's ephemeral public key
		ECDHDecrypter bobDecrypter = new ECDHDecrypter(bobKey);
		receivedJwe.decrypt(bobDecrypter);

		String plaintext = new String(receivedJwe.getPayload().toBytes());
		System.out.println("Bob decrypts: " + plaintext);

		// Internally Bob did:
		// 1. Extracted ephemeralAlicePublic from header
		// 2. Computed: shared_secret = bobPrivate · ephemeralAlicePublic
		// 3. HKDF: shared_secret → SAME CEK (by ECDH property!)
		// 4. Decrypted payload
	}
}
