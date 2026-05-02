package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDH1PUEncrypter;
import com.nimbusds.jose.crypto.ECDH1PUDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

public class Ecdh1puAuthenticatedEncryption {

	public void demonstrateEcdh1pu() throws Exception {
		// Step 1: Customer's static keypair
		ECKey customerStaticKey = new ECKeyGenerator(Curve.P_256).generate();
		System.out.println("Customer static key: " + customerStaticKey.getKeyID());

		// Step 2: Bank's static keypair (published in JWKS)
		ECKey bankStaticKey = new ECKeyGenerator(Curve.P_256).generate();
		System.out.println("Bank static key: " + bankStaticKey.getKeyID());

		// Step 3: Customer creates JWE with ECDH-1PU
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256GCM)
				.jwk(customerStaticKey.toPublicJWK()).build();

		// Create encrypter (uses customer's STATIC key for authentication)
		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(customerStaticKey.toECPrivateKey(), // Sender's static PRIVATE
																								// key (authentication)
				bankStaticKey.toECPublicKey() // Recipient's static public key
		);

		JWEObject jwe = new JWEObject(header, new Payload("{\"amount\": 1000, \"recipient\": \"BankB\"}"));
		jwe.encrypt(encrypter);

		String encrypted = jwe.serialize();
		System.out.println("\nCustomer sends authenticated JWE to Bank");

		// Internally:
		// 1. Generated ephemeralPrivate
		// 2. Computed shared_secret = customerStatic·bankStatic + ephemeral·bankStatic
		// 3. HKDF: shared_secret → CEK
		// 4. Encrypted payload

		// Step 4: Bank receives and verifies sender
		JWEObject receivedJwe = JWEObject.parse(encrypted);

		// Extract customer's static public key from header
		ECKey customerPublicKey = (ECKey) receivedJwe.getHeader().getJWK();
		System.out.println("Bank extracts customer public key from header");

		// Decrypt with ECDH-1PU (requires knowing customer's public key)
		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bankStaticKey.toECPrivateKey(), // Bank's static PRIVATE key
				customerPublicKey.toECPublicKey() // Customer's static PUBLIC key (for authentication)
		);

		try {
			receivedJwe.decrypt(decrypter);
			String plaintext = new String(receivedJwe.getPayload().toBytes());
			System.out.println("Bank decrypts and CONFIRMS sender is customer: " + plaintext);

			// Why this is secure:
			// If attacker tries with DIFFERENT static key:
			// 1. Attacker computes: attackerStatic·bankStatic + ephemeral·bankStatic
			// 2. Bank tries: customerStatic·bankStatic + ephemeral·bankStatic
			// 3. Different shared secrets → decryption FAILS
			// 4. Fraud detected!

		} catch (JOSEException e) {
			System.out.println("Bank REJECTS: Wrong sender key or tampering!");
			throw new Exception("Authentication failed!");
		}
	}
}
