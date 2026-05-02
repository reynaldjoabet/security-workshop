package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import java.security.SecureRandom;

public class Main {
	public static void main(String[] args) throws Exception {
		System.out.println("Hello, Nimbus JOSE+JWT!");
	}

	/** PBES2-HS512+A256KW password-based key encryption example */
	public static String pbes2Encrypt(String sensitiveData) throws Exception {
		String pin = "4837";
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		PasswordBasedEncrypter encrypter = new PasswordBasedEncrypter(pin, 2048, 600000);
		JWEAlgorithm alg = JWEAlgorithm.PBES2_HS512_A256KW;
		EncryptionMethod enc = EncryptionMethod.A256GCM;
		JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(sensitiveData));
		jwe.encrypt(encrypter);
		return jwe.serialize();
	}

	/** Decrypt PBES2 token */
	public static String pbes2Decrypt(String token) throws Exception {
		String pin = "4837";
		PasswordBasedDecrypter decrypter = new PasswordBasedDecrypter(pin);
		JWEObject jwe = JWEObject.parse(token);
		jwe.decrypt(decrypter);
		return jwe.getPayload().toString();
	}

	/** ECDH-1PU authenticated sender encryption example */
	public static String ecdh1puEncrypt(String paymentOrder, ECKey senderStaticKey, ECKey recipientStaticKey)
			throws Exception {
		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(senderStaticKey.toECPrivateKey(),
				recipientStaticKey.toECPublicKey());
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256GCM),
				new Payload(paymentOrder));
		jwe.encrypt(encrypter);
		return jwe.serialize();
	}

	/** ECDH-1PU decrypt — sender's static key proves authorship */
	public static String ecdh1puDecrypt(String token, ECKey bankPrivateKey, ECKey senderStaticKey) throws Exception {
		JWEObject jwe = JWEObject.parse(token);
		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bankPrivateKey.toECPrivateKey(),
				senderStaticKey.toECPublicKey());
		jwe.decrypt(decrypter);
		return jwe.getPayload().toString();
	}
}