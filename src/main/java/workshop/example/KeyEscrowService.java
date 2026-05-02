package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;

public class KeyEscrowService {

	/**
	 * Encrypts a JWK private key with a passphrase using PBES2. Used for regulatory
	 * key escrow, disaster recovery backups. The passphrase is split across 3 key
	 * custodians (Shamir Secret Sharing outside of this).
	 */
	public String exportEncryptedPrivateKey(ECKey privateKey, String passphrase) throws JOSEException {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.PBES2_HS512_A256KW, // PBKDF2-HMAC-SHA512 key derivation
				EncryptionMethod.A256CBC_HS512 // AES-CBC + HMAC (not GCM) for export compatibility
		).keyID(privateKey.getKeyID()).build();

		// Serialize the private key as the payload
		JWEObject jwe = new JWEObject(header, new Payload(privateKey.toJSONString()));
		jwe.encrypt(new PasswordBasedEncrypter(passphrase, 16, // salt length (bytes) — NIST recommends >= 16
				310000 // PBKDF2 iterations — OWASP 2023 recommendation for PBKDF2-HMAC-SHA512
		));
		return jwe.serialize();
	}

	public ECKey importEncryptedPrivateKey(String encryptedJwk, String passphrase) throws Exception {
		JWEObject jwe = JWEObject.parse(encryptedJwk);
		jwe.decrypt(new PasswordBasedDecrypter(passphrase));
		return ECKey.parse(jwe.getPayload().toString());
	}
}