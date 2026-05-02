package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import java.util.UUID;
import com.nimbusds.jose.jwk.KeyUse;

public class X25519EncryptionService {

	public OctetKeyPair generateX25519Key() throws Exception {
		return new OctetKeyPairGenerator(Curve.X25519).keyID(UUID.randomUUID().toString()).keyUse(KeyUse.ENCRYPTION)
				.generate();
	}

	/** ECDH-ES over X25519 — standard for DID/VC ecosystems and mobile wallets */
	public String encrypt(String payload, OctetKeyPair recipientPublicKey) throws JOSEException {
		JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
				.keyID(recipientPublicKey.getKeyID()).build(), new Payload(payload));
		jwe.encrypt(new X25519Encrypter(recipientPublicKey));
		return jwe.serialize();
	}

	public String decrypt(String token, OctetKeyPair privateKey) throws Exception {
		JWEObject jwe = JWEObject.parse(token);
		jwe.decrypt(new X25519Decrypter(privateKey));
		return jwe.getPayload().toString();
	}
}