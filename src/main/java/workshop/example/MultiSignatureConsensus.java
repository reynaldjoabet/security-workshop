package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import java.util.*;

public class MultiSignatureConsensus {

	/**
	 * JWS JSON Serialization allows multiple signatures on the same payload. Each
	 * cosigner appends their signature to the 'signatures' array.
	 */
	public String buildMultiSignedPayment(String paymentJson, List<ECKey> cosignerKeys) throws Exception {
		Payload payload = new Payload(paymentJson);

		// Use JWSObjectJSON for multi-signature support (JWS JSON Serialization)
		JWSObjectJSON jwsJson = new JWSObjectJSON(payload);

		for (int i = 0; i < cosignerKeys.size(); i++) {
			ECKey key = cosignerKeys.get(i);
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID())
					.customParam("cosigner_rank", i + 1).build();
			jwsJson.sign(header, new ECDSASigner(key));
		}

		return jwsJson.serializeGeneral();
	}

	/** Only accept payment if M-of-N cosigners have signed */
	public void validateMultiSigned(String jwtString, int requiredSignatures, List<ECKey> authorizedCosigners)
			throws Exception {
		JWSObjectJSON jws = JWSObjectJSON.parse(jwtString);

		List<JWSObjectJSON.Signature> signatures = jws.getSignatures();

		if (signatures.size() < requiredSignatures) {
			throw new SecurityException(
					"Payment requires " + requiredSignatures + " signatures but only has " + signatures.size());
		}

		for (JWSObjectJSON.Signature sig : signatures) {
			String keyId = sig.getHeader().getKeyID();
			ECKey cosignerKey = authorizedCosigners.stream().filter(k -> k.getKeyID().equals(keyId)).findFirst()
					.orElseThrow(() -> new SecurityException("Unknown cosigner key: " + keyId));

			boolean valid = sig.verify(new ECDSAVerifier(cosignerKey.toECPublicKey()));
			if (!valid) {
				throw new SecurityException("Cosigner signature for key " + keyId + " is invalid");
			}
		}
	}
}