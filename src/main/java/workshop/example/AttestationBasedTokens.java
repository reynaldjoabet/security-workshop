package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.util.Set;

public class AttestationBasedTokens {

	/**
	 * Payment engine runs inside a Trusted Execution Environment (TEE). The TEE
	 * signs the token with an attestation key. Recipients can verify the token came
	 * from legitimate TEE.
	 */
	public String issueAttestingToken(JWTClaimsSet claims, String teeAttestationKey, // from TPM/SEV
			String paymentEngineVersion) throws Exception {
		// Add attestation metadata
		claims = new JWTClaimsSet.Builder(claims).claim("attestation_key_id", teeAttestationKey)
				.claim("engine_version", paymentEngineVersion).claim("tee_type", "AMD-SEV").build();

		// Sign with TEE key (private key never leaves the TEE)
		// In reality: TEE signs remotely via HSM API
		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).customParam("tee_attestation", true).build(), claims);
		// jwt.sign(new TEERemoteSigner(teeAttestationKey));
		return jwt.serialize();
	}

	/** Verify the token came from legitimate TEE */
	public void validateAttestation(SignedJWT jwt, Set<String> trustedTeeKeys) throws Exception {
		String attestationKey = (String) jwt.getHeader().getCustomParam("tee_attestation_key_id");

		if (!trustedTeeKeys.contains(attestationKey)) {
			throw new SecurityException(
					"Token is not attested by a trusted TEE — attestation key unknown: " + attestationKey);
		}

		// Verify signature with the TEE's public key
		// (In practice: fetch TEE public cert from TPM attestation service)
	}
}
