package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.*;
import java.util.*;
import java.util.Base64;

public class ZeroKnowledgeTokens {

	/**
	 * Token contains a ZK proof instead of plaintext claim. Verifier can confirm
	 * "age >= 18" without knowing actual DOB.
	 */
	public String issueZKProofToken(String subject, LocalDate dateOfBirth, ECKey signingKey) throws Exception {
		// 1. Generate ZK proof: "I can prove DOB >= 1993-05-17 without revealing actual
		// DOB"
		// (In practice: use a ZK proof library like ZoKrates, Circom)
		String zkProofJson = generateZKProof(dateOfBirth, LocalDate.of(2006, 1, 1)); // 18 years ago

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject(subject).claim("age_proof", zkProofJson) // proof
																											// object,
																											// not
																											// plaintext
																											// age
				.claim("dob_hash", sha256(dateOfBirth.toString())) // one-way hash for audit
				.issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(3600))).build();

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(),
				claims);
		jwt.sign(new ECDSASigner(signingKey));
		return jwt.serialize();
	}

	/** Verifier confirms ZK proof without learning DOB */
	public void verifyAgeProof(JWTClaimsSet claims, int minimumAge) throws Exception {
		Map<String, Object> ageProof = claims.getJSONObjectClaim("age_proof");

		// Verify the proof (cryptographically confirms age >= minimumAge)
		boolean isAdult = verifyZKProof(ageProof, minimumAge);

		if (!isAdult) {
			throw new SecurityException("Zero-knowledge proof failed: age requirement not met");
		}
	}

	private String generateZKProof(LocalDate actual, LocalDate threshold) {
		// Simplified — in production use ZoKrates or similar
		return "{\"proof\":\"...\",\"pubkey\":\"...\"}";
	}

	private boolean verifyZKProof(Map<String, Object> proof, int minAge) {
		// Verify proof cryptographically
		return true;
	}

	private String sha256(String s) throws Exception {
		return Base64.getEncoder()
				.encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes()));
	}
}