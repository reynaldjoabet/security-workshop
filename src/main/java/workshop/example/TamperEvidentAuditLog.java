package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

public class TamperEvidentAuditLog {

	private String lastEntryHash = "GENESIS"; // known anchor for first entry

	public synchronized String appendAuditEntry(String eventType, String actorId, String resourceId,
			Map<String, Object> details, ECKey signingKey) throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString())
				.issueTime(Date.from(Instant.now())).claim("event_type", eventType) // e.g., PAYMENT_INITIATED,
																					// CONSENT_REVOKED
				.claim("actor_id", actorId).claim("resource_id", resourceId).claim("details", details)
				.claim("prev_hash", lastEntryHash) // chain link — critical for tamper detection
				.build();

		SignedJWT entry = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(),
				claims);
		entry.sign(new ECDSASigner(signingKey));

		String serialized = entry.serialize();

		// Hash this entry to be embedded in the next
		byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(serialized.getBytes("UTF-8"));
		lastEntryHash = Base64URL.encode(hashBytes).toString();

		return serialized;
	}

	/**
	 * Validates the entire chain from genesis — O(n) but run offline / audit-time
	 * only
	 */
	public boolean verifyChain(List<String> entries, ECKey verificationKey) throws Exception {
		String expectedPrevHash = "GENESIS";
		for (String entry : entries) {
			SignedJWT jwt = SignedJWT.parse(entry);
			if (!jwt.verify(new ECDSAVerifier(verificationKey.toECPublicKey()))) {
				return false; // signature broken
			}
			String prevHash = jwt.getJWTClaimsSet().getStringClaim("prev_hash");
			if (!expectedPrevHash.equals(prevHash)) {
				return false; // chain broken — tampering detected
			}
			byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(entry.getBytes("UTF-8"));
			expectedPrevHash = Base64URL.encode(hashBytes).toString();
		}
		return true;
	}
}