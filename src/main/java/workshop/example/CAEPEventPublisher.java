package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class CAEPEventPublisher {

	/** Bank publishes a session-revoked event to the SSF stream */
	public String issueSessionRevokedEvent(String subjectSessionId, String reason, String recipientUrl,
			ECKey signingKey) throws JOSEException {
		Map<String, Object> sessionSubject = Map.of("format", "iss_sub", "iss", "https://auth.bank.com", "sub",
				subjectSessionId);

		Map<String, Object> eventDetail = Map.of("subject", sessionSubject, "reason_admin", Map.of("en", reason),
				"initiating_entity", "policy" // policy-triggered, not user-initiated
		);

		Map<String, Object> events = Map.of("https://schemas.openid.net/secevent/caep/event-type/session-revoked",
				eventDetail);

		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://auth.bank.com")
				.jwtID(UUID.randomUUID().toString()).issueTime(Date.from(Instant.now())).audience(recipientUrl)
				.claim("events", events).claim("toe", Instant.now().getEpochSecond())
				.claim("txn", UUID.randomUUID().toString()) // transaction correlation ID
				.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("secevent+jwt"))
				.keyID(signingKey.getKeyID()).build(), claims);
		jwt.sign(new ECDSASigner(signingKey));
		return jwt.serialize();
	}
}
