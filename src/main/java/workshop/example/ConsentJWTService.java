package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class ConsentJWTService {

	public String issueConsentBoundAccessToken(String subject, String consentId, List<String> permittedAccountIds,
			List<String> permissions, Instant consentExpiry, ECKey signingKey) throws JOSEException {
		// Embed full consent metadata — no DB lookup needed at resource server
		Map<String, Object> consentClaims = Map.of("ConsentId", consentId, "Permissions", permissions, // ["ReadAccountsBasic","ReadBalances","ReadTransactionsDebits"]
				"AccountIds", permittedAccountIds, "ExpirationDateTime", consentExpiry.toString(),
				"TransactionFromDateTime", Instant.now().minusSeconds(86400 * 90).toString());

		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://auth.bank.com").subject(subject)
				.audience("https://api.bank.com").jwtID(UUID.randomUUID().toString())
				.issueTime(Date.from(Instant.now())).expirationTime(Date.from(consentExpiry))
				.claim("scope", "accounts transactions balances").claim("consent", consentClaims) // self-contained
																									// consent — no DB
																									// round-trip
				.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(),
				claims);
		jwt.sign(new ECDSASigner(signingKey));
		return jwt.serialize();
	}

	/** Resource server validates account access inline — no external call */
	public void assertAccountAccess(JWTClaimsSet claims, String requestedAccountId) throws Exception {
		Map<String, Object> consent = claims.getJSONObjectClaim("consent");
		@SuppressWarnings("unchecked")
		List<String> permittedAccounts = (List<String>) consent.get("AccountIds");

		if (!permittedAccounts.contains(requestedAccountId)) {
			throw new SecurityException("Account " + requestedAccountId + " not in consent scope");
		}

		String expiryStr = (String) consent.get("ExpirationDateTime");
		if (Instant.parse(expiryStr).isBefore(Instant.now())) {
			throw new SecurityException("Consent has expired");
		}
	}
}