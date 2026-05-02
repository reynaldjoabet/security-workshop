package example;

import com.nimbusds.jwt.JWTClaimsSet;
import java.util.*;

public class SCAClaimsValidator {

	private static final String PSD2_SCA_ACR = "urn:openbanking:psd2:sca";
	private static final Set<String> VALID_AMR_COMBINATIONS = Set.of("pwd+otp", // password + OTP
			"pwd+biom", // password + biometric
			"hwk+pin" // hardware key + PIN
	);

	public void requireSCA(JWTClaimsSet claims) throws Exception {
		// 1. Verify Authentication Context (ACR) — assurance level
		String acr = claims.getStringClaim("acr");
		if (!PSD2_SCA_ACR.equals(acr)) {
			throw new SecurityException("SCA not performed — acr '" + acr + "' insufficient for payment");
		}

		// 2. Verify Authentication Methods References (AMR) — what factors were used
		List<String> amr = claims.getStringListClaim("amr");
		if (amr == null || amr.isEmpty()) {
			throw new SecurityException("AMR claim absent — cannot confirm SCA factors");
		}
		String combined = String.join("+", amr.stream().sorted().toArray(String[]::new));
		if (!VALID_AMR_COMBINATIONS.contains(combined)) {
			throw new SecurityException("AMR combination '" + combined + "' does not satisfy SCA");
		}

		// 3. Verify auth_time is recent (PSD2: SCA must not be older than 5 minutes for
		// payments)
		Date authTime = (Date) claims.getClaim("auth_time");
		if (authTime == null || authTime.toInstant().isBefore(java.time.Instant.now().minusSeconds(300))) {
			throw new SecurityException("SCA is stale — re-authentication required for payment");
		}
	}
}
