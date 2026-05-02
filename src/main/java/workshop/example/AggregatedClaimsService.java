package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class AggregatedClaimsService {

	/**
	 * External KYC provider issues a JWT containing verified identity claims. This
	 * is the "aggregated claims" source JWT embedded in the ID token.
	 */
	public String issueKYCAggregatedClaimsJWT(String subject, String amlStatus, String identityLevel,
			ECKey kycProviderKey) throws JOSEException {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://kyc.provider.com").subject(subject)
				.audience("https://bank.example.com").issueTime(Date.from(Instant.now()))
				.expirationTime(Date.from(Instant.now().plusSeconds(86400)))
				// Verified claims per OIDC Identity Assurance (eKYC-IDA spec)
				.claim("verified_claims",
						Map.of("verification", Map.of("trust_framework", "uk_tfida", "assurance_level", identityLevel, // "medium"
																														// or
																														// "high"
								"time", Instant.now().toString()), "claims",
								Map.of("aml_status", amlStatus, // "PASS" / "REFER" / "FAIL"
										"pep_status", "CLEAR", "sanctions_check", "CLEAR")))
				.build();

		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kycProviderKey.getKeyID()).build(), claims);
		jwt.sign(new ECDSASigner(kycProviderKey));
		return jwt.serialize();
	}

	/**
	 * Bank embeds KYC provider's JWT as an aggregated claims source in the OIDC ID
	 * token. The RP fetches and verifies it independently — bank never holds or
	 * re-signs PII.
	 */
	public String issueIDTokenWithAggregatedClaims(String subject, String kycJwt, ECKey bankSigningKey)
			throws JOSEException {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://auth.bank.com").subject(subject)
				.audience("tpp-client-id").issueTime(Date.from(Instant.now()))
				.expirationTime(Date.from(Instant.now().plusSeconds(3600)))
				// Aggregated claims: claims_sources + _claim_names mapping
				.claim("_claim_sources", Map.of("src1", Map.of("JWT", kycJwt) // embed the KYC JWT directly (aggregated)
				)).claim("_claim_names", Map.of("verified_claims", "src1", // tell RP where to find verified_claims
						"aml_status", "src1"))
				.build();

		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(bankSigningKey.getKeyID()).build(), claims);
		jwt.sign(new ECDSASigner(bankSigningKey));
		return jwt.serialize();
	}
}