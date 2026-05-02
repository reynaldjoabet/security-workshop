package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class VerifiableCredentialIssuer {

	/** KYC provider issues a W3C VC-JWT credential */
	public String issueKYCCredential(String subjectDid, String nationality, int verifiedAge, ECKey issuerKey)
			throws JOSEException {
		Map<String, Object> credentialSubject = Map.of("id", subjectDid, "nationality", nationality, "ageOver18",
				verifiedAge >= 18, "kycLevel", "ENHANCED" // e.g., AML-compliant full KYC
		);

		Map<String, Object> vc = Map.of("@context", List.of("https://www.w3.org/2018/credentials/v1"), "type",
				List.of("VerifiableCredential", "KYCCredential"), "issuer", "did:web:kyc-provider.example.com",
				"issuanceDate", Instant.now().toString(), "credentialSubject", credentialSubject);

		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("did:web:kyc-provider.example.com").subject(subjectDid)
				.jwtID("urn:uuid:" + UUID.randomUUID()).issueTime(Date.from(Instant.now()))
				.expirationTime(Date.from(Instant.now().plusSeconds(86400 * 365))) // 1 year
				.claim("vc", vc).build();

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("vc+jwt")) // W3C
																													// VC-JWT
																													// media
																													// type
				.keyID(issuerKey.getKeyID()).build(), claims);
		jwt.sign(new ECDSASigner(issuerKey));
		return jwt.serialize();
	}
}
