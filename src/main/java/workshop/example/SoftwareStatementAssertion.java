package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class SoftwareStatementAssertion {

	/** Trust Framework Directory (e.g., Open Banking Ltd) issues the SSA */
	public String issueSSA(String softwareId, String organisationId, String organisationName, List<String> redirectUris,
			List<String> roles, ECKey directorySigningKey) throws JOSEException {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://directory.openbanking.org.uk")
				.issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(3600)))
				.jwtID(UUID.randomUUID().toString())
				// SSA-specific claims (OBIE spec)
				.claim("software_id", softwareId).claim("software_client_name", "Fintech Payment App")
				.claim("software_client_uri", "https://tpp.fintech.com").claim("software_redirect_uris", redirectUris)
				.claim("software_roles", roles) // e.g., ["PISP","AISP"]
				.claim("org_id", organisationId).claim("org_name", organisationName).claim("org_status", "Active")
				.claim("ob_registry_tos", "https://directory.openbanking.org.uk/tos.pdf")
				.claim("software_jwks_endpoint",
						"https://keystore.openbanking.org.uk/" + organisationId + "/" + softwareId + ".jwks")
				.build();

		SignedJWT ssa = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(directorySigningKey.getKeyID()).build(), claims);
		ssa.sign(new RSASSASigner(directorySigningKey.toRSAKey()));
		return ssa.serialize();
	}

	/** TPP presents the SSA to the bank's DCR endpoint (RFC 7591) */
	public String buildDynamicClientRegistrationRequest(String ssaToken, List<String> grantTypes, ECKey tppSigningKey)
			throws JOSEException {
		JWTClaimsSet registrationClaims = new JWTClaimsSet.Builder().issuer("your-software-id")
				.audience("https://bank.example.com").jwtID(UUID.randomUUID().toString())
				.issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(300)))
				// Embed the SSA from the directory
				.claim("software_statement", ssaToken).claim("grant_types", grantTypes) // ["authorization_code","client_credentials","refresh_token"]
				.claim("response_types", List.of("code")).claim("application_type", "web")
				.claim("token_endpoint_auth_method", "private_key_jwt")
				.claim("tls_client_auth_subject_dn", "CN=tpp.fintech.com").claim("request_object_signing_alg", "PS256")
				.claim("id_token_signed_response_alg", "PS256").build();

		SignedJWT registrationJwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(tppSigningKey.getKeyID()).build(), registrationClaims);
		registrationJwt.sign(new RSASSASigner(tppSigningKey.toRSAKey()));
		return registrationJwt.serialize();
		// POST /register with Content-Type: application/jwt
	}
}