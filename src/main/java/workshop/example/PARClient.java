package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.net.URI;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublishers;
import java.time.Instant;
import java.util.*;

/**
 * RFC 9126 — Pushed Authorization Request (PAR) client. Pushes the full
 * /authorize params to the AS before the redirect, preventing parameter
 * tampering and enabling request confidentiality.
 */
public class PARClient {

	private final String parEndpoint;
	private final String clientId;
	private final ECKey signingKey;
	private final HttpClient httpClient = HttpClient.newHttpClient();

	public PARClient(String parEndpoint, String clientId, ECKey signingKey) {
		this.parEndpoint = parEndpoint;
		this.clientId = clientId;
		this.signingKey = signingKey;
	}

	/**
	 * Push the authorization request to the AS and return the request_uri. The
	 * returned request_uri replaces all /authorize query params in the redirect.
	 */
	public String pushAuthorizationRequest(String responseType, String scope, String redirectUri, String state,
			String codeChallenge) throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(clientId).audience(parEndpoint)
				.jwtID(UUID.randomUUID().toString()).issueTime(Date.from(Instant.now()))
				.expirationTime(Date.from(Instant.now().plusSeconds(60))).claim("response_type", responseType)
				.claim("client_id", clientId).claim("scope", scope).claim("redirect_uri", redirectUri)
				.claim("state", state).claim("code_challenge", codeChallenge).claim("code_challenge_method", "S256")
				.build();

		SignedJWT jar = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(),
				claims);
		jar.sign(new ECDSASigner(signingKey));

		String body = "client_id=" + clientId + "&request=" + jar.serialize();

		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(parEndpoint))
				.header("Content-Type", "application/x-www-form-urlencoded").POST(BodyPublishers.ofString(body))
				.build();

		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() != 201) {
			throw new SecurityException("PAR request rejected: " + response.body());
		}

		// Parse request_uri from JSON response (simplified — use a JSON library in
		// production)
		String responseBody = response.body();
		int start = responseBody.indexOf("\"request_uri\":\"") + 15;
		int end = responseBody.indexOf("\"", start);
		return responseBody.substring(start, end);
	}
}