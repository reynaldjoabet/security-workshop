package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;

public class CIBARequestBuilder {

	public String buildBackchannelAuthRequest(String loginHint, String scope, String bindingMessage, String clientId,
			ECKey signingKey) throws JOSEException {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(clientId).audience("https://auth.bank.com/bc-authorize")
				.claim("login_hint", loginHint) // user identifier
				.claim("scope", "openid " + scope).claim("binding_message", bindingMessage) // shown on both devices for
																							// user confirmation
				.claim("acr_values", "urn:openbanking:psd2:sca") // SCA required
				.claim("request_expiry", 300) // user has 5 mins to approve
				.issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(60)))
				.jwtID(UUID.randomUUID().toString()).build();

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(),
				claims);
		jwt.sign(new ECDSASigner(signingKey));
		return jwt.serialize();
	}
	// POST /bc-authorize
	// request=<jwt>&client_assertion_type=...&client_assertion=<private_key_jwt>
	// Response: {"auth_req_id":"...","expires_in":300,"interval":5}
	// Client polls /token with grant_type=urn:openid:params:grant-type:ciba
}
