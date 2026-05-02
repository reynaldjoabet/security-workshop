package example;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.proc.*;
import java.net.URL;
import java.util.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;

public class TokenValidator {

	private final ConfigurableJWTProcessor<SecurityContext> processor;

	public TokenValidator(String jwksUrl) throws Exception {
		JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(jwksUrl));

		processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, keySource));

		JWTClaimsSet requiredClaims = new JWTClaimsSet.Builder().issuer("https://auth.fintech.com").build();

		processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(requiredClaims,
				new HashSet<>(Arrays.asList("sub", "exp", "iat", "jti", "scope"))));
	}

	public JWTClaimsSet validate(String token) throws Exception {
		return processor.process(token, null);
	}

	public List<String> extractScopes(JWTClaimsSet claims) throws Exception {
		String scope = claims.getStringClaim("scope");
		return scope != null ? Arrays.asList(scope.split(" ")) : Collections.emptyList();
	}
}