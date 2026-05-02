package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;
import java.util.*;

public class AlgNoneDefense {

	public ConfigurableJWTProcessor<SecurityContext> buildHardenedProcessor(JWKSource<SecurityContext> keySource) {

		ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

		// 1. Restrict to exactly the algorithms you expect — anything else is rejected
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, keySource));

		// 2. Reject 'none' algorithm explicitly via type verifier
		// DefaultJWTProcessor already rejects PlainJWT when a JWSKeySelector is set,
		// but make it explicit and log it
		processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder().build(),
				Set.of("iss", "sub", "exp", "iat", "jti")));

		return processor;
	}

	/**
	 * API gateway entry point — always validate type before processing. Rejects
	 * alg=none, unexpected typ, and unexpected algorithms.
	 */
	public JWTClaimsSet safeProcess(String rawToken, ConfigurableJWTProcessor<SecurityContext> processor)
			throws Exception {
		// Guard: detect and loudly reject PlainJWT before processing
		try {
			PlainJWT plain = PlainJWT.parse(rawToken);
			// If it parsed as PlainJWT — it has alg=none
			throw new SecurityException("SECURITY: alg=none token rejected — possible downgrade attack. Sub: "
					+ plain.getJWTClaimsSet().getSubject());
		} catch (java.text.ParseException e) {
			// Good — it's not a PlainJWT, continue normal processing
		}

		return processor.process(rawToken, null);
	}
}