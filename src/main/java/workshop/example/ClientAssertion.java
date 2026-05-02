package example;

import com.nimbusds.jose.jwk.ECKey;

/** Builds a Private Key JWT client assertion per RFC 7523 / FAPI 2.0. */
@FunctionalInterface
public interface ClientAssertion {
	String build(String clientId, String tokenEndpoint, ECKey signingKey) throws Exception;
}
