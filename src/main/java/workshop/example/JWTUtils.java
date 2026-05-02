

package federation.utils;

import java.security.PublicKey;
import java.util.List;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.ParseException;

/**
 * Federation JWT utilities.
 */
public class JWTUtils {

	/**
	 * Resolves the signing JWS algorithm for the specified JWK.
	 *
	 * @param jwk The JWK. Must not be {@code null}.
	 *
	 * @return The JWS algorithm.
	 *
	 * @throws JOSEException If the resolution failed.
	 */
	public static JWSAlgorithm resolveSigningAlgorithm(final JWK jwk) throws JOSEException {

		KeyType jwkType = jwk.getKeyType();

		if (KeyType.RSA.equals(jwkType)) {
			if (jwk.getAlgorithm() != null) {
				return new JWSAlgorithm(jwk.getAlgorithm().getName());
			} else {
				return JWSAlgorithm.RS256; // assume RS256 as default
			}
		} else if (KeyType.EC.equals(jwkType)) {
			ECKey ecJWK = jwk.toECKey();
			if (jwk.getAlgorithm() != null) {
				return new JWSAlgorithm(ecJWK.getAlgorithm().getName());
			} else {
				if (Curve.P_256.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES256;
				} else if (Curve.P_384.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES384;
				} else if (Curve.P_521.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES512;
				} else if (Curve.SECP256K1.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES256K;
				} else {
					throw new JOSEException("Unsupported ECDSA curve: " + ecJWK.getCurve());
				}
			}
		} else if (KeyType.OKP.equals(jwkType)) {
			OctetKeyPair okp = jwk.toOctetKeyPair();
			if (Curve.Ed25519.equals(okp.getCurve())) {
				return JWSAlgorithm.EdDSA;
			} else {
				throw new JOSEException("Unsupported EdDSA curve: " + okp.getCurve());
			}
		} else {
			throw new JOSEException("Unsupported JWK type: " + jwkType);
		}
	}

	/**
	 * Signs the specified JWT claims set.
	 *
	 * @param signingJWK The signing JWK. Must not be {@code null}.
	 * @param alg        The JWS algorithm. Must not be {@code null}.
	 * @param type       The JOSE object type, {@code null} if not specified,
	 * @param claimsSet  The JWT claims set.
	 *
	 * @return The signed JWT.
	 *
	 * @throws JOSEException If signing failed.
	 */
	public static SignedJWT sign(final JWK signingJWK, final JWSAlgorithm alg, final JOSEObjectType type,
			final JWTClaimsSet claimsSet) throws JOSEException {

		JWSSigner jwsSigner = new DefaultJWSSignerFactory().createJWSSigner(signingJWK, alg);

		JWSHeader jwsHeader = new JWSHeader.Builder(alg).type(type).keyID(signingJWK.getKeyID()).build();

		SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
		jwt.sign(jwsSigner);
		return jwt;
	}

	/**
	 * Verifies the signature of the specified JWT.
	 *
	 * @param jwt            The signed JWT. Must not be {@code null}.
	 * @param type           The expected JOSE object type. Must not be
	 *                       {@code null}.
	 * @param claimsVerifier The JWT claims verifier. Must not be {@code null}.
	 * @param jwkSet         The public JWK set. Must not be {@code null}.
	 *
	 * @return The thumbprint of the JWK used to successfully verify the signature.
	 *
	 * @throws BadJOSEException If the JWT is invalid.
	 * @throws JOSEException    If the signature verification failed.
	 */
	public static Base64URL verifySignature(final SignedJWT jwt, final JOSEObjectType type,
			final JWTClaimsSetVerifier<?> claimsVerifier, final JWKSet jwkSet) throws BadJOSEException, JOSEException {

		if (!type.equals(jwt.getHeader().getType())) {
			throw new BadJOSEException("JWT rejected: Invalid or missing JWT typ (type) header");
		}

		// Check claims with JWT framework

		try {
			claimsVerifier.verify(jwt.getJWTClaimsSet(), null);
		} catch (java.text.ParseException e) {
			throw new BadJOSEException(e.getMessage(), e);
		}

		List<JWK> jwkMatches = new JWKSelector(JWKMatcher.forJWSHeader(jwt.getHeader())).select(jwkSet);

		if (jwkMatches.isEmpty()) {
			throw new BadJOSEException("JWT rejected: Another JOSE algorithm expected, or no matching key(s) found");
		}

		JWSVerifierFactory verifierFactory = new DefaultJWSVerifierFactory();

		for (JWK candidateJWK : jwkMatches) {

			if (candidateJWK instanceof AsymmetricJWK) {
				PublicKey publicKey = ((AsymmetricJWK) candidateJWK).toPublicKey();
				JWSVerifier jwsVerifier = verifierFactory.createJWSVerifier(jwt.getHeader(), publicKey);
				if (jwt.verify(jwsVerifier)) {
					// success
					return candidateJWK.computeThumbprint();
				}
			}
		}

		throw new BadJOSEException("JWT rejected: Invalid signature");
	}

	/**
	 * Parses the claims of the specified signed JWT.
	 *
	 * @param jwt The signed JWT. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static JWTClaimsSet parseSignedJWTClaimsSet(final SignedJWT jwt) throws ParseException {

		if (JWSObject.State.UNSIGNED.equals(jwt.getState())) {
			throw new ParseException("The JWT is not signed");
		}

		try {
			return jwt.getJWTClaimsSet();
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}

	private JWTUtils() {
	}
}
