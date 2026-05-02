package validators;

import java.util.Date;
import java.util.List;
import java.util.Objects;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.openid.connect.sdk.Nonce;


/**
 * ID token claims verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.3.7 for code flow.
 *     <li>OpenID Connect Core 1.0, section 3.2.2.11 for implicit flow.
 *     <li>OpenID Connect Core 1.0, sections 3.3.2.12 and 3.3.3.7 for hybrid
 *         flow.
 * </ul>
 */
@ThreadSafe
public class IDTokenClaimsVerifier implements JWTClaimsSetVerifier, ClockSkewAware {


	/**
	 * The expected ID token issuer.
	 */
	private final Issuer expectedIssuer;


	/**
	 * The requesting client.
	 */
	private final ClientID expectedClientID;


	/**
	 * The expected nonce, {@code null} if not required or specified.
	 */
	private final Nonce expectedNonce;


	/**
	 * The maximum acceptable clock skew, in seconds.
	 */
	private int maxClockSkew;


	/**
	 * Creates a new ID token claims verifier.
	 *
	 * @param issuer       The expected ID token issuer. Must not be
	 *                     {@code null}.
	 * @param clientID     The client ID. Must not be {@code null}.
	 * @param nonce        The nonce, required in the implicit flow or for
	 *                     ID tokens returned by the authorisation endpoint
	 *                     int the hybrid flow. {@code null} if not
	 *                     required or specified.
	 * @param maxClockSkew The maximum acceptable clock skew (absolute
	 *                     value), in seconds. Must be zero (no clock skew)
	 *                     or positive integer.
	 */
	public IDTokenClaimsVerifier(final Issuer issuer,
				     final ClientID clientID,
				     final Nonce nonce,
				     final int maxClockSkew) {

		this.expectedIssuer = Objects.requireNonNull(issuer);
		this.expectedClientID = Objects.requireNonNull(clientID);
		this.expectedNonce = nonce;
		setMaxClockSkew(maxClockSkew);
	}


	/**
	 * Returns the expected ID token issuer.
	 *
	 * @return The ID token issuer.
	 */
	public Issuer getExpectedIssuer() {

		return expectedIssuer;
	}


	/**
	 * Returns the client ID for verifying the ID token audience.
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {

		return expectedClientID;
	}


	/**
	 * Returns the expected nonce.
	 *
	 * @return The nonce, {@code null} if not required or specified.
	 */
	public Nonce getExpectedNonce() {

		return expectedNonce;
	}


	@Override
	public int getMaxClockSkew() {

		return maxClockSkew;
	}


	@Override
	public void setMaxClockSkew(final int maxClockSkew) {
		if (maxClockSkew < 0) {
			throw new IllegalArgumentException("The max clock skew must be zero or positive");
		}
		this.maxClockSkew = maxClockSkew;
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet, final SecurityContext ctx)
		throws BadJWTException {

		// See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

		final String tokenIssuer = claimsSet.getIssuer();

		if (tokenIssuer == null) {
			throw BadJWTExceptions.MISSING_ISS_CLAIM_EXCEPTION;
		}

		if (! expectedIssuer.getValue().equals(tokenIssuer)) {
			throw new BadJWTException("Unexpected JWT issuer: " + tokenIssuer);
		}

		if (claimsSet.getSubject() == null) {
			throw BadJWTExceptions.MISSING_SUB_CLAIM_EXCEPTION;
		}

		final List<String> tokenAudience = claimsSet.getAudience();

		if (CollectionUtils.isEmpty(tokenAudience)) {
			throw BadJWTExceptions.MISSING_AUD_CLAIM_EXCEPTION;
		}

		if (! tokenAudience.contains(expectedClientID.getValue())) {
			throw new BadJWTException("Unexpected JWT audience: " + tokenAudience);
		}

                try {
                        // The optional "azp" claim is only checked for being
                        // a string, extension-specific "azp" checks should be
                        // subclassed or performed elsewhere.
                        claimsSet.getStringClaim("azp");
                } catch (java.text.ParseException e) {
                        throw new BadJWTException("Invalid JWT authorized party (azp) claim: " + e.getMessage());
                }

		final Date exp = claimsSet.getExpirationTime();

		if (exp == null) {
			throw BadJWTExceptions.MISSING_EXP_CLAIM_EXCEPTION;
		}

		final Date iat = claimsSet.getIssueTime();

		if (iat == null) {
			throw BadJWTExceptions.MISSING_IAT_CLAIM_EXCEPTION;
		}


		final Date nowRef = new Date();

		// Expiration must be after current time, given acceptable clock skew
		if (! DateUtils.isAfter(exp, nowRef, maxClockSkew)) {
			throw BadJWTExceptions.EXPIRED_EXCEPTION;
		}

		// Issue time must be before current time, given acceptable clock skew, or equal to current time
		if (! (iat.equals(nowRef) || DateUtils.isBefore(iat, nowRef, maxClockSkew))) {
			throw BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION;
		}


		if (expectedNonce != null) {

			final String tokenNonce;

			try {
				tokenNonce = claimsSet.getStringClaim("nonce");
			} catch (java.text.ParseException e) {
				throw new BadJWTException("Invalid JWT nonce (nonce) claim: " + e.getMessage());
			}

			if (tokenNonce == null) {
				throw BadJWTExceptions.MISSING_NONCE_CLAIM_EXCEPTION;
			}

			if (! expectedNonce.getValue().equals(tokenNonce)) {
				throw new BadJWTException("Unexpected JWT nonce (nonce) claim: " + tokenNonce);
			}
		}
	}
}
