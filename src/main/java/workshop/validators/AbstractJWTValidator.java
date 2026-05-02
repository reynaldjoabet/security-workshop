package validators;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;


/**
 * Abstract JSON Web Token (JWT) validator for ID tokens and logout tokens.
 */
public abstract class AbstractJWTValidator implements ClockSkewAware {
	
	
	/**
	 * The default maximum acceptable clock skew for verifying token
	 * timestamps, in seconds.
	 */
	public static final int DEFAULT_MAX_CLOCK_SKEW = 60;
	
	
	/**
	 * The expected JWT "typ" (type) header, {@code null} if none.
	 */
	private final JOSEObjectType jwtType;
	
	
	/**
	 * The expected token issuer.
	 */
	private final Issuer expectedIssuer;
	
	
	/**
	 * The requesting client.
	 */
	private final ClientID clientID;
	
	
	/**
	 * The JWS key selector.
	 */
	private final JWSKeySelector jwsKeySelector;
	
	
	/**
	 * The JWE key selector.
	 */
	private final JWEKeySelector jweKeySelector;
	
	
	/**
	 * The maximum acceptable clock skew, in seconds.
	 */
	private int maxClockSkew = DEFAULT_MAX_CLOCK_SKEW;
	
	
	/**
	 * Creates a new abstract JWT validator.
	 *
	 * @param expectedIssuer The expected token issuer (OpenID Provider).
	 *                       Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param jwsKeySelector The key selector for JWS verification,
	 *                       {@code null} if unsecured (plain) tokens are
	 *                       expected.
	 * @param jweKeySelector The key selector for JWE decryption,
	 *                       {@code null} if encrypted tokens are not
	 *                       expected.
	 */
	@Deprecated
	public AbstractJWTValidator(final Issuer expectedIssuer,
				    final ClientID clientID,
				    final JWSKeySelector jwsKeySelector,
				    final JWEKeySelector jweKeySelector) {
		
		this(null, expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
	}
	
	
	/**
	 * Creates a new abstract JWT validator.
	 *
	 * @param jwtType        The expected JWT "typ" (type) header,
	 *                       {@code null} if none.
	 * @param expectedIssuer The expected token issuer (OpenID Provider).
	 *                       Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param jwsKeySelector The key selector for JWS verification,
	 *                       {@code null} if unsecured (plain) tokens are
	 *                       expected.
	 * @param jweKeySelector The key selector for JWE decryption,
	 *                       {@code null} if encrypted tokens are not
	 *                       expected.
	 */
	public AbstractJWTValidator(final JOSEObjectType jwtType,
				    final Issuer expectedIssuer,
				    final ClientID clientID,
				    final JWSKeySelector jwsKeySelector,
				    final JWEKeySelector jweKeySelector) {
		
		this.jwtType = jwtType;
		
		if (expectedIssuer == null) {
			throw new IllegalArgumentException("The expected token issuer must not be null");
		}
		this.expectedIssuer = expectedIssuer;
		
		if (clientID == null) {
			throw new IllegalArgumentException("The client ID must not be null");
		}
		this.clientID = clientID;
		
		// Optional
		this.jwsKeySelector = jwsKeySelector;
		this.jweKeySelector = jweKeySelector;
	}
	
	
	/**
	 * Returns the expected JWT "typ" (type) header.
	 *
	 * @return The expected JWT "typ" (type) header, {@code null} if none.
	 */
	public JOSEObjectType getExpectedJWTType() {
		return jwtType;
	}
	
	
	/**
	 * Returns the expected token issuer.
	 *
	 * @return The token issuer.
	 */
	public Issuer getExpectedIssuer() {
		return expectedIssuer;
	}
	
	
	/**
	 * Returns the client ID (the expected JWT audience).
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {
		return clientID;
	}
	
	
	/**
	 * Returns the configured JWS key selector for signed token
	 * verification.
	 *
	 * @return The JWS key selector, {@code null} if none.
	 */
	public JWSKeySelector getJWSKeySelector() {
		return jwsKeySelector;
	}
	
	
	/**
	 * Returns the configured JWE key selector for encrypted token
	 * decryption.
	 *
	 * @return The JWE key selector, {@code null}.
	 */
	public JWEKeySelector getJWEKeySelector() {
		return jweKeySelector;
	}
	
	
	/**
	 * Gets the maximum acceptable clock skew for verifying the token
	 * timestamps.
	 *
	 * @return The maximum acceptable clock skew, in seconds. Zero
	 *         indicates none.
	 */
	@Override
	public int getMaxClockSkew() {
		return maxClockSkew;
	}
	
	
	/**
	 * Sets the maximum acceptable clock skew for verifying the token
	 * timestamps.
	 *
	 * @param maxClockSkew The maximum acceptable clock skew, in seconds.
	 *                     Zero indicates none. Must not be negative.
	 */
	@Override
	public void setMaxClockSkew(final int maxClockSkew) {
		this.maxClockSkew = maxClockSkew;
	}
}
