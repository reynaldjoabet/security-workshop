package validators;

import com.nimbusds.jwt.proc.BadJWTException;
import net.jcip.annotations.Immutable;


/**
 * Common bad JWT exceptions.
 */
@Immutable
public final class BadJWTExceptions {
	
	
	/**
	 * Missing {@code exp} claim exception.
	 */
	public static final BadJWTException MISSING_EXP_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT expiration (exp) claim");
	
	
	/**
	 * Missing {@code iat} claim exception.
	 */
	public static final BadJWTException MISSING_IAT_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT issue time (iat) claim");
	
	
	/**
	 * Missing {@code iss} claim exception.
	 */
	public static final BadJWTException MISSING_ISS_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT issuer (iss) claim");
	
	
	/**
	 * Missing {@code sub} claim exception.
	 */
	public static final BadJWTException MISSING_SUB_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT subject (sub) claim");
	
	
	/**
	 * Missing {@code aud} claim exception.
	 */
	public static final BadJWTException MISSING_AUD_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT audience (aud) claim");
	
	
	/**
	 * Missing {@code nonce} claim exception.
	 */
	public static final BadJWTException MISSING_NONCE_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT nonce (nonce) claim");
	
	
	/**
	 * Expired ID token exception.
	 */
	public static final BadJWTException EXPIRED_EXCEPTION =
		new BadJWTException("Expired JWT");
	
	
	/**
	 * ID token issue time ahead of current time exception.
	 */
	public static final BadJWTException IAT_CLAIM_AHEAD_EXCEPTION =
		new BadJWTException("JWT issue time ahead of current time");
	
	
	/**
	 * Prevents public instantiation.
	 */
	private BadJWTExceptions() {}
}
