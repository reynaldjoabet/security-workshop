package validators;

/**
 * Invalid access token / code hash exception.
 */
public class InvalidHashException extends Exception {
	
	
	private static final long serialVersionUID = -8395417336093625256L;
	
	
	/**
	 * Access token hash mismatch exception.
	 */
	public static final InvalidHashException INVALID_ACCESS_T0KEN_HASH_EXCEPTION
		= new InvalidHashException("Access token hash (at_hash) mismatch");
	
	
	/**
	 * Authorisation code hash mismatch exception.
	 */
	public static final InvalidHashException INVALID_CODE_HASH_EXCEPTION
		= new InvalidHashException("Authorization code hash (c_hash) mismatch");
	
	
	/**
	 * State hash mismatch exception.
	 */
	public static final InvalidHashException INVALID_STATE_HASH_EXCEPTION
		= new InvalidHashException("State hash (s_hash) mismatch");
	
	
	/**
	 * Creates a new invalid hash exception.
	 *
	 * @param message The exception message.
	 */
	private InvalidHashException(String message) {
		super(message);
	}
}
