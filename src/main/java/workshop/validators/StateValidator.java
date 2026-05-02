package validators;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.claims.StateHash;
import net.jcip.annotations.ThreadSafe;

/**
 * State validator, using the optional {@code s_hash} ID token claim. Required
 * for applications that must comply with Financial Services – Financial API -
 * Part 2: Read and Write API Security Profile.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial Services – Financial API - Part 2: Read and Write API
 *         Security Profile
 * </ul>
 */
@ThreadSafe
public class StateValidator {
	
	
	/**
	 * Validates the specified state.
	 *
	 * @param state        The state received at the redirection URI. Must
	 *                     not be {@code null}.
	 * @param jwsAlgorithm The JWS algorithm of the ID token. Must not be
	 *                     be {@code null}.
	 * @param stateHash    The state hash, as set in the {@code s_hash} ID
	 *                     token claim. Must not be {@code null}.
	 *
	 * @throws InvalidHashException If the received state doesn't match the
	 *                              hash.
	 */
	public static void validate(final State state,
				    final JWSAlgorithm jwsAlgorithm,
				    final StateHash stateHash)
		throws InvalidHashException {
		
		StateHash expectedHash = StateHash.compute(state, jwsAlgorithm);
		
		if (expectedHash == null) {
			throw InvalidHashException.INVALID_STATE_HASH_EXCEPTION;
		}
		
		if (! expectedHash.equals(stateHash)) {
			throw InvalidHashException.INVALID_STATE_HASH_EXCEPTION;
		}
	}
}
