package validators;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import net.jcip.annotations.ThreadSafe;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;


/**
 * Logout token claims verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Back-Channel Logout 1.0
 * </ul>
 */
@ThreadSafe
public class LogoutTokenClaimsVerifier extends DefaultJWTClaimsVerifier {
	
	
	/**
	 * The expected logout token issuer.
	 */
	private final Issuer expectedIssuer;


	/**
	 * The requesting client.
	 */
	private final ClientID expectedClientID;
	
	
	/**
	 * Creates a new logout token claims verifier.
	 *
	 * @param issuer   The expected ID token issuer. Must not be
	 *                 {@code null}.
	 * @param clientID The client ID. Must not be {@code null}.
	 */
	public LogoutTokenClaimsVerifier(final Issuer issuer,
					 final ClientID clientID) {

		super(
			Collections.singleton(clientID.getValue()),
			new JWTClaimsSet.Builder()
				.issuer(issuer.getValue())
				.build(),
                        new HashSet<>(Arrays.asList("iat", "exp", "jti", "events")),
			Collections.singleton("nonce")
		);
		this.expectedIssuer = issuer;
		this.expectedClientID = clientID;
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
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet, final SecurityContext ctx)
		throws BadJWTException {

		super.verify(claimsSet, ctx);

		// See http://openid.net/specs/openid-connect-backchannel-1_0-ID1.html#Validation
		
		// Check event type
		try {
			Map<String, Object> events = claimsSet.getJSONObjectClaim("events");
			
			if (events == null) {
				throw new BadJWTException("Missing / invalid JWT events (events) claim");
			}
			
			if (com.nimbusds.jose.util.JSONObjectUtils.getJSONObject(events, LogoutTokenClaimsSet.EVENT_TYPE) == null) {
				throw new BadJWTException("Missing event type, required " + LogoutTokenClaimsSet.EVENT_TYPE);
			}
			
		} catch (java.text.ParseException e) {
			throw new BadJWTException("Invalid JWT events (events) claim", e);
		}
		
		// Either sub or sid must be present
		try {
			if (claimsSet.getSubject() == null && claimsSet.getStringClaim("sid") == null) {
				throw new BadJWTException("Missing subject (sub) and / or session ID (sid) claim(s)");
			}
			
		} catch (java.text.ParseException e) {
			throw new BadJWTException("Invalid session ID (sid) claim");
		}
	}
}
