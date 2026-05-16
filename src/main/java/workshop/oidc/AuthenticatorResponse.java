package workshop.oidc;

import java.util.Optional;
import java.util.Set;
/** Mirrors authenticator.Response from Go. */
public record AuthenticatorResponse(UserInfo user, Set<String> audiences) {
	public static AuthenticatorResponse fail() {
		return null; // null == "no match", caller should treat as not-authenticated
	}
}