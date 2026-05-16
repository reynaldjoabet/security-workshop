package workshop.oidc;

import java.util.Map;
import java.util.Optional;

public record ClaimMappings(ClaimMapping username, // Required
		ClaimMapping groups, // Optional
		ClaimMapping uid, // Optional
		Map<String, ClaimMapping> extra // Optional, key=extra-key
) {
	public record ClaimMapping(String claim, String prefix) {
		public static ClaimMapping of(String claim) {
			return new ClaimMapping(claim, null);
		}

		public static ClaimMapping of(String claim, String prefix) {
			return new ClaimMapping(claim, prefix);
		}
	}
}