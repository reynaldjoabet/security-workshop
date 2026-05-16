package workshop.oidc;

import java.util.List;
import java.util.Map;
import java.util.Set;

public record UserInfo(String username, String uid, List<String> groups, Map<String, List<String>> extra) {
}