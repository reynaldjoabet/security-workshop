package example;

import java.util.Optional;

public interface TenantRegistry {
	Optional<String> getJwksUrlForIssuer(String issuer);
}
