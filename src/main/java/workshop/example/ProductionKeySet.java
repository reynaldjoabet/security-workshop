package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import java.time.Instant;
import java.util.*;

public class ProductionKeySet {

	public JWKSet buildKeySet() throws Exception {
		ECKey signingKey = new ECKeyGenerator(Curve.P_256).keyID("sig-2026-04").keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.ES256).expirationTime(Date.from(Instant.now().plusSeconds(86400 * 90)))
				.generate();

		// 2. Encryption key — RSA-OAEP-256, enc only, wrapKey+unwrapKey ops
		RSAKey encryptionKey = new RSAKeyGenerator(2048).keyID("enc-2026-04").keyUse(KeyUse.ENCRYPTION)
				.algorithm(JWEAlgorithm.RSA_OAEP_256)
				.keyOperations(Set.of(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY)).generate();

		// 3. Internal service key — AES-GCM key wrapping only
		OctetSequenceKey internalKey = new OctetSequenceKeyGenerator(256).keyID("internal-wrap-2026-04")
				.keyUse(KeyUse.ENCRYPTION).algorithm(JWEAlgorithm.A256GCMKW)
				.keyOperations(Set.of(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY)).generate();

		// 4. Retiring signing key — kept in JWKS for in-flight token validation
		ECKey retiringKey = new ECKeyGenerator(Curve.P_256).keyID("sig-2026-01").keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.ES256).expirationTime(Date.from(Instant.now().plusSeconds(300))) // expires soon
				.generate();

		return new JWKSet(List.of(signingKey, encryptionKey, internalKey, retiringKey));
	}
}