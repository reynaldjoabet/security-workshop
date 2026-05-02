package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import java.util.*;

public class DynamicAlgorithmSelection {

	enum KeyCapability {
		EC_256(JWSAlgorithm.ES256, Curve.P_256), EC_384(JWSAlgorithm.ES384, Curve.P_384),
		RSA_PSS(JWSAlgorithm.PS256, null), ED25519(JWSAlgorithm.Ed25519, Curve.Ed25519);

		JWSAlgorithm alg;
		Curve curve;

		KeyCapability(JWSAlgorithm alg, Curve curve) {
			this.alg = alg;
			this.curve = curve;
		}
	}

	/**
	 * Select algorithm based on available keys and runtime context. Prefer
	 * strongest; fallback to weaker if necessary.
	 */
	public JWSAlgorithm selectAlgorithm(Map<KeyCapability, JWK> availableKeys, String clientType, boolean fipsMode) {
		// Priority order
		List<KeyCapability> preference = fipsMode ? List.of(KeyCapability.RSA_PSS, KeyCapability.EC_384) // FIPS prefers
																											// RSA-PSS
				: List.of(KeyCapability.ED25519, KeyCapability.EC_256); // Default prefers EdDSA

		for (KeyCapability cap : preference) {
			if (availableKeys.containsKey(cap)) {
				return cap.alg;
			}
		}

		throw new SecurityException("No suitable algorithm available");
	}

	public String issueTokenWithDynamicAlgorithm(JWTClaimsSet claims, Map<KeyCapability, JWK> availableKeys,
			String clientType, boolean fipsMode) throws Exception {
		JWSAlgorithm selectedAlg = selectAlgorithm(availableKeys, clientType, fipsMode);

		JWK selectedKey = availableKeys.values().stream()
				.filter(k -> k.getAlgorithm() != null && k.getAlgorithm().equals(selectedAlg)).findFirst()
				.orElseThrow();

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(selectedAlg).keyID(selectedKey.getKeyID())
				.customParam("alg_selection_reason", "dynamic: fips=" + fipsMode).build(), claims);

		// Sign with the selected key
		if (selectedKey instanceof ECKey ec) {
			jwt.sign(new ECDSASigner(ec));
		} else if (selectedKey instanceof RSAKey rsa) {
			jwt.sign(new RSASSASigner(rsa));
		} else if (selectedKey instanceof OctetKeyPair okp) {
			jwt.sign(new Ed25519Signer(okp));
		}

		return jwt.serialize();
	}
}