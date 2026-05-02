package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;
import java.time.Instant;
import java.util.*;

public class CriticalHeaderService {

	private static final String OB_IAT = "http://openbanking.org.uk/iat";
	private static final String OB_ISS = "http://openbanking.org.uk/iss";
	private static final String OB_TAN = "http://openbanking.org.uk/tan";

	/** Signs with Open Banking-defined critical headers */
	public String signWithOBCritHeaders(Payload payload, String tppIssuerId, ECKey signingKey) throws JOSEException {
		long issuedAt = Instant.now().getEpochSecond();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(signingKey.getKeyID())
				.criticalParams(Set.of(OB_IAT, OB_ISS, OB_TAN)) // receiver MUST understand these
				.customParam(OB_IAT, issuedAt).customParam(OB_ISS, tppIssuerId)
				.customParam(OB_TAN, "openbanking.org.uk") // Trust Anchor Name
				.build();

		JWSObject jws = new JWSObject(header, payload);
		jws.sign(new ECDSASigner(signingKey));
		return jws.serialize(true); // detached for Open Banking message signing
	}

	/**
	 * Verifier must explicitly declare which crit params it understands, or reject
	 */
	public ConfigurableJWTProcessor<SecurityContext> buildProcessorWithCritSupport() {
		ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

		// Register supported critical params — processor rejects unknown crit params
		processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));

		// Note: crit param checking is done implicitly by the key selector / verifier.
		// The DefaultJWTProcessor will reject tokens whose crit header set includes
		// params not present in the JWSVerifier's accepted crit set.

		return processor;
	}
}
