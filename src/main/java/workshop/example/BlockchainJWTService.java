package example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;
import java.util.UUID;

public class BlockchainJWTService {

	/** secp256k1 — same curve as Bitcoin/Ethereum wallet keys */
	public ECKey generateSecp256k1Key() throws Exception {
		return new ECKeyGenerator(Curve.SECP256K1).keyID(UUID.randomUUID().toString()).keyUse(KeyUse.SIGNATURE)
				.generate();
	}

	/**
	 * Issue a JWT signed with an Ethereum wallet key. Used in: DeFi custody, CBDC
	 * identity binding, blockchain-anchored KYC.
	 */
	public String issueBlockchainBoundToken(String ethereumAddress, String assetId, ECKey walletKey)
			throws JOSEException {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject(ethereumAddress) // Ethereum address as subject
				.claim("asset_id", assetId).claim("chain", "ethereum")
				.claim("wallet_key_thumbprint", walletKey.computeThumbprint().toString())
				.issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(3600))).build();

		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256K) // secp256k1
				.keyID(walletKey.getKeyID()).build(), claims);
		jwt.sign(new ECDSASigner(walletKey));
		return jwt.serialize();
	}

	public JWTClaimsSet verifyBlockchainToken(String token, ECKey publicKey) throws Exception {
		SignedJWT jwt = SignedJWT.parse(token);
		if (!jwt.verify(new ECDSAVerifier(publicKey))) {
			throw new SecurityException("secp256k1 signature invalid");
		}
		return jwt.getJWTClaimsSet();
	}
}