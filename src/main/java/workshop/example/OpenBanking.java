import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

class OpenBanking {
	public static String createSignedToken(RSAPrivateKey privateKey) throws JOSEException {
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("email@domain.com").claim("role", "customer")
				.claim("account_number", "123456789").audience("https://api.mybank.com").issueTime(new Date())
				.jwtID(UUID.randomUUID().toString()).issuer("https://myapp.com")
				.expirationTime(new Date(System.currentTimeMillis() + 5L * 60L * 1000L)).build();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();

		SignedJWT signedJWT = new SignedJWT(header, claimsSet);
		JWSSigner signer = new RSASSASigner(privateKey);
		signedJWT.sign(signer);
		return signedJWT.serialize();
	}

	public static boolean verifyToken(String token, RSAPublicKey publicKey) throws Exception {
		SignedJWT signedJWT = SignedJWT.parse(token);
		JWSVerifier verifier = new RSASSAVerifier(publicKey);
		return signedJWT.verify(verifier);
	}

	public static String createEncryptedToken(RSAPublicKey recipientPublicKey) throws JOSEException {
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("payment-initiation").claim("amount", 1000)
				.audience("https://api.mybank.com").issueTime(new Date()).jwtID(UUID.randomUUID().toString())
				.issuer("https://myapp.com").expirationTime(new Date(System.currentTimeMillis() + 5L * 60L * 1000L))
				.build();

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
		EncryptedJWT encryptedJWT = new EncryptedJWT(header, claimsSet);
		JWEEncrypter encrypter = new RSAEncrypter(recipientPublicKey);
		encryptedJWT.encrypt(encrypter);
		return encryptedJWT.serialize();
	}

	public static String decryptToken(String token, RSAPrivateKey privateKey) throws Exception {
		EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);
		JWEDecrypter decrypter = new RSADecrypter(privateKey);
		encryptedJWT.decrypt(decrypter);
		return encryptedJWT.getJWTClaimsSet().toString();
	}

	public static void main(String[] args) {
		System.out.println("OpenBanking helpers loaded");
	}
}
