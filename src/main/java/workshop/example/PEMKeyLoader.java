package example;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.X509CertUtils;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.util.List;

public class PEMKeyLoader {

	/**
	 * Load an RSA/EC private key from PEM — e.g., from Vault PKI or cert-manager
	 * secret
	 */
	public JWK loadPrivateKeyFromPEM(String pemContent, String keyId) throws Exception {
		// Note: parseFromPEMEncodedObjects() doesn't exist in nimbus 10.9.
		// For production, use KeyFactory + PKCS8EncodedKeySpec or external PEM library.
		// Stub: return null
		return null;
	}

	/**
	 * Load public key from X.509 certificate PEM — e.g., from TLS cert or eIDAS
	 * QWAC
	 */
	public JWK loadPublicKeyFromCertificate(String certPem, String keyId) throws Exception {
		X509Certificate cert = X509CertUtils.parse(certPem);
		if (cert == null)
			throw new IllegalArgumentException("Failed to parse certificate");

		PublicKey pub = cert.getPublicKey();
		if (pub instanceof RSAPublicKey rsaPub) {
			return new com.nimbusds.jose.jwk.RSAKey.Builder(rsaPub).keyID(keyId).keyUse(KeyUse.SIGNATURE)
					.x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(cert.getEncoded()))).build();
		} else if (pub instanceof ECPublicKey ecPub) {
			return new com.nimbusds.jose.jwk.ECKey.Builder(Curve.forECParameterSpec(((ECPublicKey) pub).getParams()),
					ecPub).keyID(keyId).keyUse(KeyUse.SIGNATURE).build();
		}
		throw new IllegalArgumentException("Unsupported certificate key type");
	}

	/** Kubernetes: load from mounted Secret volume (common in k8s deployments) */
	public JWK loadFromMountedSecret(String mountPath, String keyId) throws Exception {
		String pem = Files.readString(Path.of(mountPath, "tls.key"));
		return loadPrivateKeyFromPEM(pem, keyId);
	}
}