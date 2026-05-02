package workshop

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.{RSASSASigner, RSASSAVerifier}
import com.nimbusds.jose.util.{Base64URL, X509CertUtils}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import scala.jdk.CollectionConverters.*
import scala.util.Try

object EidasJwtSigner {

  def signWithQSealCertificate(
      claims: JWTClaimsSet,
      qSealCert: X509Certificate,
      privateKey: java.security.PrivateKey
  ): Try[String] = Try {
    // Include the eIDAS QSeal certificate in the x5c header for non-repudiation
    val certList =
      List(com.nimbusds.jose.util.Base64.encode(qSealCert.getEncoded)).asJava

    val header = new JWSHeader.Builder(JWSAlgorithm.PS256)
      .x509CertChain(certList) // eIDAS x5c requirement
      .x509CertSHA256Thumbprint( // x5t#S256 for fast lookup
        Base64URL.encode(
          MessageDigest.getInstance("SHA-256").digest(qSealCert.getEncoded)
        )
      )
      .build()

    val signer = new RSASSASigner(privateKey)
    val jwt = new SignedJWT(header, claims)
    jwt.sign(signer)
    jwt.serialize()
  }

  def validateQSealCertificate(
      token: String,
      trustAnchor: X509Certificate
  ): Either[String, JWTClaimsSet] =
    for {
      jwt <- Try(SignedJWT.parse(token)).toEither.left.map(_.getMessage)
      certChain = jwt.getHeader.getX509CertChain.asScala.toList
      leafCert <- Try(
        X509CertUtils.parse(certChain.head.decode())
      ).toEither.left.map(_.getMessage)
      _ <- validateCertChain(leafCert, trustAnchor)
      _ <- Try(
        jwt.verify(
          new RSASSAVerifier(leafCert.getPublicKey.asInstanceOf[RSAPublicKey])
        )
      ).toEither.left.map(_.getMessage)
    } yield jwt.getJWTClaimsSet

  private def validateCertChain(
      leafCert: X509Certificate,
      trustAnchor: X509Certificate
  ): Either[String, Unit] = {
    val issuedByTrustAnchor =
      leafCert.getIssuerX500Principal == trustAnchor.getSubjectX500Principal
    Either.cond(
      issuedByTrustAnchor,
      (),
      s"Certificate not issued by trust anchor: ${trustAnchor.getSubjectX500Principal}"
    )
  }
}
