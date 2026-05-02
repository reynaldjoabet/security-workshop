package workshop

import com.nimbusds.jwt.JWTClaimsSet
import java.security.cert.X509Certificate
import java.security.MessageDigest
import java.util.Base64

object MtlsTokenBinder {

  def computeCertThumbprint(cert: X509Certificate): String = {
    val digest = MessageDigest.getInstance("SHA-256")
    Base64.getUrlEncoder.withoutPadding
      .encodeToString(digest.digest(cert.getEncoded))
  }

  def validateBinding(
      claims: JWTClaimsSet,
      clientCert: X509Certificate
  ): Either[String, Unit] = {
    val expected = computeCertThumbprint(clientCert)
    val cnf = Option(claims.getJSONObjectClaim("cnf"))
    val actual = cnf.flatMap(m => Option(m.get("x5t#S256")).map(_.toString))

    actual match {
      case Some(thumbprint) if thumbprint == expected => Right(())
      case Some(_)                                    =>
        Left("Certificate thumbprint mismatch — token theft suspected")
      case None =>
        Left("Token is not certificate-bound — reject for FAPI compliance")
    }
  }
}
