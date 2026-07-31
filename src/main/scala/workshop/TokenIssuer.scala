package workshop

import java.time.Instant
import java.util.{Date, UUID}

import scala.jdk.CollectionConverters.*
import scala.util.Try

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.*

// Generating a Signed JWT (ES256) with Error Handling
object TokenIssuer {

  def issueAccessToken(subject: String, scopes: List[String])(using
      signingKey: ECKey
  ): Try[String] = Try {
    val signer = new ECDSASigner(signingKey)

    val claims = new JWTClaimsSet.Builder()
      .issuer("https://auth.fintech.com")
      .subject(subject)
      .audience("https://api.fintech.com")
      .claim("scope", scopes.mkString(" "))
      .issueTime(Date.from(Instant.now()))
      .expirationTime(Date.from(Instant.now().plusSeconds(300)))
      .jwtID(UUID.randomUUID().toString)
      .build()

    val header = new JWSHeader.Builder(JWSAlgorithm.ES256)
      .keyID(signingKey.getKeyID)
      .`type`(
        JOSEObjectType.JWT
      ) // backticks needed because 'type' is a keyword in Scala
      .build()

    val jwt = new SignedJWT(header, claims)
    jwt.sign(signer)
    jwt.serialize()
  }

}
