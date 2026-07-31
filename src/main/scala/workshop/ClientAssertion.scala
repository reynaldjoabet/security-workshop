package workshop

import java.time.Instant
import java.util.{Date, UUID}

import scala.util.Try

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.*

object ClientAssertion {

  def build(clientId: String, tokenEndpoint: String)(using
      signingKey: ECKey
  ): Try[String] = Try {
    val claims = new JWTClaimsSet.Builder()
      .issuer(clientId)        // iss = client_id
      .subject(clientId)       // sub = client_id
      .audience(tokenEndpoint) // aud = token endpoint URL
      .jwtID(UUID.randomUUID().toString)
      .issueTime(Date.from(Instant.now()))
      .expirationTime(Date.from(Instant.now().plusSeconds(60))) // short-lived
      .build()

    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.ES256)
        .keyID(signingKey.getKeyID)
        .build(),
      claims
    )
    jwt.sign(new ECDSASigner(signingKey))
    jwt.serialize()
  }

// Sent as: POST /token
// client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
// client_assertion=<jwt>
}
