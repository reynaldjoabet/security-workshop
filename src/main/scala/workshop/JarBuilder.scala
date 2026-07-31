package workshop

import java.time.Instant
import java.util.{Date, UUID}

import scala.util.Try

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.*

object JARBuilder {

  def buildRequestObject(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: String,
      nonce: String,
      authorizationEndpoint: String,
      pkceChallenge: String
  )(using signingKey: ECKey): Try[String] = Try {
    val claims = new JWTClaimsSet.Builder()
      .issuer(clientId)
      .audience(authorizationEndpoint)
      .claim("client_id", clientId)
      .claim("response_type", "code")
      .claim("redirect_uri", redirectUri)
      .claim("scope", scope)
      .claim("state", state)
      .claim("nonce", nonce)
      .claim("response_mode", "jwt") // JARM
      .claim("code_challenge", pkceChallenge)
      .claim("code_challenge_method", "S256")
      .expirationTime(Date.from(Instant.now().plusSeconds(60)))
      .jwtID(UUID.randomUUID().toString)
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
  // GET /authorize?client_id=...&request=<jwt>

}
