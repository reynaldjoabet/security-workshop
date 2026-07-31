package workshop

import scala.jdk.CollectionConverters.*
import scala.util.Try

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.{ECDSASigner, ECDSAVerifier}
import com.nimbusds.jose.jwk.{ECKey, JWK}
import com.nimbusds.jwt.*

object DPoPManager {

  // 1. Issuing: Bind the access token to the client's public JWK thumbprint
  def issueDPoPBoundToken(subject: String, clientJwk: JWK)(using
      signingKey: ECKey
  ): Try[String] = Try {
    // Calculate the SHA-256 thumbprint of the client's JWK
    val jktThumbprint = clientJwk.computeThumbprint().toString

    val claims = new JWTClaimsSet.Builder()
      .subject(subject)
      // Standard DPoP confirmation claim component
      .claim("cnf", Map("jkt" -> jktThumbprint).asJava)
      .build()

    // ... sign as usual
    val jwt =
      new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), claims)
    jwt.sign(new ECDSASigner(signingKey))
    jwt.serialize()
  }

  // 2. Verifying: Ensure the API request is accompanied by a valid DPoP Proof JWT
  def verifyDPoPProof(
      dpopProofToken: String,
      accessToken: SignedJWT,
      httpMethod: String,
      httpUrl: String
  ): Try[Unit] = Try {
    val proofJws        = SignedJWT.parse(dpopProofToken)
    val clientPublicJwk = proofJws.getHeader.getJWK

    // Verify proof signature
    require(
      proofJws.verify(new ECDSAVerifier(clientPublicJwk.toECKey.toECPublicKey)),
      "Invalid DPoP signature"
    )

    // Verify DPoP claims (method, url, jti)
    val claims = proofJws.getJWTClaimsSet
    require(claims.getStringClaim("htm") == httpMethod, "HTTP Method mismatch")
    require(claims.getStringClaim("htu") == httpUrl, "HTTP URL mismatch")

    // Verify Access Token is bound to THIS client key
    val boundJkt = accessToken.getJWTClaimsSet
      .getJSONObjectClaim("cnf")
      .get("jkt")
      .asInstanceOf[String]
    require(
      boundJkt == clientPublicJwk.computeThumbprint().toString,
      "Token stealing detected: jkt mismatch"
    )
  }

}
