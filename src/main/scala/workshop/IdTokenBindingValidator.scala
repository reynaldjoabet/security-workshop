package workshop

import java.security.MessageDigest

import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet

object IdTokenBindingValidator {

  /**
    * Validates at_hash in the ID token matches the received access token
    */
  def validateAtHash(
      idTokenClaims: JWTClaimsSet,
      rawAccessToken: String,
      alg: JWSAlgorithm
  ): Either[String, Unit] = {
    val hashBytes = MessageDigest
      .getInstance(hashAlgorithmFor(alg))
      .digest(rawAccessToken.getBytes("ASCII"))
    val leftHalf = hashBytes.take(hashBytes.length / 2)
    val computed = Base64URL.encode(leftHalf).toString

    Either.cond(
      idTokenClaims.getStringClaim("at_hash") == computed,
      (),
      "at_hash mismatch — access token substitution attack detected"
    )
  }

  /**
    * Validates nonce to prevent replay attacks in the authorization flow
    */
  def validateNonce(
      claims: JWTClaimsSet,
      expectedNonce: String
  ): Either[String, Unit] =
    Either.cond(
      claims.getStringClaim("nonce") == expectedNonce,
      (),
      "Nonce mismatch — replay attack suspected"
    )

  private def hashAlgorithmFor(alg: JWSAlgorithm): String = alg match {
    case JWSAlgorithm.ES256 | JWSAlgorithm.RS256 | JWSAlgorithm.PS256 =>
      "SHA-256"
    case JWSAlgorithm.ES384 | JWSAlgorithm.RS384 | JWSAlgorithm.PS384 =>
      "SHA-384"
    case JWSAlgorithm.ES512 | JWSAlgorithm.RS512 | JWSAlgorithm.PS512 =>
      "SHA-512"
    case _ => throw new IllegalArgumentException(s"Unsupported algorithm: $alg")
  }

}
