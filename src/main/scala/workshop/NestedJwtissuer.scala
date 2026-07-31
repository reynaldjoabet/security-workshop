package workshop

import scala.util.Try

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.{ECDSASigner, RSAEncrypter}
import com.nimbusds.jose.jwk.{ECKey, RSAKey}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}

object NestedJwtIssuer {

  def createNestedToken(
      claims: JWTClaimsSet
  )(using bankPublicKey: RSAKey, mySigningKey: ECKey): Try[String] = Try {
    // 1. Sign
    val signedJwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.ES256)
        .keyID(mySigningKey.getKeyID)
        .build(),
      claims
    )
    signedJwt.sign(new ECDSASigner(mySigningKey))

    // 2. Encrypt the Signed JWT
    // MUST use ContentType ("cty") = "JWT" to signal it's a nested token
    val jweHeader =
      new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
        .contentType("JWT")
        .keyID(bankPublicKey.getKeyID)
        .build()

    val jwe = new JWEObject(jweHeader, new Payload(signedJwt))
    jwe.encrypt(new RSAEncrypter(bankPublicKey))
    jwe.serialize()
  }

}
