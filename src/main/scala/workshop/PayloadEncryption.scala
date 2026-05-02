package workshop

import com.nimbusds.jose.{
  JWEHeader,
  JWEAlgorithm,
  EncryptionMethod,
  JWEObject,
  Payload
}
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.RSAKey
import scala.util.Try

object PayloadEncryption {

  def encryptPayload(
      jsonPayload: String
  )(using recipientKey: RSAKey): Try[String] = Try {
    val header =
      new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
        .keyID(recipientKey.getKeyID)
        .contentType("application/json")
        .build()

    val payload = new Payload(jsonPayload)
    val jwe = new JWEObject(header, payload)

    jwe.encrypt(new RSAEncrypter(recipientKey))
    jwe.serialize()
  }
}
