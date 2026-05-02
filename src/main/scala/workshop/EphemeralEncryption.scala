package workshop

import com.nimbusds.jose.{
  EncryptionMethod,
  JWEAlgorithm,
  JWEHeader,
  JWEObject,
  Payload
}
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import scala.util.Try

object EphemeralEncryption {

  def encryptWithPFS(
      payload: String
  )(using recipientStaticKey: ECKey): Try[String] = Try {
    // Nimbus generates a fresh ephemeral key per encryption automatically with ECDH-ES
    val header = new JWEHeader.Builder(
      JWEAlgorithm.ECDH_ES_A256KW,
      EncryptionMethod.A256GCM
    )
      .keyID(recipientStaticKey.getKeyID)
      .build()

    val jwe = new JWEObject(header, new Payload(payload))
    jwe.encrypt(
      new ECDHEncrypter(recipientStaticKey)
    ) // ephemeral key pair generated internally
    jwe.serialize()
  }
}
