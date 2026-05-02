package workshop

import com.nimbusds.jose.{JWSHeader, JWSAlgorithm, JWSObject, Payload}
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import scala.util.Try
import scala.jdk.CollectionConverters.*

object MessageSigner {

  /** Creates a detached signature for an HTTP body
    * @param httpBody
    *   The raw bytes of the HTTP request body
    * @return
    *   A Tuple2 containing (Base64Payload, DetachedJWSString)
    */
  def signHttpBody(
      httpBody: Array[Byte]
  )(using signingKey: ECKey): Try[(String, String)] = Try {
    val header = new JWSHeader.Builder(JWSAlgorithm.ES256)
      .keyID(signingKey.getKeyID)
      .base64URLEncodePayload(false) // FAPI detached payload requirement
      .criticalParams(Set("b64").asJava)
      .build()

    val jws = new JWSObject(header, new Payload(httpBody))
    jws.sign(new ECDSASigner(signingKey))

    val base64Payload = jws.getPayload.toBase64URL.toString
    val detachedSignature =
      jws.serialize(true) // true = serialize without payload

    (base64Payload, detachedSignature)
  }
}
