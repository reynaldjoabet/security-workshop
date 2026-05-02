package workshop

import com.nimbusds.jose.{JWEObject}
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.jwk.RSAKey
import scala.util.Try

// Represents a business error or validation failure
enum WebhookError {
  case ParseFailure(msg: String)
  case DecryptionFailure(msg: String)
}

object WebhookReceiver {

  def decryptWebhook(
      encryptedToken: String
  )(using privateKey: RSAKey): Either[WebhookError, String] =
    for {
      jwe <- Try(JWEObject.parse(encryptedToken)).toEither.left.map(e =>
        WebhookError.ParseFailure(e.getMessage)
      )
      _ <- Try(jwe.decrypt(new RSADecrypter(privateKey))).toEither.left.map(e =>
        WebhookError.DecryptionFailure(e.getMessage)
      )
      payload <- Option(jwe.getPayload)
        .toRight(WebhookError.ParseFailure("Payload was null"))
    } yield payload.toString
}

// Usage:
// decryptWebhook(incomingString)(using myKey) match
//   case Right(json) => processSuccess(json)
//   case Left(err)   => log.error(s"Failed to process webhook: $err")
