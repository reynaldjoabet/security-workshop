package workshop

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.*
import scala.jdk.CollectionConverters.*
import scala.util.Try

object RichAuthorizationBuilder {

  def buildPaymentAuthorizationDetails(
      amount: BigDecimal,
      currency: String,
      creditorIban: String,
      creditorName: String
  ): Map[String, Any] = Map(
    "type" -> "payment_initiation",
    "locations" -> List("https://api.bank.com/payments").asJava,
    "instructedAmount" -> Map(
      "currency" -> currency,
      "amount" -> amount.toString
    ).asJava,
    "creditorAccount" -> Map(
      "iban" -> creditorIban
    ).asJava,
    "creditorName" -> creditorName
  )

  // Embed in the JAR as the 'authorization_details' claim
  def embedInRequestObject(
      details: Map[String, Any]
  )(using signingKey: ECKey): Try[String] = Try {
    val claims = new JWTClaimsSet.Builder()
      .claim("authorization_details", List(details.asJava).asJava)
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
}
