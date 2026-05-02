package workshop

import scala.concurrent.Future

abstract class TokenExchangeClient {

  protected def tokenEndpoint: String
  protected def httpClient: (String, Map[String, String]) => Future[String]

  def exchangeForDownstreamToken(
      subjectToken: String,
      targetAudience: String,
      targetScope: String,
      clientAssertion: String // Private Key JWT
  ): Future[String] =
    httpClient(
      tokenEndpoint,
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" -> subjectToken,
        "subject_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
        "audience" -> targetAudience,
        "scope" -> targetScope,
        "client_assertion_type" -> "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" -> clientAssertion
      )
    )
}
