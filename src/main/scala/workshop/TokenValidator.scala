package workshop

import java.net.URI

import scala.jdk.CollectionConverters.*
import scala.util.Try

import com.nimbusds.jose.jwk.source.{JWKSource, JWKSourceBuilder}
import com.nimbusds.jose.proc.{JWSVerificationKeySelector, SecurityContext}
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.proc.{
  ConfigurableJWTProcessor,
  DefaultJWTClaimsVerifier,
  DefaultJWTProcessor
}
import com.nimbusds.jwt.JWTClaimsSet

class TokenValidator(jwksUrl: String) {

  private val keySource: JWKSource[SecurityContext] =
    JWKSourceBuilder
      .create[SecurityContext](URI.create(jwksUrl).toURL())
      .build()

  private val processor: ConfigurableJWTProcessor[SecurityContext] = {
    val p = new DefaultJWTProcessor[SecurityContext]()
    p.setJWSKeySelector(
      new JWSVerificationKeySelector(JWSAlgorithm.ES256, keySource)
    )

    // Require specific claims
    val requiredClaims = new JWTClaimsSet.Builder()
      .issuer("https://auth.fintech.com")
      .build()
    p.setJWTClaimsSetVerifier(
      new DefaultJWTClaimsVerifier(requiredClaims, Set("sub", "exp").asJava)
    )
    p
  }

  // 2. Validation method
  def validate(token: String): Either[Throwable, JWTClaimsSet] =
    Try(processor.process(token, null)).toEither

}

// 3. Idiomatic Scala 3 Extension Methods for safe claim extraction
extension (claims: JWTClaimsSet) {

  def getScopeList: List[String] =
    Option(claims.getStringClaim("scope"))
      .map(_.split(" ").toList)
      .getOrElse(List.empty)

  def getOptionalClaim(name: String): Option[String] =
    Option(claims.getStringClaim(name))

}

// Usage:
// val result = validator.validate(tokenStr)
// result.map(_.getScopeList).foreach(println)
