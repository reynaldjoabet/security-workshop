package workshop

import java.util.Date

import scala.util.Try

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.{JWSVerificationKeySelector, SecurityContext}
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}

object JARMValidator {

  def validateAuthorizationResponse(
      jarmToken: String,
      expectedState: String,
      expectedIssuer: String
  )(using keySource: JWKSource[SecurityContext]): Either[String, String] =
    for {
      jwt   <- Try(SignedJWT.parse(jarmToken)).toEither.left.map(_.getMessage)
      _     <- verifySignature(jwt, keySource)
      claims = jwt.getJWTClaimsSet
      _     <- Either.cond(
             claims.getIssuer == expectedIssuer,
             (),
             "Issuer mismatch"
           )
      _ <- Either.cond(!isExpired(claims), (), "JARM token expired")
      _ <- Either.cond(
             claims.getStringClaim("state") == expectedState,
             (),
             "State mismatch — CSRF suspected"
           )
      code <- Option(claims.getStringClaim("code"))
                .toRight("Missing authorization code in JARM response")
    } yield code

  private def verifySignature(
      jwt: SignedJWT,
      keySource: JWKSource[SecurityContext]
  ): Either[String, Unit] = {
    val processor = new DefaultJWTProcessor[SecurityContext]()
    processor.setJWSKeySelector(
      new JWSVerificationKeySelector(JWSAlgorithm.ES256, keySource)
    )
    Try(processor.process(jwt.serialize(), null)).toEither.left
      .map(_.getMessage)
      .map(_ => ())
  }

  private def isExpired(claims: JWTClaimsSet): Boolean =
    Option(claims.getExpirationTime).exists(_.before(new Date()))

}
