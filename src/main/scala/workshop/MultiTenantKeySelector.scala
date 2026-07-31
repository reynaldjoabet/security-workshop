package workshop

import java.net.URI
import java.security.Key

import scala.jdk.CollectionConverters.*
import scala.util.Try

import com.nimbusds.jose.jwk.{JWKMatcher, JWKSelector}
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.{JWSKeySelector, SecurityContext}
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector
import com.nimbusds.jwt.JWTClaimsSet

trait TenantRegistry {
  def getJwksUrlForIssuer(issuer: String): Option[String]
}

class MultiTenantKeySelector(tenantRegistry: TenantRegistry)
    extends JWTClaimsSetAwareJWSKeySelector[SecurityContext] {

  override def selectKeys(
      header: JWSHeader,
      claimsSet: JWTClaimsSet,
      context: SecurityContext
  ): java.util.List[? <: Key] = {
    val issuer        = claimsSet.getIssuer
    val tenantJwksUrl = tenantRegistry
      .getJwksUrlForIssuer(issuer)
      .getOrElse(throw new IllegalArgumentException(s"Unknown tenant: $issuer"))

    val keySource = JWKSourceBuilder
      .create[SecurityContext](URI.create(tenantJwksUrl).toURL())
      .build()
    val selector = new JWKSelector(
      new JWKMatcher.Builder().keyID(header.getKeyID).build()
    )
    keySource
      .get(selector, context)
      .asScala
      .flatMap(jwk => Try(jwk.toECKey.toECPublicKey).toOption)
      .toList
      .asJava
  }

}

// Plug this into your ConfigurableJWTProcessor
// processor.setJWTClaimsSetAwareJWSKeySelector(new MultiTenantKeySelector(registry))
