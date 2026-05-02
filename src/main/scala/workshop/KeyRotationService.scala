package workshop

import com.nimbusds.jose.jwk.{Curve, ECKey, JWKSet, KeyUse}
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import java.time.Instant
import java.util.{Date, UUID}
import scala.jdk.CollectionConverters.*
import scala.util.Try

trait DistributedKeyStore {
  def promoteKey(key: ECKey): Unit
  def retireOldKey(): Unit
  def getActiveAndRetiringPublicKeys: List[ECKey]
}

class KeyRotationService(keyStore: DistributedKeyStore) {

  /** Rotates the active signing key. Old key is retained in JWKS for TTL of
    * existing tokens (e.g., 5 minutes).
    */
  def rotate(): Try[ECKey] = Try {
    val newKey = new ECKeyGenerator(Curve.P_256)
      .keyID(UUID.randomUUID().toString)
      .keyUse(KeyUse.SIGNATURE)
      .expirationTime(
        Date.from(Instant.now().plusSeconds(300))
      ) // active window
      .generate()

    keyStore.promoteKey(newKey) // new key becomes signing key
    keyStore.retireOldKey() // old key stays in JWKS for ~5 more minutes
    newKey
  }

  /** Served at /.well-known/jwks.json — contains both active and retiring keys
    */
  def currentJwkSet(): JWKSet =
    new JWKSet(keyStore.getActiveAndRetiringPublicKeys.asJava)
}
