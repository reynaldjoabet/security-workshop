package workshop

import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import java.security.{PrivateKey, Provider}
import scala.util.Try

object HsmSigner {

  /** Signs a JWT using a private key reference where the actual signing happens
    * on the HSM hardware via the injected JCA provider.
    */
  def signWithHSM(claims: JWTClaimsSet, hsmKeyRef: PrivateKey)(using
      hsmProvider: Provider,
      publicKey: ECKey
  ): Try[String] = Try {
    // We only need the private key REFERENCE and the public key for the header
    val signer = new ECDSASigner(hsmKeyRef, publicKey.getCurve)

    // Crucial: Tell Nimbus to send the cryptographic operation to the HSM provider
    signer.getJCAContext.setProvider(hsmProvider)

    val header = new JWSHeader.Builder(JWSAlgorithm.ES256)
      .keyID(publicKey.getKeyID)
      .build()

    val jwt = new SignedJWT(header, claims)
    jwt.sign(signer)
    jwt.serialize()
  }
}
