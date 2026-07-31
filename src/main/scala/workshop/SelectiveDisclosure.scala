package workshop

import scala.util.Try

import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.JWSAlgorithm

// SD-JWT (Selective Disclosure JWT) requires a dedicated library beyond nimbus-jose-jwt.
// This is a conceptual stub showing the intended API shape.
object SelectiveDisclosure {

  def issueKYCCredential(dob: String, nationality: String, riskLevel: String)(using
      issuerKey: ECKey
  ): Try[String] = Try {
    // In production: use an SD-JWT library (e.g. nimbus SD-JWT extension).
    // Each claim is individually salted and hashed;
    // the holder selectively discloses only what the verifier needs.
    ???
  }

}
