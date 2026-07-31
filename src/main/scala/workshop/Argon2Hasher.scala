import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

object Argon2Hasher {

  def hashPassword(password: Array[Char], salt: Array[Byte]): Array[Byte] = {
    // 1. Configure the parameters
    val params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
      .withVersion(Argon2Parameters.ARGON2_VERSION_13)
      .withIterations(3)     // Time cost
      .withMemoryAsKB(65536) // 64MB Memory cost
      .withParallelism(1)    // Degree of parallelism
      .withSalt(salt)
      .build()

    // 2. Initialize the generator
    val generator = new Argon2BytesGenerator()
    generator.init(params)

    // 3. Generate the hash (e.g., 32 bytes / 256 bits)
    val result = new Array[Byte](32)
    generator.generateBytes(password, result)

    result
  }

}
