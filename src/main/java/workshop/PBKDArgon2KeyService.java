package workshop;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class PBKDArgon2KeyService implements PBKDKeyService {

	private static final int ITERATIONS = 3;
	private static final int MEMORY_KB = 65536;
	private static final int PARALLELISM = 1;

	@Override
	public SecretKey generateKey(String password, byte[] salt, int keyLengthInBits) {
		Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withSalt(salt)
				.withIterations(ITERATIONS)
				.withMemoryAsKB(MEMORY_KB)
				.withParallelism(PARALLELISM)
				.build();

		Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(params);

		byte[] keyBytes = new byte[keyLengthInBits / 8];
		generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), keyBytes);

		return new SecretKeySpec(keyBytes, "AES");
	}
}
