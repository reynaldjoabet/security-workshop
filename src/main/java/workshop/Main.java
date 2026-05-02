package workshop;

import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Main {
    public static void main(String[] args) {
        System.out.println("Run the unit tests to see the vulnerabilities in action!");
    }

 	private static byte[] generateKey(byte[] secret, byte[] salt) {
		Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(
				new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
						.withSalt(salt).withMemoryAsKB(65536).withParallelism(4).withIterations(1).build());

		byte[] key = new byte[32];
		generator.generateBytes(secret, key);
		return key;
	}   
}