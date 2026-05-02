package workshop;
import java.io.InputStream;

/**
 * Abstraction for stream based symmetric encryption and decryption services.
 * Implementations return {@link InputStream} instances that must be consumed
 * and closed by the caller. Concrete implementations include
 * {@link JcaCryptoServiceImpl} and {@link BcCryptoServiceImpl}.
 */
public interface CryptoService {

class Secret {}
	/**
	 * Encrypts the provided data stream.
	 *
	 * @param inputStream plaintext data to encrypt
	 * @param secret      secret material used to derive the encryption key
	 * @return a stream containing the encrypted data
	 */
	InputStream encrypt(InputStream inputStream, Secret secret);

	/**
	 * Decrypts an encrypted data stream.
	 *
	 * @param inputStream the encrypted data
	 * @return a stream yielding the decrypted plaintext
	 */
	InputStream decrypt(InputStream inputStream);

	/**
	 * Encrypts a text value and returns the Base64 encoded result.
	 *
	 * @param text   the text to encrypt
	 * @param secret secret material used to derive the encryption key
	 * @return encrypted text encoded in Base64
	 */
	String encryptText(String text, Secret secret);

	/**
	 * Decrypts a Base64 encoded encrypted text value.
	 *
	 * @param encryptedText the Base64 encoded encrypted text
	 * @return the decrypted plain text
	 */
	String decryptText(String encryptedText);

}