package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.Provider;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.crypter.exception.CrypterException;

/**
 * Abstract class thats implements {@link Cipher}.
 * <p>
 * Thread-safe: a {@link javax.crypto.Cipher} is stateful, so a new one is created for each operation
 * @param <I> The INPUT value
 * @param <O> The OUTPUT value
 * @author tazouxme
 */
public abstract sealed class AbstractCipher<I, O> implements Cipher<I, O>
		permits AbstractAsymmetricSypterCipher, SymmetricSypterCipher {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	/**
	 * Creates a new {@link javax.crypto.Cipher} for each operation
	 */
	@FunctionalInterface
	private interface CipherSource {

		javax.crypto.Cipher newCipher() throws GeneralSecurityException;

	}

	private final CipherSource cipherSource;

	/**
	 * @param algo The cipher transformation
	 * @param provider If blank, the default provider is used
	 * @throws GeneralSecurityException if the transformation is not available
	 */
	protected AbstractCipher(String algo, String provider) throws GeneralSecurityException {
		this(source(algo, provider));
	}

	/**
	 * @param cipher Gives the transformation and the provider of the ciphers created for each operation
	 */
	protected AbstractCipher(javax.crypto.Cipher cipher) {
		this(source(cipher));
	}

	private AbstractCipher(CipherSource cipherSource) {
		this.cipherSource = cipherSource;
	}

	@Override
	public O encrypt(I input) throws CrypterException {
		return encrypt(input, newCipher());
	}

	protected abstract O encrypt(I input, javax.crypto.Cipher cipher) throws CrypterException;

	@Override
	public I decrypt(O input) throws CrypterException {
		return decrypt(input, newCipher());
	}

	protected abstract I decrypt(O input, javax.crypto.Cipher cipher) throws CrypterException;

	private javax.crypto.Cipher newCipher() throws CrypterException {
		if (cipherSource == null) {
			log.error(CrypterException.CIPHER_CANNOT_BE_EMPTY);
			throw new CrypterException(CrypterException.CIPHER_CANNOT_BE_EMPTY);
		}

		try {
			return cipherSource.newCipher();
		} catch (GeneralSecurityException e) {
			throw new CrypterException("Unable to create the cipher", e);
		}
	}

	private static CipherSource source(String algo, String provider) throws GeneralSecurityException {
		CipherSource source = () -> StringUtils.isBlank(provider) ? javax.crypto.Cipher.getInstance(algo) : javax.crypto.Cipher.getInstance(algo, provider);

		// Fail fast if the transformation or the provider is not available
		source.newCipher();
		return source;
	}

	private static CipherSource source(javax.crypto.Cipher cipher) {
		if (cipher == null) {
			return null;
		}

		String algo = cipher.getAlgorithm();
		Provider provider = cipher.getProvider();
		return () -> javax.crypto.Cipher.getInstance(algo, provider);
	}

}
