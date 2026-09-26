package io.sypt.core.crypter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.crypter.cipher.Cipher;
import io.sypt.core.crypter.exception.CrypterException;

/**
 * Abstract crypter (either RSA or EC crypter) that generates double encryption / decryption
 * @param <I> The INPUT value
 * @param <T> The INTERMEDIATE value
 * @param <O> The OUTPUT value
 * @author tazouxme
 */
public abstract sealed class AbstractCrypter<I, T, O> implements Crypter<I, O> permits EcCrypter, RsaCrypter {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	private final Cipher<T, O> asymmetricCipher;
	private final Cipher<I, T> symmetricCipher;
	
	protected AbstractCrypter(Cipher<T, O> asymmetricCipher, Cipher<I, T> symmetricCipher) {
		this.asymmetricCipher = asymmetricCipher;
		this.symmetricCipher = symmetricCipher;
	}
	
	@Override
	public O encrypt(I b) throws CrypterException {
		log.debug("Encrypt data");
		if (getAsymmetricCipher() == null || getSymmetricCipher() == null) {
			throw new CrypterException(CrypterException.CIPHERS_CANNOT_BE_EMPTY);
		}
		
		return getAsymmetricCipher().encrypt(getSymmetricCipher().encrypt(b));
	}
	
	@Override
	public I decrypt(O b) throws CrypterException {
		log.debug("Decrypt data");
		if (getAsymmetricCipher() == null || getSymmetricCipher() == null) {
			throw new CrypterException(CrypterException.CIPHERS_CANNOT_BE_EMPTY);
		}
		
		return getSymmetricCipher().decrypt(getAsymmetricCipher().decrypt(b));
	}
	
	public Cipher<T, O> getAsymmetricCipher() {
		return asymmetricCipher;
	}
	
	public Cipher<I, T> getSymmetricCipher() {
		return symmetricCipher;
	}

}
