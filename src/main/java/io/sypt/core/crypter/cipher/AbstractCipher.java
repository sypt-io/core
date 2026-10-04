package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.crypter.exception.CrypterException;

/**
 * Abstract class thats implements {@link Cipher}
 * @param <I> The INPUT value
 * @param <O> The OUTPUT value
 * @author tazouxme
 */
public abstract sealed class AbstractCipher<I, O> implements Cipher<I, O> 
		permits AbstractAsymmetricSypterCipher, SymmetricSypterCipher {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	private javax.crypto.Cipher cipher;
	
	protected AbstractCipher(String algo, String provider) throws GeneralSecurityException {
		this(StringUtils.isBlank(provider) ? javax.crypto.Cipher.getInstance(algo) : javax.crypto.Cipher.getInstance(algo, provider));
	}
	
	protected AbstractCipher(javax.crypto.Cipher cipher) {
		this.cipher = cipher;
	}
	
	@Override
	public O encrypt(I input) throws CrypterException {
		if (cipher == null) {
			log.error(CrypterException.CIPHER_CANNOT_BE_EMPTY);
			throw new CrypterException(CrypterException.CIPHER_CANNOT_BE_EMPTY);
		}
		
		return encrypt(input, cipher);
	}
	
	protected abstract O encrypt(I input, javax.crypto.Cipher cipher) throws CrypterException;
	
	@Override
	public I decrypt(O input) throws CrypterException {
		if (cipher == null) {
			log.error(CrypterException.CIPHER_CANNOT_BE_EMPTY);
			throw new CrypterException(CrypterException.CIPHER_CANNOT_BE_EMPTY);
		}
		
		return decrypt(input, cipher);
	}
	
	protected abstract I decrypt(O input, javax.crypto.Cipher cipher) throws CrypterException;

}
