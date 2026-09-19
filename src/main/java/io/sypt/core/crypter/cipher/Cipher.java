package io.sypt.core.crypter.cipher;

import io.sypt.core.crypter.exception.CrypterException;

/**
 * Cipher interface that defines encryption and decryption methods
 * @param <I> The INPUT value
 * @param <O> The OUTPUT value
 * @author tazouxme
 */
public interface Cipher<I, O> {

	/**
	 * Encrypt data
	 * @param input Clear data to be encrypted
	 * @return The encrypted data
	 * @throws CrypterException
	 */
	public O encrypt(I input) throws CrypterException;

	/**
	 * Decrypt data
	 * @param input Encrypted data to be decrypted
	 * @return The decrypted data
	 * @throws CrypterException
	 */
	public I decrypt(O input) throws CrypterException;

}
