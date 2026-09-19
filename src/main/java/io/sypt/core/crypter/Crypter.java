package io.sypt.core.crypter;

import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import io.sypt.core.crypter.exception.CrypterException;

/**
 * Crypter interface that defines encryption and decryption methods
 * @param <I> The INPUT value
 * @param <O> the OUTPUT value
 * @author tazouxme
 */
public interface Crypter<I, O> {
	
	public static final String CIPHER_SYMMETRIC_ALGO_AES = "AES/GCM/NoPadding";
	public static final String CIPHER_ASYMMETRIC_ALGO_EC = "ECIES";
	public static final String CIPHER_ASYMMETRIC_ALGO_RSA = "RSA/ECB/OAEPPadding";
	
	public static final OAEPParameterSpec CRYPTER_ASYMMETRIC_OAEP_SPEC = 
			new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
	
	/**
	 * Encrypt data
	 * @param data Clear data to be encrypted
	 * @return The encrypted data
	 * @throws CrypterException
	 */
	public O encrypt(I data) throws CrypterException;
	
	/**
	 * Decrypt data
	 * @param b Encrypted data to be decrypted
	 * @return The decrypted data
	 * @throws CrypterException
	 */
	public I decrypt(O b) throws CrypterException;

}
