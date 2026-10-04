package io.sypt.core.crypter.exception;

public class CrypterException extends Exception {
	
	public static final String CIPHER_CANNOT_BE_EMPTY = "'cipher' cannot be empty";
	public static final String CIPHERS_CANNOT_BE_EMPTY = "'asymmetricCipher' and 'symmetricCipher' cannot be empty";

	public CrypterException(String message) {
		super(message);
	}

	public CrypterException(String message, Throwable e) {
		super(message, e);
	}

}
