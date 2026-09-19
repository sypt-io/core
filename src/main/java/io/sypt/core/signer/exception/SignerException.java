package io.sypt.core.signer.exception;

public class SignerException extends Exception {
	
	public static final String CANNOT_SIGN = "Unable to sign";
	public static final String CANNOT_VERIFY = "Unable to verify signature";
	
	public SignerException(String message) {
		super(message);
	}
	
	public SignerException(String message, Throwable e) {
		super(message, e);
	}

}
