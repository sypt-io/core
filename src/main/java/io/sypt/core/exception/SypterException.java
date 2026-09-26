package io.sypt.core.exception;

public class SypterException extends Exception {

	public SypterException(String message) {
		super(message);
	}

	public SypterException(String message, Throwable e) {
		super(message, e);
	}

}
