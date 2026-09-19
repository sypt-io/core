package io.sypt.core.signer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.sypt.core.signer.exception.SignerException;

public record SignerParams(String object, String keyId, long timestamp) {
	
	public byte[] digest() throws SignerException {
		String input = object + Signer.ID_SEPARATOR + keyId + Signer.ID_SEPARATOR + Long.valueOf(timestamp);
		
		try {
            return MessageDigest.getInstance("SHA3-256").digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new SignerException("Algorithm SHA3-256 not found", e);
        }
	}

}
