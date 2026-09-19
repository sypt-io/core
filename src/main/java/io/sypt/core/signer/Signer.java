package io.sypt.core.signer;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.sypt.core.signer.exception.SignerException;

public interface Signer {

	public static final String ID_SEPARATOR = "::";
	public static final String KEY_STORE_TYPE = "pkcs12";

	public static final String SIGNATURE_ALGO_ECDSA = "SHA384withECDSA";
	public static final String SIGNATURE_ALGO_RSA = "SHA256withRSA";
	
	/**
	 * Sign data
	 * @param alias
	 * @param text
	 * @return Signature
	 * @throws SecuritySignerException
	 */
	public String sign(String alias, byte[] text) throws SignerException;
	
	/**
	 * Sign data using a specific {@link PrivateKey}
	 * @param text
	 * @param key
	 * @param algorithm
	 * @return Signature
	 * @throws SecuritySignerException
	 */
	public String sign(byte[] text, PrivateKey key, String algorithm) throws SignerException;
	
	/**
	 * Verify the Signature
	 * @param alias
	 * @param text
	 * @param digitalSignature
	 * @return Whether the Signature is verified
	 * @throws SecuritySignerException
	 */
	public boolean verify(String alias, byte[] text, byte[] digitalSignature) throws SignerException;
	
	/**
	 * Verify the Signature using a specific {@link PublicKey}
	 * @param text
	 * @param digitalSignature
	 * @param key
	 * @param algorithm
	 * @return Whether the Signature is verified
	 * @throws SecuritySignerException
	 */
	public boolean verify(byte[] text, byte[] digitalSignature, PublicKey key, String algorithm) throws SignerException;

}
