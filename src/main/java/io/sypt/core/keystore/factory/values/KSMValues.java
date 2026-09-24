package io.sypt.core.keystore.factory.values;

public interface KSMValues {
	
	/**
	 * Represents a KeyStore encoded in Base64
	 * @return
	 */
	public String getKeyStore();
	
	/**
	 * Represents a KeyStore password
	 * @return
	 */
	public char[] getPassword();

}
