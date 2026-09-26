package io.sypt.core.keystore.factory.values;

import io.sypt.core.keystore.factory.KSMType;

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
	
	/**
	 * Represents the KSMType of the KeyStore
	 * @return
	 */
	public KSMType getType();

}
