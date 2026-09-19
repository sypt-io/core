package io.sypt.core.keystore;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import io.sypt.core.keystore.exception.KSMException;

/**
 * Manager to explore and find {@link PublicKey} / {@link PrivateKey} from a {@link KeyStore} using its data
 * @author tazouxme
 */
public class DataKSM extends AbstractKSM {

	/**
	 * Default Data to retrieve Certificate
	 */
	private final InputStream data;
	
	/**
	 * Construct a new {@link DataKSM} using the default KeyStore.getInstance()
	 * @param data
	 * @param keyStorePassword
	 * @param provider
	 * @throws KSMException 
	 */
	public DataKSM(InputStream data, char[] keyStorePassword) {
		this.data = data;
		super(keyStorePassword);
	}
	
	/**
	 * Construct a new {@link DataKSM}
	 * @param data
	 * @param keyStorePassword
	 * @param provider
	 * @throws KSMException 
	 */
	public DataKSM(InputStream data, char[] keyStorePassword, String provider) {
		this.data = data;
		super(keyStorePassword, provider);
	}
	
	@Override
	protected InputStream getInputStream() throws KSMException {
		return data;
	}

}
