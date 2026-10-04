package io.sypt.core.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import io.sypt.core.keystore.exception.KSMException;

/**
 * Manager to explore and find {@link PublicKey} / {@link PrivateKey} from a {@link KeyStore} using its path
 * @author tazouxme
 */
public class FileKSM extends AbstractKSM {

	/**
	 * Default ResourceLoader to retrieve Certificate
	 */
	private static final KSMResourceLoader LOADER = new KSMResourceLoader();
	
	/**
	 * Path where the KeyStore is located
	 */
	private final String keyStorePath;
	
	/**
	 * Construct a new {@link FileKSM} using the default KeyStore.getInstance()
	 * @param keyStorePath
	 * @param keyStorePassword
	 * @throws KSMException 
	 */
	public FileKSM(String keyStorePath, char[] keyStorePassword) {
		this.keyStorePath = keyStorePath;
		super(keyStorePassword);
	}
	
	/**
	 * Construct a new {@link FileKSM}
	 * @param keyStorePath
	 * @param keyStorePassword
	 * @param provider
	 * @throws KSMException 
	 */
	public FileKSM(String keyStorePath, char[] keyStorePassword, String provider) {
		this.keyStorePath = keyStorePath;
		super(keyStorePassword, provider);
	}
	
	@Override
	protected InputStream getInputStream() throws KSMException {
		try {
			return LOADER.getResource(keyStorePath);
		} catch (IOException e) {
			throw new KSMException("Unable to load the Keystore resource", e);
		}
	}

}
