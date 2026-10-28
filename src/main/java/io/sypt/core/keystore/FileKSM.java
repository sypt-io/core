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
	 * Construct a new {@link FileKSM} using the default KeyStore.getInstance()
	 * @param keyStorePath
	 * @param keyStorePassword
	 */
	public FileKSM(String keyStorePath, char[] keyStorePassword) {
		this(keyStorePath, keyStorePassword, null);
	}

	/**
	 * Construct a new {@link FileKSM}
	 * @param keyStorePath
	 * @param keyStorePassword
	 * @param provider
	 */
	public FileKSM(String keyStorePath, char[] keyStorePassword, String provider) {
		super(() -> open(keyStorePath), keyStorePassword, provider);
	}

	private static InputStream open(String keyStorePath) throws KSMException {
		try {
			return LOADER.getResource(keyStorePath);
		} catch (IOException e) {
			throw new KSMException("Unable to load the Keystore resource", e);
		}
	}

}
