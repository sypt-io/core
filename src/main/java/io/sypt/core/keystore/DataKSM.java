package io.sypt.core.keystore;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Manager to explore and find {@link PublicKey} / {@link PrivateKey} from a {@link KeyStore} using its data
 * @author tazouxme
 */
public class DataKSM extends AbstractKSM {

	/**
	 * Construct a new {@link DataKSM} using the default KeyStore.getInstance()
	 * @param data
	 * @param keyStorePassword
	 */
	public DataKSM(InputStream data, char[] keyStorePassword) {
		this(data, keyStorePassword, null);
	}

	/**
	 * Construct a new {@link DataKSM}
	 * @param data
	 * @param keyStorePassword
	 * @param provider
	 */
	public DataKSM(InputStream data, char[] keyStorePassword, String provider) {
		super(() -> data, keyStorePassword, provider);
	}

}
