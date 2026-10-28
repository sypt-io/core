package io.sypt.core.keystore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.util.LogUtils;

/**
 * Manager to explore and find {@link PublicKey} / {@link PrivateKey} from a PKCS12 {@link KeyStore} using its data
 * @author tazouxme
 */
public abstract class AbstractKSM implements KSM {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	/**
	 * KeyStore containing Public / Private keys
	 */
	private final KeyStore keyStore;
	
	/**
	 * Flag to ensure that the Keystore has not been closed
	 */
	private final AtomicBoolean closed = new AtomicBoolean(false);
	
	/**
	 * Security Provider. Default is {@link BouncyCastleProvider} (BC)
	 */
	private final String provider;
	
	/**
	 * Container for the PrivateKey password
	 */
	private final char[] password;
	
	/**
	 * Supplier of the KeyStore data
	 */
	@FunctionalInterface
	protected interface KeyStoreSource {
		
		InputStream open() throws KSMException;
		
	}
	
	/**
	 * Construct a new {@link AbstractKSM}. The KeyStore is loaded before the object initialization
	 * so that no partially initialized object exists if it fails
	 * @param source The KeyStore data, closed once loaded
	 * @param password
	 * @param provider If blank, the default KeyStore.getInstance() is used
	 */
	protected AbstractKSM(KeyStoreSource source, char[] password, String provider) {
		this(load(source, password, provider), password, provider);
	}

	private AbstractKSM(KeyStore keyStore, char[] password, String provider) {
		this.keyStore = keyStore;
		this.password = password.clone();
		this.provider = provider;

		log.info("KeyStore loaded and initialized");
	}

	/**
	 * Load the {@link KeyStore}, failing if the password is missing or if the KeyStore cannot be loaded
	 * @param source The KeyStore data
	 * @param password The password for the Keystore
	 * @param provider The KeyStore provider
	 * @return Loaded {@link KeyStore}
	 */
	private static KeyStore load(KeyStoreSource source, char[] password, String provider) {
		if (password == null) {
            throw new IllegalArgumentException("Keystore password is required");
        }

		char[] pwd = password.clone();
        try {
            return loadAndInitialize(source, pwd, provider);
        } catch (KSMException e) {
			throw new IllegalStateException("Unable to load keystore", e);
		} finally {
            Arrays.fill(pwd, '\0');
        }
	}

	/**
	 * Extract the {@link KeyStore} using the data of the KeyStore and its initialized password
	 * @param source The KeyStore data
	 * @param pwd The password for the Keystore
	 * @param provider The KeyStore provider
	 * @return Found {@link KeyStore}
	 * @throws KSMException
	 */
	private static KeyStore loadAndInitialize(KeyStoreSource source, char[] pwd, String provider) throws KSMException {
		try (InputStream is = source.open()) {
            if (is == null) {
                throw new KSMException("InputStream is null, cannot load KeyStore");
            }
            
            KeyStore ks = StringUtils.isBlank(provider) ? KeyStore.getInstance(KSM.KEY_STORE_TYPE) : KeyStore.getInstance(KSM.KEY_STORE_TYPE, provider);
            ks.load(is, pwd);
            return ks;
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KSMException("Unable to load the KeyStore", e);
        }
	}
	
	@Override
	public String getProvider() {
		return provider;
	}
	
	@Override
	public Certificate getEncryptionCertificate(String alias) throws KSMException {
        try {
            return getKeyStore().getCertificate(normalizeAlias(alias, "-enc"));
        } catch (KeyStoreException e) {
            throw new KSMException("Unable to get the EncryptionCertificate", e);
        }
	}
	
	@Override
	public Certificate[] getEncryptionCertificateChain(String alias) throws KSMException {
        try {
            return getKeyStore().getCertificateChain(normalizeAlias(alias, "-enc"));
        } catch (KeyStoreException e) {
            throw new KSMException("Unable to get the EncryptionCertificate chain", e);
        }
	}

	@Override
	public PublicKey getEncryptionKey(String alias) throws KSMException {
		Certificate cert = getEncryptionCertificate(normalizeAlias(alias, "-enc"));
        if (cert == null) {
            throw new KSMException("No EncryptionCertificate found for alias: " + alias);
        }
        return cert.getPublicKey();
	}
	
	@Override
	public PrivateKey getDecryptionKey(String alias) throws KSMException {
		String sanitizedAlias = LogUtils.sanitize(alias);
		log.warn("Accessing DecryptionKey with alias {}", sanitizedAlias);
        char[] pwd = password.clone();
        try {
            return (PrivateKey) getKeyStore().getKey(normalizeAlias(alias, "-enc"), pwd);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new KSMException("Unable to get the DecryptionKey", e);
        } finally {
            Arrays.fill(pwd, '\0');
        }
	}
	
	@Override
	public Certificate getVerificationCertificate(String alias) throws KSMException {
        try {
            return getKeyStore().getCertificate(normalizeAlias(alias, "-sig"));
        } catch (KeyStoreException e) {
            throw new KSMException("Unable to get the VerificationCertificate", e);
        }
	}
	
	@Override
	public Certificate[] getVerificationCertificateChain(String alias) throws KSMException {
        try {
            return getKeyStore().getCertificateChain(normalizeAlias(alias, "-sig"));
        } catch (KeyStoreException e) {
            throw new KSMException("Unable to get the VerificationCertificate chain", e);
        }
	}

	@Override
	public PublicKey getVerificationKey(String alias) throws KSMException {
		Certificate cert = getVerificationCertificate(normalizeAlias(alias, "-sig"));
        if (cert == null) {
            throw new KSMException("No VerificationCertificate found for alias: " + alias);
        }
        return cert.getPublicKey();
	}
	
	@Override
	public PrivateKey getSigningKey(String alias) throws KSMException {
		String sanitizedAlias = LogUtils.sanitize(alias);
		log.warn("Accessing SigningKey with alias {}", sanitizedAlias);
        char[] pwd = password.clone();
        try {
            return (PrivateKey) getKeyStore().getKey(normalizeAlias(alias, "-sig"), pwd);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new KSMException("Unable to get the SigningKey", e);
        } finally {
            Arrays.fill(pwd, '\0');
        }
	}
	
	@Override
	public boolean exists(String alias) throws KSMException {
		try {
			boolean containsSig = getKeyStore().containsAlias(normalizeAlias(alias, "-sig"));
			boolean containsEnc = getKeyStore().containsAlias(normalizeAlias(alias, "-enc"));
			
			if (containsSig ^ containsEnc) {
				String sanitizedAlias = LogUtils.sanitize(alias);
				log.warn("Keystore is not in sync for alias {}", sanitizedAlias);
				throw new KSMException("Keystore is not in sync for alias " + alias);
			}
			
			return containsSig && containsEnc;
		} catch (KeyStoreException | KSMException e) {
			throw new KSMException("Unable to verify the sig alias " + alias, e);
		}
	}
	
	@Override
	public void put(String alias, KSM ksm) throws KSMException {
		String sanitizedAlias = LogUtils.sanitize(alias);
        char[] pwd = password.clone();
        ProtectionParameter protectionParam = new PasswordProtection(pwd);
		try {
			log.debug("Tranferring sig data data for alias {}", sanitizedAlias);
			PrivateKeyEntry sigEntry = new PrivateKeyEntry(ksm.getSigningKey(alias), ksm.getVerificationCertificateChain(alias));
			getKeyStore().setEntry(normalizeAlias(alias, "-sig"), sigEntry, protectionParam);
			
			log.debug("Tranferring enc data data for alias {}", sanitizedAlias);
			PrivateKeyEntry encEntry = new PrivateKeyEntry(ksm.getDecryptionKey(alias), ksm.getEncryptionCertificateChain(alias));
			getKeyStore().setEntry(normalizeAlias(alias, "-enc"), encEntry, protectionParam);
		} catch (KeyStoreException | KSMException e) {
            throw new KSMException("Unable to put the Keys from the given KSM", e);
		} finally {
            Arrays.fill(pwd, '\0');
            protectionParam = null;
        }
	}

	@Override
	public void remove(String alias) throws KSMException {
		try {
			getKeyStore().deleteEntry(normalizeAlias(alias, "-sig"));
			getKeyStore().deleteEntry(normalizeAlias(alias, "-enc"));
		} catch (KeyStoreException | KSMException e) {
            throw new KSMException("Unable to remove the Keys for the given alias " + alias, e);
		}
	}
	
	@Override
	public String toBase64() throws KSMException {
		KeyStore localKeyStore = getKeyStore();
		char[] pwd = password.clone();
		try {
			return encode(localKeyStore, pwd);
		} finally {
			Arrays.fill(pwd, '\0');
		}
	}

	/**
	 * Export a copy of the KeyStore where the KeyStore and every key are protected by the new password.
	 * This {@link KSM} keeps its own password
	 */
	@Override
	public String toBase64(char[] newPassword) throws KSMException {
		if (newPassword == null) {
			throw new KSMException("The new KeyStore password cannot be null");
		}

		KeyStore localKeyStore = getKeyStore();
		char[] newPwd = newPassword.clone();
		PasswordProtection current = new PasswordProtection(password);
		PasswordProtection target = new PasswordProtection(newPwd);
		try {
			KeyStore copy = StringUtils.isBlank(provider) ? KeyStore.getInstance(KSM.KEY_STORE_TYPE) : KeyStore.getInstance(KSM.KEY_STORE_TYPE, provider);
			copy.load(null, null);

			for (String alias : Collections.list(localKeyStore.aliases())) {
				if (localKeyStore.isKeyEntry(alias)) {
					copy.setEntry(alias, localKeyStore.getEntry(alias, current), target);
				} else {
					copy.setEntry(alias, localKeyStore.getEntry(alias, null), null);
				}
			}

			return encode(copy, newPwd);
		} catch (GeneralSecurityException | IOException e) {
			throw new KSMException("Unable to copy the KeyStore with the new password", e);
		} finally {
			Arrays.fill(newPwd, '\0');
			destroy(current);
			destroy(target);
		}
	}

	private static String encode(KeyStore keyStore, char[] pwd) throws KSMException {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			keyStore.store(out, pwd);

			return Base64.getEncoder().encodeToString(out.toByteArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new KSMException("Unable to export the KeyStore", e);
		}
	}

	private void destroy(PasswordProtection protection) {
		try {
			protection.destroy();
		} catch (DestroyFailedException _) {
			log.trace("Unable to destroy the password protection");
		}
	}
	
	@Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            Arrays.fill(password, '\0');
            log.debug("KSM closed and secrets wiped");
        }
    }
	
	private KeyStore getKeyStore() throws KSMException {
		if (closed.get()) {
            throw new KSMException("KSM is closed. Secrets have been wiped.");
        }
        return keyStore;
	}
	
	private String normalizeAlias(String alias, String suffix) {
		if (!alias.endsWith(suffix)) {
			return alias + suffix;
		}
		
		return alias;
	}

}
