package io.sypt.core.keystore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.keystore.exception.KSMException;

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
	 * Container for the PrivateKey password
	 */
	private final char[] password;
	
	/**
	 * Security Provider. Default is {@link BouncyCastleProvider} (BC)
	 */
	private final String provider;
	
	/**
	 * Construct a new {@link AbstractKSM} using the default KeyStore.getInstance()
	 * @param password
	 * @throws KSMException 
	 */
	protected AbstractKSM(char[] password) {
		this(password, null);
	}
	
	/**
	 * Construct a new {@link AbstractKSM}
	 * @param password
	 * @param provider
	 * @throws KSMException 
	 */
	protected AbstractKSM(char[] password, String provider) {
		if (password == null) {
            throw new IllegalArgumentException("Keystore password is required");
        }
		
		this.password = password.clone();
		this.provider = provider;
		
		char[] pwd = password.clone();
        try {
            this.keyStore = loadAndInitialize(pwd);
        } catch (KSMException e) {
        	log.warn("Unable to load keystore");
			throw new IllegalStateException("Unable to load keystore", e);
		} finally {
            Arrays.fill(pwd, '\0');
        }
	}

	/**
	 * Extract the {@link KeyStore} using the data of the KeyStore and its initialized password
	 * @param The password for the Keystore
	 * @return Found {@link KeyStore}
	 * @throws KSMException
	 */
	private KeyStore loadAndInitialize(char[] pwd) throws KSMException {
		try (InputStream is = getInputStream()) {
            if (is == null) {
                throw new KSMException("InputStream is null, cannot load KeyStore");
            }
            
            KeyStore ks = StringUtils.isBlank(provider) ? KeyStore.getInstance(KSM.KEY_STORE_TYPE) : KeyStore.getInstance(KSM.KEY_STORE_TYPE, provider);
            ks.load(is, pwd);
            log.info("KeyStore loaded and initialized");
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
		log.warn("Accessing getDecryptionKey with alias {}", alias);
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
		log.warn("Accessing SigningKey with alias {}", alias);
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
				log.warn("Keystore is not in sync for alias {}", alias);
				throw new KSMException("Keystore is not in sync for alias " + alias);
			}
			
			return containsSig && containsEnc;
		} catch (KeyStoreException | KSMException e) {
			throw new KSMException("Unable to verify the sig alias " + alias, e);
		}
	}
	
	@Override
	public void put(String alias, KSM ksm) throws KSMException {
        char[] pwd = password.clone();
        ProtectionParameter protectionParam = new PasswordProtection(pwd);
		try {
			log.debug("Tranferring sig data data for alias {}", alias);
			PrivateKeyEntry sigEntry = new PrivateKeyEntry(ksm.getSigningKey(alias), ksm.getVerificationCertificateChain(alias));
			getKeyStore().setEntry(normalizeAlias(alias, "-sig"), sigEntry, protectionParam);
			
			log.debug("Tranferring enc data data for alias {}", alias);
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
        char[] pwd = password.clone();
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			getKeyStore().store(PKCS12StoreParameter.builder(out, pwd).build());
			return Base64.getEncoder().encodeToString(out.toByteArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | KSMException e) {
			throw new KSMException("Unable to put the Keys from the given KSM", e);
		} finally {
            Arrays.fill(pwd, '\0');
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
	
	protected abstract InputStream getInputStream() throws KSMException;

}
