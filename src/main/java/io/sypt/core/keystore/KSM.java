package io.sypt.core.keystore;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

public interface KSM extends AutoCloseable {
	
	public static final String AES = "AES";
	public static final String EC = "EC";
	public static final String RSA = "RSA";

	public static final String SHA256_WITH_ECDSA = "SHA256withECDSA";
	public static final String SHA384_WITH_ECDSA = "SHA384withECDSA";
	public static final String SHA256_WITH_RSA = "SHA256withRSA";
	public static final String SHA512_WITH_RSA = "SHA512withRSA";

	public static final String ML_KEM_768 = "ML-KEM-768";
	public static final String ML_KEM_1024 = "ML-KEM-1024";
	public static final String ML_DSA_65 = "ML-DSA-65";
	public static final String ML_DSA_87 = "ML-DSA-87";

	public static final String KEY_STORE_TYPE = "pkcs12";
	
	/**
	 * Retrieve the Provider used to instantiate the KeyStore
	 * @return The Provider
	 */
	public String getProvider();
	
	/**
	 * Retrieve the {@link Certificate} from the KeyStore for the initialized crypter alias
	 * @param alias
	 * @return Found {@link Certificate}
	 * @throws KSMException
	 */
	public Certificate getEncryptionCertificate(String alias) throws KSMException;
	
	/**
	 * Retrieve the chain of {@link Certificate} from the KeyStore for the initialized crypter alias
	 * @param alias
	 * @return Found chain of {@link Certificate}
	 * @throws KSMException
	 */
	public Certificate[] getEncryptionCertificateChain(String alias) throws KSMException;

	/**
	 * Retrieve the {@link PublicKey} from the KeyStore for the initialized crypter alias
	 * @param alias
	 * @return Found {@link PublicKey}
	 * @throws KSMException
	 */
	public PublicKey getEncryptionKey(String alias) throws KSMException;
	
	/**
	 * Retrieve the {@link PrivateKey} from the KeyStore for the initialized crypter alias
	 * @param alias
	 * @return Found {@link PrivateKey}
	 * @throws KSMException
	 */
	public PrivateKey getDecryptionKey(String alias) throws KSMException;
	
	/**
	 * Retrieve the {@link Certificate} from the KeyStore for the initialized signer alias
	 * @param alias
	 * @return Found {@link Certificate}
	 * @throws KSMException
	 */
	public Certificate getVerificationCertificate(String alias) throws KSMException;
	
	/**
	 * Retrieve the chain of {@link Certificate} from the KeyStore for the initialized signer alias
	 * @param alias
	 * @return Found chain of {@link Certificate}
	 * @throws KSMException
	 */
	public Certificate[] getVerificationCertificateChain(String alias) throws KSMException;

	/**
	 * Retrieve the {@link PublicKey} from the KeyStore for the initialized signer alias
	 * @param alias
	 * @return Found {@link PublicKey}
	 * @throws KSMException
	 */
	public PublicKey getVerificationKey(String alias) throws KSMException;
	
	/**
	 * Retrieve the {@link PrivateKey} from the KeyStore for the initialized signer alias
	 * @param alias
	 * @return Found {@link PrivateKey}
	 * @throws KSMException
	 */
	public PrivateKey getSigningKey(String alias) throws KSMException;
	
	/**
	 * Checks whether the alias exists in the KSM
	 * @param alias To be checked
	 * @return True is the alias is present
	 * @throws KSMException
	 */
	public boolean exists(String alias) throws KSMException;
	
	/**
	 * Transfer an entry in this {@link KSM} using an existing KSM
	 * @param alias The alias of the transferred keys
	 * @param ksm The {@link KSM} where the keys are stored
	 * @throws KSMException
	 */
	public void put(String alias, KSM ksm) throws KSMException;
	
	/**
	 * Remove an entry from the KSM for the given alias
	 * @param alias Alias and associated keys to be removed
	 * @throws KSMException
	 */
	public void remove(String alias) throws KSMException;
	
	/**
	 * Get the current KeyStore as a Base64 String
	 * @return
	 * @throws KSMException
	 */
	public String toBase64() throws KSMException;
	
	/**
	 * Retrieve the {@link KSMType} based on the VerificationCertificate type
	 * @param alias
	 * @return Related {@link KSMType}
	 * @throws KSMException
	 */
	default KSMType getVerificationType(String alias) throws KSMException {
		PublicKey key = getVerificationKey(alias);
		if (key == null) {
			throw new KSMException("No VerificationKey found for alias: " + alias);
		}
		
		return KSMType.fromPublicKey(key);
	}
	
	/**
	 * Retrieve the {@link KSMType} based on the EncryptionCertificate type
	 * @param alias
	 * @return Related {@link KSMType}
	 * @throws KSMException
	 */
	default KSMType getEncryptionType(String alias) throws KSMException {
		PublicKey key = getEncryptionKey(alias);
		if (key == null) {
			throw new KSMException("No EncryptionKey found for alias: " + alias);
		}
		
		return KSMType.fromPublicKey(key);
	}

}
