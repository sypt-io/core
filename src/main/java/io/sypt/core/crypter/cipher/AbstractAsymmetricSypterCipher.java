package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.entity.SymmetricSypterObject;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;

public abstract sealed class AbstractAsymmetricSypterCipher extends AbstractCipher<SymmetricSypterObject, AsymmetricSypterObject>
		permits AsymmetricEcSypterCipher, AsymmetricRsaSypterCipher, AsymmetricPQCSypterCipher {
	
	private final KSM ksm;
	private final String ksmAlias;
	
	protected AbstractAsymmetricSypterCipher(KSMType ksmType, KSM ksm, String ksmAlias) throws GeneralSecurityException {
		super(ksmType.encryptionSpec().contentCrypter(), ksm.getProvider());
		this.ksm = ksm;
		this.ksmAlias = ksmAlias;
	}
	
	protected AbstractAsymmetricSypterCipher(KSM ksm, String ksmAlias, javax.crypto.Cipher cipher) {
		super(cipher);
		this.ksm = ksm;
		this.ksmAlias = ksmAlias;
	}

	@Override
	protected AsymmetricSypterObject encrypt(SymmetricSypterObject s, javax.crypto.Cipher cipher) throws CrypterException {
		if (ksm == null) {
			throw new CrypterException("'ksm' cannot be empty");
		}
		
		try {
			String encryptedSecretKey = encrypt(s.getSecretKey().getBytes(), cipher, ksm.getEncryptionKey(ksmAlias));
			return new AsymmetricSypterObject(s.getEncryptedData(), encryptedSecretKey, s.getIv());
		} catch (Exception e) {
			throw new CrypterException("Unable to encrypt", e);
		}
	}
	
	@Override
	protected SymmetricSypterObject decrypt(AsymmetricSypterObject input, javax.crypto.Cipher cipher) throws CrypterException {
		if (ksm == null) {
			throw new CrypterException("'ksm' cannot be empty");
		}
		
		try {
			String secretKey = new String(decrypt(input.getEncryptedSecretKey(), cipher, ksm.getDecryptionKey(ksmAlias)));
			return new SymmetricSypterObject(input.getEncryptedData(), secretKey, input.getIv());
		} catch (Exception e) {
			throw new CrypterException("Unable to decrypt", e);
		} 
	}
	
	private String encrypt(byte[] b, javax.crypto.Cipher cipher, PublicKey key) throws CrypterException {
		try {
			return new String(Base64.getEncoder().encode(wrapKey(b, cipher, key)));
		} catch (Exception e) {
			throw new CrypterException("Unable to encrypt", e);
		} 
	}
	
	/**
	 * Protect the symmetric secret key with the asymmetric public key
	 * @param secretKey The symmetric secret key to protect
	 * @param cipher The cipher used to protect the secret key
	 * @param key The public key
	 * @return The protected secret key
	 * @throws GeneralSecurityException
	 */
	protected abstract byte[] wrapKey(byte[] secretKey, javax.crypto.Cipher cipher, PublicKey key) throws GeneralSecurityException;
	
	private byte[] decrypt(String text, javax.crypto.Cipher cipher, PrivateKey key) throws CrypterException {
		try {
			return unwrapKey(Base64.getDecoder().decode(text), cipher, key);
		} catch (Exception e) {
			throw new CrypterException("Unable to decrypt", e);
		} 
	}
	
	/**
	 * Recover the symmetric secret key with the asymmetric private key
	 * @param wrappedKey The protected secret key
	 * @param cipher The cipher used to protect the secret key
	 * @param key The private key
	 * @return The symmetric secret key
	 * @throws GeneralSecurityException
	 */
	protected abstract byte[] unwrapKey(byte[] wrappedKey, javax.crypto.Cipher cipher, PrivateKey key) throws GeneralSecurityException;

}
