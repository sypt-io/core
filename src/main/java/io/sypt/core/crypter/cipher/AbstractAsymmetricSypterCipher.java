package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Base64;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.entity.SymmetricSypterObject;
import io.sypt.core.keystore.KSM;

public abstract sealed class AbstractAsymmetricSypterCipher extends AbstractCipher<SymmetricSypterObject, AsymmetricSypterObject>
		permits AsymmetricEcSypterCipher, AsymmetricRsaSypterCipher {
	
	private final KSM ksm;
	private final String ksmAlias;
	
	protected AbstractAsymmetricSypterCipher(KSM ksm, String ksmAlias, String algorithm) throws GeneralSecurityException {
		super(algorithm, ksm.getProvider());
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
	
	private String encrypt(byte[] b, javax.crypto.Cipher cipher, Key key) throws CrypterException {
		try {
			initEncryptCipher(cipher, key);
			return new String(Base64.getEncoder().encode(cipher.doFinal(b)));
		} catch (Exception e) {
			throw new CrypterException("Unable to encrypt", e);
		} 
	}
	
	protected abstract void initEncryptCipher(javax.crypto.Cipher cipher, Key key) throws GeneralSecurityException;
	
	private byte[] decrypt(String text, javax.crypto.Cipher cipher, Key key) throws CrypterException {
		try {
			initDecryptCipher(cipher, key);
			return cipher.doFinal(Base64.getDecoder().decode(text));
		} catch (Exception e) {
			throw new CrypterException("Unable to decrypt", e);
		} 
	}
	
	protected abstract void initDecryptCipher(javax.crypto.Cipher cipher, Key key) throws GeneralSecurityException;

}
