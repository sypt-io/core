package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Base64;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.SymmetricSypterObject;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.generator.SypterGenerator;
import io.sypt.core.generator.entity.SypterValues;
import io.sypt.core.keystore.KSM;

public final class SymmetricSypterCipher extends AbstractCipher<byte[], SymmetricSypterObject> {
	
	private final SypterGenerator generator;

	public SymmetricSypterCipher(String provider) throws GeneralSecurityException {
		this(new DefaultSypterGenerator(provider), provider);
	}

	public SymmetricSypterCipher(javax.crypto.Cipher cipher, String provider) {
		this(new DefaultSypterGenerator(provider), cipher);
	}

	public SymmetricSypterCipher(SypterGenerator generator, String provider) throws GeneralSecurityException {
		super(Crypter.CIPHER_SYMMETRIC_ALGO_AES, provider);
		this.generator = generator;
	}

	public SymmetricSypterCipher(SypterGenerator generator, javax.crypto.Cipher cipher) {
		super(cipher);
		this.generator = generator;
	}
	
	@Override
	protected SymmetricSypterObject encrypt(byte[] text, javax.crypto.Cipher cipher) throws CrypterException {
		try {
			SypterValues values = generator.generateValues();
			Key key = values.key();
			
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, values.iv())); 
			String encryptedData = new String(Base64.getEncoder().encode(cipher.doFinal(text)));
			
			return new SymmetricSypterObject(encryptedData, new String(Base64.getEncoder().encode(key.getEncoded())), values.encodedIv());
		} catch (Exception e) {
			throw new CrypterException("Unable to encrypt", e);
		}
	}
	
	@Override
	protected byte[] decrypt(SymmetricSypterObject s, javax.crypto.Cipher cipher) throws CrypterException {
		try {
			Key key = new SecretKeySpec(Base64.getDecoder().decode(s.getSecretKey()), KSM.AES);
	        GCMParameterSpec spec = new GCMParameterSpec(128, Base64.getDecoder().decode(s.getIv()));
			
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec); 
			return cipher.doFinal(Base64.getDecoder().decode(s.getEncryptedData()));
		} catch (Exception e) {
			throw new CrypterException("Unable to decrypt", e);
		}
	}

}
