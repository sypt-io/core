package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;

public final class AsymmetricRsaSypterCipher extends AbstractAsymmetricSypterCipher {
	
	public AsymmetricRsaSypterCipher(KSMType ksmType, KSM ksm, String ksmAlias) throws GeneralSecurityException {
		super(ksmType, ksm, ksmAlias);
	}
	
	public AsymmetricRsaSypterCipher(KSM ksm, String ksmAlias, javax.crypto.Cipher cipher) {
		super(ksm, ksmAlias, cipher);
	}
	
	@Override
	protected byte[] wrapKey(byte[] secretKey, Cipher cipher, PublicKey key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, Crypter.CRYPTER_ASYMMETRIC_OAEP_SPEC_256);
		return cipher.doFinal(secretKey);
	}
	
	@Override
	protected byte[] unwrapKey(byte[] wrappedKey, Cipher cipher, PrivateKey key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, Crypter.CRYPTER_ASYMMETRIC_OAEP_SPEC_256);
		return cipher.doFinal(wrappedKey);
	}

}
