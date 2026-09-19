package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.keystore.KSM;

public final class AsymmetricRsaSypterCipher extends AbstractAsymmetricSypterCipher {
	
	public AsymmetricRsaSypterCipher(KSM ksm, String ksmAlias) throws GeneralSecurityException {
		super(ksm, ksmAlias, Crypter.CIPHER_ASYMMETRIC_ALGO_RSA);
	}
	
	public AsymmetricRsaSypterCipher(KSM ksm, String ksmAlias, javax.crypto.Cipher cipher) {
		super(ksm, ksmAlias, cipher);
	}
	
	@Override
	protected void initEncryptCipher(Cipher cipher, Key key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, Crypter.CRYPTER_ASYMMETRIC_OAEP_SPEC);
	}
	
	@Override
	protected void initDecryptCipher(Cipher cipher, Key key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, Crypter.CRYPTER_ASYMMETRIC_OAEP_SPEC);
	}

}
