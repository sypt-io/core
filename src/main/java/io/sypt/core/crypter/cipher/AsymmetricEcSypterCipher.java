package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;

public final class AsymmetricEcSypterCipher extends AbstractAsymmetricSypterCipher {
	
	public AsymmetricEcSypterCipher(KSM ksm, String ksmAlias) throws GeneralSecurityException, KSMException {
		super(ksm, ksmAlias);
	}
	
	public AsymmetricEcSypterCipher(KSM ksm, String ksmAlias, javax.crypto.Cipher cipher) {
		super(ksm, ksmAlias, cipher);
	}
	
	@Override
	protected void initEncryptCipher(Cipher cipher, Key key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
	}
	
	@Override
	protected void initDecryptCipher(Cipher cipher, Key key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
	}

}
