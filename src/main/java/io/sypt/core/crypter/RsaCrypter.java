package io.sypt.core.crypter;

import java.security.GeneralSecurityException;

import io.sypt.core.crypter.cipher.AsymmetricRsaSypterCipher;
import io.sypt.core.crypter.cipher.SymmetricSypterCipher;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.entity.SymmetricSypterObject;
import io.sypt.core.keystore.KSM;

/**
 * Default RSA crypter that generates double encryption from {@link byte[]} to a {@link AsymmetricSypterObject}
 */
public final class RsaCrypter extends AbstractCrypter<byte[], SymmetricSypterObject, AsymmetricSypterObject> {
	
	public RsaCrypter(KSM ksm, String ksmAlias) throws GeneralSecurityException {
		super(new AsymmetricRsaSypterCipher(ksm, ksmAlias), new SymmetricSypterCipher(ksm.getProvider()));
	}

}
