package io.sypt.core.crypter;

import java.security.GeneralSecurityException;

import io.sypt.core.crypter.cipher.AsymmetricEcSypterCipher;
import io.sypt.core.crypter.cipher.SymmetricSypterCipher;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.entity.SymmetricSypterObject;
import io.sypt.core.keystore.KSM;

/**
 * Default Elliptic Curve crypter that generates double encryption from {@link byte[]} to a {@link AsymmetricSypterObject}
 */
public final class EcCrypter extends AbstractCrypter<byte[], SymmetricSypterObject, AsymmetricSypterObject> {
	
	public EcCrypter(KSM ksm, String ksmAlias) throws GeneralSecurityException {
		super(new AsymmetricEcSypterCipher(ksm, ksmAlias), new SymmetricSypterCipher(ksm.getProvider()));
	}

}
