package io.sypt.core.crypter;

import java.security.GeneralSecurityException;

import io.sypt.core.crypter.cipher.AsymmetricPQCSypterCipher;
import io.sypt.core.crypter.cipher.SymmetricSypterCipher;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.entity.SymmetricSypterObject;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;

/**
 * Default PQC crypter that generates double encryption from {@link byte[]} to a {@link AsymmetricSypterObject}
 */
public final class PQCCrypter extends AbstractCrypter<byte[], SymmetricSypterObject, AsymmetricSypterObject> {

	public PQCCrypter(KSMType ksmType, KSM ksm, String ksmAlias) throws GeneralSecurityException {
		super(new AsymmetricPQCSypterCipher(ksmType, ksm, ksmAlias), new SymmetricSypterCipher(ksm.getProvider()));
	}

}
