package io.sypt.core.crypter.factory;

import java.security.GeneralSecurityException;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.crypter.EcCrypter;
import io.sypt.core.crypter.PQCCrypter;
import io.sypt.core.crypter.RsaCrypter;
import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

public class CrypterFactory {
	
	private CrypterFactory() { }

	/**
	 * Get a Crypter depending on the KeyStore algorithm
	 * <ul>
	 * <li><code>EC (Elliptic Curve)</code> will return a <code>EcCrypter</code></li>
	 * <li><code>RSA</code> will return a <code>RsaCrypter</code></li>
	 * <li><code>PQC</code> will return a <code>PQCCrypter</code></li>
	 * </ul>
	 * @param ksm The KSM
	 * @param ksmAlias The KSM's alias
	 * @return the generated Crypter
	 * @throws CrypterException if the KSM is null or if the algorithm is not EC nor RSA
	 */
	public static final Crypter<byte[], AsymmetricSypterObject> getCrypter(KSM ksm, String ksmAlias) throws CrypterException {
		if (ksm == null) {
			throw new CrypterException("'ksm' cannot be null");
		}
		
		try {
			return getCrypter(ksm.getEncryptionType(ksmAlias), ksm, ksmAlias);
		} catch (KSMException e) {
			throw new CrypterException("Unable to generate new Crypter", e);
		}
	}

	/**
	 * Get a Crypter depending on the KeyStore algorithm
	 * <ul>
	 * <li><code>EC (Elliptic Curve)</code> will return a <code>EcCrypter</code></li>
	 * <li><code>RSA</code> will return a <code>RsaCrypter</code></li>
	 * <li><code>PQC</code> will return a <code>PQCCrypter</code></li>
	 * </ul>
	 * @param ksmType The KSMType
	 * @param ksm The KSM
	 * @param ksmAlias The KSM's alias
	 * @return the generated Crypter
	 * @throws CrypterException if the KSM is null or if the algorithm is not EC nor RSA
	 */
	public static final Crypter<byte[], AsymmetricSypterObject> getCrypter(KSMType ksmType, KSM ksm, String ksmAlias) throws CrypterException {
		if (ksm == null) {
			throw new CrypterException("'ksm' cannot be null");
		}

		if (ksmType == null) {
			throw new CrypterException("'ksmType' cannot be null");
		}
		
		try {
			return switch (ksmType) {
				case EC_256, EC_384 -> new EcCrypter(ksmType, ksm, ksmAlias);
				case RSA_2048, RSA_4096 -> new RsaCrypter(ksmType, ksm, ksmAlias);
				case PQC_L2, PQC_L5 -> new PQCCrypter(ksmType, ksm, ksmAlias);
			};
		} catch (GeneralSecurityException e) {
			throw new CrypterException("Unable to generate new Crypter", e);
		}
	}

}
