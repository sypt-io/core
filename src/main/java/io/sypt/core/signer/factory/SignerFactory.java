package io.sypt.core.signer.factory;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.core.signer.EcSigner;
import io.sypt.core.signer.PQCSigner;
import io.sypt.core.signer.RsaSigner;
import io.sypt.core.signer.Signer;
import io.sypt.core.signer.exception.SignerException;

public class SignerFactory {
	
	private SignerFactory() { }
	
	/**
	 * Get a Signer depending on the KeyStore algorithm
	 * <ul>
	 * <li><code>EC (Elliptic Curve)</code> will return a <code>EcSigner</code></li>
	 * <li><code>RSA</code> will return a <code>RsaSigner</code></li>
	 * </ul>
	 * @param ksm The KSM
	 * @param ksmAlias The KSM's alias
	 * @return the generated Signer
	 * @throws SignerException if the KSM is null or if the algorithm is not EC nor RSA
	 */
	public static final Signer getSigner(KSM ksm, String ksmAlias) throws SignerException {
		if (ksm == null) {
			throw new SignerException("'ksm' cannot be null");
		}
		
		try {
			KSMType algorithm = ksm.getVerificationType(ksmAlias);
			if (algorithm == null) {
				throw new SignerException("Unable to retrieve KSM type");
			}
			
			return switch (algorithm) {
				case EC_256, EC_384 -> new EcSigner(ksm);
				case RSA_2048, RSA_4096 -> new RsaSigner(ksm);
				case PQC_L2, PQC_L5 -> new PQCSigner(ksm);
			};
		} catch (KSMException e) {
			throw new SignerException("Unable to generate new Signer", e);
		}
	}

}
