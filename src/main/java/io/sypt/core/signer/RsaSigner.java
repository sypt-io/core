package io.sypt.core.signer;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;

public final class RsaSigner extends AbstractSigner {
	
	public RsaSigner(KSMType ksmType, KSM ksm, String ksmAlias) {
		super(ksmType, ksm, ksmAlias);
	}

}
