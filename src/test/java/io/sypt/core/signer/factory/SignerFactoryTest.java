package io.sypt.core.signer.factory;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.signer.exception.SignerException;

class SignerFactoryTest {
	
	@Test
	void getSignerNoKeyStoreManager() {
		Assertions.assertThrows(SignerException.class, () -> SignerFactory.getSigner(null, ""));
	}
	
	@Test
	void getSignerNoPublicKey() throws Exception {
		KSM keyStoreManager = mock(KSM.class);
		doThrow(new KSMException("")).when(keyStoreManager).getVerificationKey("");
		
		Assertions.assertThrows(SignerException.class, () -> SignerFactory.getSigner(keyStoreManager, ""));
	}

}
