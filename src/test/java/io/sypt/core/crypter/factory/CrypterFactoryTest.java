package io.sypt.core.crypter.factory;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;

class CrypterFactoryTest {
	
	@Test
	void getCrypterNoKeyStoreManager() {
		Assertions.assertThrows(CrypterException.class, () -> CrypterFactory.getCrypter(null, ""));
	}
	
	@Test
	void getCrypterNoPublicKey() throws Exception {
		KSM keyStoreManager = mock(KSM.class);
		doThrow(new KSMException("")).when(keyStoreManager).getEncryptionKey("");
		
		Assertions.assertThrows(CrypterException.class, () -> CrypterFactory.getCrypter(keyStoreManager, ""));
	}

}
