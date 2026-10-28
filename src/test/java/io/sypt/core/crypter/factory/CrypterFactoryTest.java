package io.sypt.core.crypter.factory;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

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
	
	@Test
	void getCrypterWithTypeNoType() {
		KSM keyStoreManager = mock(KSM.class);
		Assertions.assertThrows(CrypterException.class, () -> CrypterFactory.getCrypter(null, keyStoreManager, ""));
	}
	
	@Test
	void getCrypterWithTypeNoKeyStoreManager() {
		Assertions.assertThrows(CrypterException.class, () -> CrypterFactory.getCrypter(KSMType.EC_256, null, ""));
	}

}
