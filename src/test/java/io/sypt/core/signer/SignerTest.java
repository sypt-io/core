package io.sypt.core.signer;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.core.signer.exception.SignerException;

class SignerTest {
	
	private static final KSMType EC_TYPE = KSMType.EC_256;
	
	@Test
	void signExceptionNoKeyStoreManager() {
		Signer signer = new EcSigner(EC_TYPE, null, "");
		Assertions.assertThrows(SignerException.class, () -> signer.sign(new byte[0]));
	}
	
	@Test
	void signExceptionNoPrivateKey() throws Exception {
		KSM keyStoreManager = mock(KSM.class);
		doThrow(new KSMException("")).when(keyStoreManager).getSigningKey("");

		Signer signer = spy(new EcSigner(EC_TYPE, keyStoreManager, ""));
		Assertions.assertThrows(SignerException.class, () -> signer.sign(new byte[0]));
	}
	
	@Test
	void signExceptionInvalidPrivateKey() {
		Signer signer = new EcSigner(EC_TYPE, null, "");
		Assertions.assertThrows(SignerException.class, () -> signer.sign(new byte[0], null, ""));
	}
	
	@Test
	void verifyExceptionNoKeyStoreManager() {
		Signer signer = new EcSigner(EC_TYPE, null, "");
		Assertions.assertThrows(SignerException.class, () -> signer.verify(new byte[0], new byte[0]));
	}
	
	@Test
	void verifyExceptionNoPublicKey() throws Exception {
		KSM keyStoreManager = mock(KSM.class);
		doThrow(new KSMException("")).when(keyStoreManager).getVerificationKey("");

		Signer signer = spy(new EcSigner(EC_TYPE, keyStoreManager, ""));
		Assertions.assertThrows(SignerException.class, () -> signer.verify(new byte[0], new byte[0]));
	}
	
	@Test
	void verifyExceptionInvalidPublicKey() {
		Signer signer = new EcSigner(EC_TYPE, null, "");
		Assertions.assertThrows(SignerException.class, () -> signer.verify(new byte[0], new byte[0], null, ""));
	}

}
