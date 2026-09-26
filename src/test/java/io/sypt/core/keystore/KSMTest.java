package io.sypt.core.keystore;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.Base64;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatchers;
import org.mockito.junit.jupiter.MockitoExtension;

import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

@ExtendWith(MockitoExtension.class)
class KSMTest {
	
	public KSMTest() {
		Security.addProvider(new BouncyCastleProvider());
	}
    
    @Test
    void shouldLoadPqcKeystore() throws Exception {
    	try (KSM ksm = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray())) {
    		String sigAlgo = ksm.getVerificationKey("sypt-crypto-data").getAlgorithm();
    		assertTrue(sigAlgo.startsWith("ML-DSA"), "Expected ML-DSA algorithm, got: " + sigAlgo);
    		String encAlgo = ksm.getEncryptionKey("sypt-crypto-data").getAlgorithm();
    		assertTrue(encAlgo.startsWith("ML-KEM"), "Expected ML-KEM algorithm, got: " + sigAlgo);
    	}
    }
    
    @Test
    void shouldLoadPqcKeystore_WithBouncyCastle() throws Exception {
    	try (KSM ksm = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
    		String sigAlgo = ksm.getVerificationKey("sypt-crypto-data").getAlgorithm();
    		assertTrue(sigAlgo.startsWith("ML-DSA"), "Expected ML-DSA algorithm, got: " + sigAlgo);
    		String encAlgo = ksm.getEncryptionKey("sypt-crypto-data").getAlgorithm();
    		assertTrue(encAlgo.startsWith("ML-KEM"), "Expected ML-KEM algorithm, got: " + sigAlgo);
    	}
    }
	
	@ParameterizedTest
	@MethodSource("testGetNullDataKeystore")
	void testGetNullDataKeystore(Class<? extends Exception> e, InputStream is, char[] keystorePassword) {
		Assertions.assertThrows(e, () -> new DataKSM(is, keystorePassword, "BC"));
	}
	
	@Test
	void testGetCertificate() throws Exception {
		try (KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			Assertions.assertDoesNotThrow(() -> masterKsm.getEncryptionCertificate("sypt-crypto-data"));			
			Assertions.assertDoesNotThrow(() -> masterKsm.getVerificationCertificate("sypt-crypto-data"));			
		}
	}
	
	@Test
	void testGetCertificateException() throws Exception {
		KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");
		KSM manager = spy(masterKsm);

		manager.close();

	    Assertions.assertThrows(KSMException.class, () -> manager.getEncryptionCertificate("sypt-crypto-data"));
	    Assertions.assertThrows(KSMException.class, () -> manager.getVerificationCertificate("sypt-crypto-data"));
	}
	
	@Test
	void testGetPublicKey() throws Exception {
		try (KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			Assertions.assertDoesNotThrow(() -> masterKsm.getVerificationKey("sypt-crypto-data"));
			Assertions.assertDoesNotThrow(() -> masterKsm.getEncryptionKey("sypt-crypto-data"));
		}
	}
	
	@Test
	void testGetPublicKeyNullException() throws KSMException {
		KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");
		KSM manager = spy(masterKsm);

		when(manager.getEncryptionCertificate(ArgumentMatchers.anyString())).thenReturn(null);
		when(manager.getVerificationCertificate(ArgumentMatchers.anyString())).thenReturn(null);

	    Assertions.assertThrows(KSMException.class, () -> manager.getEncryptionKey("sypt-crypto-data"));
	    Assertions.assertThrows(KSMException.class, () -> manager.getVerificationKey("sypt-crypto-data"));
	}
	
	@Test
	void testGetPublicKeyException() throws Exception {
		KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");
		KSM manager = spy(masterKsm);

		manager.close();

	    Assertions.assertThrows(KSMException.class, () -> manager.getEncryptionKey("sypt-crypto-data"));
	    Assertions.assertThrows(KSMException.class, () -> manager.getVerificationKey("sypt-crypto-data"));
	}
	
	@Test
	void testGetPrivateKey() throws Exception {
		try (KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			Assertions.assertDoesNotThrow(() -> masterKsm.getDecryptionKey("sypt-crypto-data"));
			Assertions.assertDoesNotThrow(() -> masterKsm.getSigningKey("sypt-crypto-data"));
		}
	}
	
	@Test
	void testGetPrivateKeyException() throws Exception {
		KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");
		KSM manager = spy(masterKsm);

		manager.close();

	    Assertions.assertThrows(KSMException.class, () -> manager.getDecryptionKey("sypt-crypto-data"));
	    Assertions.assertThrows(KSMException.class, () -> manager.getSigningKey("sypt-crypto-data"));
	}
	
	@Test
	void testExists() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec-new.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			Assertions.assertTrue(source.exists("sypt-crypto-data-new"));
			
			source.remove("sypt-crypto-data-new");

			Assertions.assertFalse(source.exists("sypt-crypto-data-new"));
		}
	}
	
	@Test
	void testExistsException() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec-new.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			KSM manager = spy(source);
			manager.close();
			
			Assertions.assertThrows(KSMException.class, () -> source.exists("sypt-crypto-data-new"));
		}
	}
	
	@Test
	void testPut() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec-new.p12", "sypt-crypto-data-pass".toCharArray(), "BC");
				KSM target = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			Assertions.assertNull(target.getDecryptionKey("sypt-crypto-data-new"));
			Assertions.assertNull(target.getSigningKey("sypt-crypto-data-new"));
			
			target.put("sypt-crypto-data-new", source);

			Assertions.assertNotNull(target.getDecryptionKey("sypt-crypto-data-new"));
			Assertions.assertNotNull(target.getSigningKey("sypt-crypto-data-new"));
		}
	}
	
	@Test
	void testPutException() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec-new.p12", "sypt-crypto-data-pass".toCharArray(), "BC");
				KSM target = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			KSM manager = spy(source);
			manager.close();
			
			Assertions.assertThrows(KSMException.class, () -> target.put("sypt-crypto-data-new", source));	
		}
	}
	
	@Test
	void testRemove() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec-new.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			Assertions.assertNotNull(source.getDecryptionKey("sypt-crypto-data-new"));
			Assertions.assertNotNull(source.getSigningKey("sypt-crypto-data-new"));
			
			source.remove("sypt-crypto-data-new");

			Assertions.assertNull(source.getDecryptionKey("sypt-crypto-data-new"));
			Assertions.assertNull(source.getSigningKey("sypt-crypto-data-new"));
		}
	}
	
	@Test
	void testRemoveException() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec-new.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			KSM manager = spy(source);
			manager.close();
			
			Assertions.assertThrows(KSMException.class, () -> source.remove("sypt-crypto-data-new"));
		}
	}
	
	@Test
	void testToBase64() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec-new.p12", "sypt-crypto-data-pass".toCharArray(), "BC");
				KSM target = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			String oldTarget = target.toBase64();
			
			try (KSM ksm = new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(target.toBase64())), "sypt-crypto-data-pass".toCharArray(), "BC")) {
				Assertions.assertThrows(KSMException.class, () -> ksm.getEncryptionType("sypt-crypto-data-new"));
				Assertions.assertThrows(KSMException.class, () -> ksm.getVerificationType("sypt-crypto-data-new"));
			}
			
			target.put("sypt-crypto-data-new", source);
			Assertions.assertNotEquals(oldTarget, target.toBase64());
			
			try (KSM ksm = new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(target.toBase64())), "sypt-crypto-data-pass".toCharArray(), "BC")) {
				KSMType encryptionType = ksm.getEncryptionType("sypt-crypto-data-new");
				KSMType verificationType = ksm.getVerificationType("sypt-crypto-data-new");
				
				Assertions.assertEquals(KSMType.EC_384, encryptionType);
				Assertions.assertEquals(KSMType.EC_384, verificationType);
			}
		}
	}
	
	private static Stream<Arguments> testGetNullDataKeystore() {
		return Stream.of(
			Arguments.of(IllegalStateException.class, null, "keystorePassword".toCharArray()),
			Arguments.of(IllegalArgumentException.class, new ByteArrayInputStream(new byte[1]), null)
		);
	}

}
