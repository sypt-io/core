package io.sypt.core.crypter;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.util.Base64;

import javax.crypto.KEM;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.sypt.core.AbstractSypter;
import io.sypt.core.crypter.cipher.AsymmetricPQCSypterCipher;
import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.crypter.factory.CrypterFactory;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.keystore.DataKSM;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMFactory;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.core.keystore.factory.entity.TestSypterable;
import io.sypt.core.keystore.factory.values.KSMValues;

class PQCCrypterTest {

	private static final String MASTER_ALIAS = "sypt-crypto-data";
	private static final String ALIAS = "test";
	private static final byte[] DATA = "{\"id\":\"pqc\",\"data\":\"sypt\"}".getBytes(StandardCharsets.UTF_8);

	/**
	 * Base64 secret key of 44 bytes wrapped by AES-KWP: 8 bytes AIV + 48 bytes padded
	 */
	private static final int WRAPPED_SECRET_KEY_LENGTH = 56;

	private static KSM masterKSM;
	private static KSM pqcL2KSM;

	@BeforeAll
	static void init() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSMValues values = KSMFactory.builder()
				.keyStoreManager(masterKSM, MASTER_ALIAS)
				.type(KSMType.PQC_L2)
				.alias(ALIAS)
				.domain("test.com")
				.encryptedPassword(false)
				.build();
		pqcL2KSM = new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(values.getKeyStore())), values.getPassword(), "BC");
	}

	/**
	 * Not passing the {@link KSM} directly: JUnit closes {@link AutoCloseable} arguments after each test
	 */
	private record PQCKeyStore(KSMType type, KSM ksm, String alias, int encapsulationLength) {
		
		Crypter<byte[], AsymmetricSypterObject> crypter() throws CrypterException {
			return CrypterFactory.getCrypter(type, ksm, alias);
		}
		
	}
	
	private static Arguments[] pqcKeyStores() {
		return new Arguments[] {
			Arguments.of(new PQCKeyStore(KSMType.PQC_L2, pqcL2KSM, ALIAS, 1088)),
			Arguments.of(new PQCKeyStore(KSMType.PQC_L5, masterKSM, MASTER_ALIAS, 1568))
		};
	}

	@ParameterizedTest
	@MethodSource("pqcKeyStores")
	void testRoundTrip(PQCKeyStore keyStore) throws Exception {
		Crypter<byte[], AsymmetricSypterObject> crypter = keyStore.crypter();
		AsymmetricSypterObject encrypted = crypter.encrypt(DATA);

		Assertions.assertEquals(keyStore.encapsulationLength() + WRAPPED_SECRET_KEY_LENGTH,
				Base64.getDecoder().decode(encrypted.getEncryptedSecretKey()).length);
		Assertions.assertArrayEquals(DATA, crypter.decrypt(encrypted));
	}

	@ParameterizedTest
	@MethodSource("pqcKeyStores")
	void testEncryptionIsRandomized(PQCKeyStore keyStore) throws Exception {
		Crypter<byte[], AsymmetricSypterObject> crypter = keyStore.crypter();

		Assertions.assertNotEquals(crypter.encrypt(DATA).getEncryptedSecretKey(), crypter.encrypt(DATA).getEncryptedSecretKey());
	}

	@ParameterizedTest
	@MethodSource("pqcKeyStores")
	void testTamperedWrappedSecretKey(PQCKeyStore keyStore) throws Exception {
		Crypter<byte[], AsymmetricSypterObject> crypter = keyStore.crypter();
		AsymmetricSypterObject encrypted = crypter.encrypt(DATA);

		byte[] secretKey = Base64.getDecoder().decode(encrypted.getEncryptedSecretKey());
		secretKey[secretKey.length - 1] ^= 0x01;
		encrypted.setEncryptedSecretKey(Base64.getEncoder().encodeToString(secretKey));

		Assertions.assertThrows(CrypterException.class, () -> crypter.decrypt(encrypted));
	}

	@ParameterizedTest
	@MethodSource("pqcKeyStores")
	void testTamperedEncapsulation(PQCKeyStore keyStore) throws Exception {
		Crypter<byte[], AsymmetricSypterObject> crypter = keyStore.crypter();
		AsymmetricSypterObject encrypted = crypter.encrypt(DATA);

		byte[] secretKey = Base64.getDecoder().decode(encrypted.getEncryptedSecretKey());
		secretKey[0] ^= 0x01;
		encrypted.setEncryptedSecretKey(Base64.getEncoder().encodeToString(secretKey));

		Assertions.assertThrows(CrypterException.class, () -> crypter.decrypt(encrypted));
	}

	@ParameterizedTest
	@MethodSource("pqcKeyStores")
	void testInvalidSecretKeyLength(PQCKeyStore keyStore) throws Exception {
		Crypter<byte[], AsymmetricSypterObject> crypter = keyStore.crypter();
		AsymmetricSypterObject encrypted = crypter.encrypt(DATA);
		encrypted.setEncryptedSecretKey(Base64.getEncoder().encodeToString(new byte[keyStore.encapsulationLength() - 1]));

		Assertions.assertThrows(CrypterException.class, () -> crypter.decrypt(encrypted));
	}

	@ParameterizedTest
	@MethodSource("pqcKeyStores")
	void testDecryptLegacyFormat(PQCKeyStore keyStore) throws Exception {
		// Legacy format: the ML-KEM shared secret is directly the AES-GCM key of the data
		KEM.Encapsulated encapsulated = KEM.getInstance(keyStore.type().encryptionSpec().keyPairGenerator(), "BC")
				.newEncapsulator(keyStore.ksm().getEncryptionKey(keyStore.alias()))
				.encapsulate();
		byte[] iv = new DefaultSypterGenerator().generateIv();

		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(Crypter.CIPHER_SYMMETRIC_ALGO_AES);
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(encapsulated.key().getEncoded(), "AES"), new GCMParameterSpec(128, iv));

		AsymmetricSypterObject legacy = new AsymmetricSypterObject(
				Base64.getEncoder().encodeToString(cipher.doFinal(DATA)),
				Base64.getEncoder().encodeToString(encapsulated.encapsulation()),
				Base64.getEncoder().encodeToString(iv));

		Assertions.assertArrayEquals(DATA, keyStore.crypter().decrypt(legacy));
	}

	@Test
	void testDecryptLegacyVector() throws Exception {
		String vector;
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("vectors/pqc-legacy-l5.txt")) {
			vector = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
		}

		TestSypterable sypterable = new LegacySypter().decodeAndUnsypt(vector, TestSypterable.class);

		Assertions.assertEquals("legacy-id", sypterable.getId());
		Assertions.assertEquals("legacy-data", sypterable.getData());
	}

	@Test
	void testNotPQCType() {
		Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> new AsymmetricPQCSypterCipher(KSMType.RSA_2048, masterKSM, MASTER_ALIAS));
		Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> new AsymmetricPQCSypterCipher(null, masterKSM, MASTER_ALIAS));
	}

	private static class LegacySypter extends AbstractSypter<TestSypterable> {

		LegacySypter() throws Exception {
			super(KSMType.PQC_L5, masterKSM, MASTER_ALIAS);
		}

		@Override
		protected boolean isEntityValid(TestSypterable obj) {
			return obj != null;
		}

	}

}
