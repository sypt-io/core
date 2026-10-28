package io.sypt.core.keystore.factory;

import java.io.ByteArrayInputStream;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import io.sypt.core.AbstractSypter;
import io.sypt.core.entity.Syptered;
import io.sypt.core.keystore.DataKSM;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.entity.TestSypterable;
import io.sypt.core.keystore.factory.values.KSMValues;

class KSMTypeTest {

	private static final String BC = "BC";

	/**
	 * Default JDK providers (SunRsaSign, SunEC, SunJCE)
	 */
	private static final String JDK = "";

	@BeforeAll
	static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static Stream<Arguments> keys() {
		return Stream.of(BC, JDK).flatMap(provider -> Stream.of(
			Arguments.of(provider, "RSA", 2048, KSMType.RSA_2048),
			Arguments.of(provider, "RSA", 3072, KSMType.RSA_2048),
			Arguments.of(provider, "RSA", 4096, KSMType.RSA_4096),
			Arguments.of(provider, "EC", "secp256r1", KSMType.EC_256),
			Arguments.of(provider, "EC", "secp384r1", KSMType.EC_384),
			Arguments.of(provider, "EC", "secp521r1", KSMType.EC_384),
			Arguments.of(provider, "ML-DSA-65", null, KSMType.PQC_L2),
			Arguments.of(provider, "ML-KEM-768", null, KSMType.PQC_L2),
			Arguments.of(provider, "ML-DSA-87", null, KSMType.PQC_L5),
			Arguments.of(provider, "ML-KEM-1024", null, KSMType.PQC_L5)
		));
	}

	@ParameterizedTest
	@MethodSource("keys")
	void testFromPublicKey(String provider, String algorithm, Object params, KSMType expected) throws Exception {
		Assertions.assertEquals(expected, KSMType.fromPublicKey(generate(provider, algorithm, params)));
	}

	private static Stream<Arguments> unsupportedKeys() {
		return Stream.of(BC, JDK).flatMap(provider -> Stream.of(
			Arguments.of(provider, "RSA", 1024),
			Arguments.of(provider, "ML-DSA-44", null),
			Arguments.of(provider, "ML-KEM-512", null)
		));
	}

	@ParameterizedTest
	@MethodSource("unsupportedKeys")
	void testFromPublicKeyUnsupported(String provider, String algorithm, Object params) throws Exception {
		Assertions.assertNull(KSMType.fromPublicKey(generate(provider, algorithm, params)));
	}

	@Test
	void testFromPublicKeyNull() {
		Assertions.assertNull(KSMType.fromPublicKey(null));
	}

	/**
	 * A generated KeyStore must be usable without giving its type explicitly
	 */
	@ParameterizedTest
	@EnumSource(KSMType.class)
	void testAutoDetectedKeyStore(KSMType type) throws Exception {
		try (KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), BC)) {
			KSMValues values = KSMFactory.builder()
					.keyStoreManager(masterKSM, "sypt-crypto-data")
					.type(type)
					.alias("test")
					.domain("test.com")
					.encryptedPassword(false)
					.build();

			try (KSM ksm = new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(values.getKeyStore())), values.getPassword(), BC)) {
				Assertions.assertEquals(type, ksm.getVerificationType("test"));
				Assertions.assertEquals(type, ksm.getEncryptionType("test"));

				AutoDetectedSypter sypter = new AutoDetectedSypter(ksm);
				Syptered syptered = sypter.sypt(new TestSypterable("id", "data"));

				Assertions.assertEquals("data", sypter.unsypt(syptered, TestSypterable.class).getData());
			}
		}
	}

	private static PublicKey generate(String provider, String algorithm, Object params) throws Exception {
		KeyPairGenerator generator = provider.isEmpty() ? KeyPairGenerator.getInstance(algorithm) : KeyPairGenerator.getInstance(algorithm, provider);
		if (params instanceof Integer size) {
			generator.initialize(size);
		} else if (params instanceof String curve) {
			generator.initialize(new ECGenParameterSpec(curve));
		}

		return generator.generateKeyPair().getPublic();
	}

	private static class AutoDetectedSypter extends AbstractSypter<TestSypterable> {

		AutoDetectedSypter(KSM ksm) throws Exception {
			super(ksm, "test");
		}

		@Override
		protected boolean isEntityValid(TestSypterable obj) {
			return obj != null;
		}

	}

}
