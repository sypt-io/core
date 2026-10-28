package io.sypt.core.keystore;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.util.Base64;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.sypt.core.keystore.exception.KSMException;

/**
 * Exporting a {@link KSM} must not change it
 */
class KSMExportTest {

	private static final String ALIAS = "sypt-crypto-data";
	private static final char[] PASSWORD = "sypt-crypto-data-pass".toCharArray();
	private static final char[] NEW_PASSWORD = "new-password".toCharArray();

	@BeforeAll
	static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * KeyStores loaded with BouncyCastle and with the default JDK provider (null)
	 */
	private static Stream<Arguments> keyStores() {
		return Stream.of("ec", "rsa", "pqc").flatMap(type -> Stream.of(
			Arguments.of("classpath:keystore/sypt-crypto-data-" + type + ".p12", "BC"),
			Arguments.of("classpath:keystore/sypt-crypto-data-" + type + ".p12", null)
		));
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testExportWithNewPasswordKeepsKsmUnchanged(String path, String provider) throws Exception {
		try (KSM ksm = new FileKSM(path, PASSWORD, provider)) {
			ksm.toBase64(NEW_PASSWORD);

			Assertions.assertNotNull(ksm.getSigningKey(ALIAS));
			Assertions.assertNotNull(ksm.getDecryptionKey(ALIAS));
			assertSameKeys(ksm, ksm.toBase64(), PASSWORD, provider);
		}
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testExportWithNewPasswordProtectsKeys(String path, String provider) throws Exception {
		try (KSM ksm = new FileKSM(path, PASSWORD, provider)) {
			String exported = ksm.toBase64(NEW_PASSWORD);

			assertSameKeys(ksm, exported, NEW_PASSWORD, provider);
			Assertions.assertThrows(IllegalStateException.class, // NOSONAR
					() -> new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(exported)), PASSWORD, provider));
		}
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testExportWithCurrentPassword(String path, String provider) throws Exception {
		try (KSM ksm = new FileKSM(path, PASSWORD, provider)) {
			assertSameKeys(ksm, ksm.toBase64(), PASSWORD, provider);
		}
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testExportWithoutPasswordKeepsKsmUnchanged(String path, String provider) throws Exception {
		try (KSM ksm = new FileKSM(path, PASSWORD, provider)) {
			Assertions.assertThrows(KSMException.class, () -> ksm.toBase64(null));

			Assertions.assertNotNull(ksm.getSigningKey(ALIAS));
			assertSameKeys(ksm, ksm.toBase64(), PASSWORD, provider);
		}
	}

	private static void assertSameKeys(KSM expected, String exported, char[] password, String provider) throws Exception {
		try (KSM actual = new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(exported)), password, provider)) {
			Assertions.assertArrayEquals(expected.getSigningKey(ALIAS).getEncoded(), actual.getSigningKey(ALIAS).getEncoded());
			Assertions.assertArrayEquals(expected.getDecryptionKey(ALIAS).getEncoded(), actual.getDecryptionKey(ALIAS).getEncoded());
			Assertions.assertArrayEquals(expected.getVerificationCertificate(ALIAS).getEncoded(), actual.getVerificationCertificate(ALIAS).getEncoded());
			Assertions.assertArrayEquals(expected.getEncryptionCertificate(ALIAS).getEncoded(), actual.getEncryptionCertificate(ALIAS).getEncoded());
		}
	}

}
