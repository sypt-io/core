package io.sypt.core;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.sypt.core.entity.Syptered;
import io.sypt.core.exception.SypterException;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.entity.TestSypterable;

class SypteredVersionTest {

	@BeforeAll
	static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * KeyStore type and its {@link Syptered#VERSION_1} vector, generated before the version existed
	 */
	private static Stream<Arguments> keyStores() {
		return Stream.of(
			Arguments.of("ec", "vectors/syptered-v1-ec.txt"),
			Arguments.of("rsa", "vectors/syptered-v1-rsa.txt"),
			Arguments.of("pqc", "vectors/pqc-legacy-l5.txt")
		);
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testSyptCurrentVersion(String type, String vector) throws Exception {
		try (KSM ksm = ksm(type)) {
			TestSypter sypter = new TestSypter(ksm);

			Assertions.assertEquals(Syptered.CURRENT_VERSION, sypter.sypt(new TestSypterable("id", "data")).getVersion());

			String encoded = sypter.syptAndEncode(new TestSypterable("id", "data"));
			Assertions.assertTrue(decode(encoded).contains("\"version\":" + Syptered.CURRENT_VERSION));
			Assertions.assertEquals("data", sypter.decodeAndUnsypt(encoded, TestSypterable.class).getData());
		}
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testUnsyptVersion1(String type, String vector) throws Exception {
		try (KSM ksm = ksm(type)) {
			TestSypterable unsypt = new TestSypter(ksm).decodeAndUnsypt(read(vector), TestSypterable.class);

			Assertions.assertEquals("legacy-id", unsypt.getId());
			Assertions.assertEquals("legacy-data", unsypt.getData());
		}
	}

	/**
	 * {@link Syptered#VERSION_2} vectors generated with Jackson 3 (sypt-core): also read by sypt-core-jackson-2
	 */
	@ParameterizedTest
	@MethodSource("keyStores")
	void testUnsyptVersion2(String type, String vector) throws Exception {
		try (KSM ksm = ksm(type)) {
			TestSypterable unsypt = new TestSypter(ksm).decodeAndUnsypt(read("vectors/syptered-v2-" + type + ".txt"), TestSypterable.class);
			
			Assertions.assertEquals("v2-id", unsypt.getId());
			Assertions.assertEquals("v2-data", unsypt.getData());
		}
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testVersion1UpgradedToVersion2Fails(String type, String vector) throws Exception {
		try (KSM ksm = ksm(type)) {
			String upgraded = encode(decode(read(vector)).replaceFirst("\\{", "{\"version\":2,"));

			Assertions.assertThrows(SypterException.class, () -> new TestSypter(ksm).decodeAndUnsypt(upgraded, TestSypterable.class));
		}
	}

	@ParameterizedTest
	@MethodSource("keyStores")
	void testTamperedVersion2Fails(String type, String vector) throws Exception {
		try (KSM ksm = ksm(type)) {
			TestSypter sypter = new TestSypter(ksm);
			Syptered s = sypter.sypt(new TestSypterable("id", "data"));

			Syptered[] tampered = {
				new Syptered(Syptered.VERSION_1, s.getKey(), s.getEncAlgo(), s.getSigAlgo(), s.getObject(), s.getSignature(), s.getTimestamp()),
				new Syptered(3, s.getKey(), s.getEncAlgo(), s.getSigAlgo(), s.getObject(), s.getSignature(), s.getTimestamp()),
				new Syptered(s.getVersion(), "other", s.getEncAlgo(), s.getSigAlgo(), s.getObject(), s.getSignature(), s.getTimestamp()),
				new Syptered(s.getVersion(), s.getKey(), "other", s.getSigAlgo(), s.getObject(), s.getSignature(), s.getTimestamp()),
				new Syptered(s.getVersion(), s.getKey(), s.getEncAlgo(), "other", s.getObject(), s.getSignature(), s.getTimestamp()),
				new Syptered(s.getVersion(), s.getKey(), s.getEncAlgo(), s.getSigAlgo(), s.getObject(), s.getSignature(), s.getTimestamp() + 1)
			};

			Assertions.assertEquals("data", sypter.unsypt(s, TestSypterable.class).getData());
			for (Syptered t : tampered) {
				Assertions.assertThrows(SypterException.class, () -> sypter.unsypt(t, TestSypterable.class));
			}
		}
	}

	private static KSM ksm(String type) {
		return new FileKSM("classpath:keystore/sypt-crypto-data-" + type + ".p12", "sypt-crypto-data-pass".toCharArray(), "BC");
	}

	private static String read(String vector) throws Exception {
		try (InputStream is = SypteredVersionTest.class.getClassLoader().getResourceAsStream(vector)) {
			return new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
		}
	}

	private static String decode(String value) {
		return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
	}

	private static String encode(String value) {
		return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
	}

	private static class TestSypter extends AbstractSypter<TestSypterable> {

		TestSypter(KSM ksm) throws Exception {
			super(ksm, "sypt-crypto-data");
		}

		@Override
		protected boolean isEntityValid(TestSypterable obj) {
			return obj != null;
		}

	}

}
