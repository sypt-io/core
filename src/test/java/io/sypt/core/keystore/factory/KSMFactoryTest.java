package io.sypt.core.keystore.factory;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.entity.Syptered;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.generator.SypterGenerator;
import io.sypt.core.keystore.DataKSM;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMFactory.Usage;
import io.sypt.core.keystore.factory.entity.TestSypterable;
import io.sypt.core.keystore.factory.values.KSMValues;
import io.sypt.core.keystore.sypter.KeyStoreSypter;
import io.sypt.core.keystore.sypter.entity.KeyStoreSypterable;

class KSMFactoryTest {
	
	private final SypterGenerator gen = new DefaultSypterGenerator();
	
	private static final String ALIAS = "test";
	private static final String DOMAIN = "test.com";
	
	public KSMFactoryTest() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void testRsa() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.RSA_2048, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testRsa_4096() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.RSA_4096, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_4096, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_4096, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testRsaMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.RSA_2048, Usage.MTLS));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedRsa() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.RSA_2048, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedRsaMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.RSA_2048, Usage.MTLS));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.RSA_2048, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testEc() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.EC_256, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testEc_384() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.EC_384, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_384, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_384, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testEcMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.EC_256, Usage.MTLS));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedEc() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.EC_256, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedEcMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.EC_256, Usage.MTLS));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.EC_256, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testPQC() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.PQC_L2, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testPQC_L5() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.PQC_L5, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L5, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L5, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testPQCMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.PQC_L2, Usage.MTLS));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedPQC() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.PQC_L2, Usage.SYPT));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotNull()
			.containsExactlyInAnyOrder(List.of(2, "test.com"));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedPQCMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKSM = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC");

		KSM ksm = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKSM, "sypt-crypto-data", KSMType.PQC_L2, Usage.MTLS));
		Assertions.assertNotEquals(masterKSM.getSigningKey("sypt-crypto-data").getEncoded(), ksm.getSigningKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationKey("sypt-crypto-data").getEncoded(), ksm.getVerificationKey(ALIAS).getEncoded());
		Assertions.assertNotEquals(masterKSM.getVerificationCertificate("sypt-crypto-data").getEncoded(), ksm.getVerificationCertificate(ALIAS).getEncoded());
		
		Assertions.assertDoesNotThrow(() -> ksm.getVerificationCertificate(ALIAS).verify(masterKSM.getVerificationKey("sypt-crypto-data")));
		
		X509Certificate certificate = (X509Certificate) ksm.getVerificationCertificate(ALIAS);
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(KSMType.PQC_L2, ksm).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	private KSM obtainKeyStoreManager(
		KSM masterKSM,
		String masterAlias,
		KSMType type,
		Usage usage
	) throws Exception {
		KSMValues keyStoreValues = KSMFactory.builder()
				.keyStoreManager(masterKSM, masterAlias)
				.type(type)
				.alias(ALIAS)
				.domain(DOMAIN)
				.usage(usage)
				.build();
		
		Assertions.assertEquals(type, keyStoreValues.getType());

		KeyStoreSypterable passwordSypterable = new KeyStoreSypter(masterKSM, masterAlias).decodeAndUnsypt(
				String.valueOf(keyStoreValues.getPassword()),
				KeyStoreSypterable.class);

		return new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(keyStoreValues.getKeyStore())),
				passwordSypterable.getPassword(),
				"BC");
	}

	private KSM obtainDecryptedKeyStoreManager(
		KSM masterKSM,
		String masterAlias,
		KSMType type,
		Usage usage
	) throws Exception {
		KSMValues keyStoreValues = KSMFactory.builder()
				.keyStoreManager(masterKSM, masterAlias)
				.type(type)
				.alias(ALIAS)
				.domain(DOMAIN)
				.usage(usage)
				.encryptedPassword(false)
				.build();

		return new DataKSM(new ByteArrayInputStream(Base64.getDecoder().decode(keyStoreValues.getKeyStore())),
				keyStoreValues.getPassword(),
				"BC");
	}

}
