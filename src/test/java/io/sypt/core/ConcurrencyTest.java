package io.sypt.core;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.sypt.core.crypter.cipher.SymmetricSypterCipher;
import io.sypt.core.entity.SymmetricSypterObject;
import io.sypt.core.entity.Syptered;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.entity.TestSypterable;

/**
 * Sypters and ciphers are meant to be shared (singletons, application scoped beans): they must be thread-safe
 */
class ConcurrencyTest {

	private static final int THREADS = 16;

	@BeforeAll
	static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void testSharedSymmetricCipher() throws Exception {
		SymmetricSypterCipher cipher = new SymmetricSypterCipher("BC");

		runConcurrently(200, (thread, i) -> {
			byte[] data = ("data-" + thread + "-" + i).getBytes(StandardCharsets.UTF_8);
			SymmetricSypterObject encrypted = cipher.encrypt(data);
			Assertions.assertArrayEquals(data, cipher.decrypt(encrypted));
		});
	}

	@ParameterizedTest
	@ValueSource(strings = { "rsa", "ec", "pqc" })
	void testSharedSypter(String type) throws Exception {
		try (KSM ksm = new FileKSM("classpath:keystore/sypt-crypto-data-" + type + ".p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
			Sypter<TestSypterable> sypter = new SharedSypter(ksm);

			runConcurrently(20, (thread, i) -> {
				String id = "id-" + thread + "-" + i;
				Syptered syptered = sypter.sypt(new TestSypterable(id, "data-" + id));
				TestSypterable unsypt = sypter.unsypt(syptered, TestSypterable.class);

				Assertions.assertEquals(id, unsypt.getId());
				Assertions.assertEquals("data-" + id, unsypt.getData());
			});
		}
	}

	@FunctionalInterface
	private interface Operation {

		void run(int thread, int iteration) throws Exception;

	}

	/**
	 * Run the operation from all threads at the same time and fail on the first error
	 */
	private static void runConcurrently(int iterations, Operation operation) throws Exception {
		ExecutorService executor = Executors.newFixedThreadPool(THREADS);
		CountDownLatch start = new CountDownLatch(1);

		try {
			List<Future<Void>> futures = new ArrayList<>();
			for (int t = 0; t < THREADS; t++) {
				int thread = t;
				futures.add(executor.submit(() -> {
					start.await();
					for (int i = 0; i < iterations; i++) {
						operation.run(thread, i);
					}
					return null;
				}));
			}

			start.countDown();
			for (Future<Void> future : futures) {
				future.get(2, TimeUnit.MINUTES);
			}
		} finally {
			executor.shutdownNow();
		}
	}

	private static class SharedSypter extends AbstractSypter<TestSypterable> {

		SharedSypter(KSM ksm) throws Exception {
			super(ksm, "sypt-crypto-data");
		}

		@Override
		protected boolean isEntityValid(TestSypterable obj) {
			return obj != null;
		}

	}

}
