package io.sypt.core.generator;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.generator.entity.SypterValues;

class DefaultSypterGeneratorTest {
	
	@Test
	void generateValues_ShouldWork() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		SypterGenerator gen = new DefaultSypterGenerator();
		SypterValues values = gen.generateValues();
		
		Assertions.assertNotNull(values);
		Assertions.assertNotNull(values.encodedIv());
		Assertions.assertNotNull(values.key());
	}
	
	@Test
	void generateSecretKey_ShouldWork() throws NoSuchProviderException, NoSuchAlgorithmException {
		SypterGenerator gen = new DefaultSypterGenerator();
		Key key = gen.generateSecretKey();
		
		Assertions.assertNotNull(key);
	}
	
	@Test
	void generateId_ShouldWork() {
		SypterGenerator gen = new DefaultSypterGenerator();
		String id = gen.generateId("SYPT", 4);
		
		Assertions.assertEquals(8, id.length());
	}
	
	@Test
	void generateIv_ShouldWork() {
		SypterGenerator gen = new DefaultSypterGenerator();
		byte[] iv = gen.generateIv();
		
		Assertions.assertEquals(12, iv.length);
	}
	
	@Test
	void generateUserCode_ShouldWork() {
		SypterGenerator gen = new DefaultSypterGenerator();
		String userCode = gen.generateUserCode("SYPT", 4);
		
		Assertions.assertEquals(14, userCode.length());
	}

}
