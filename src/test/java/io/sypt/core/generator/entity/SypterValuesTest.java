package io.sypt.core.generator.entity;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.generator.DefaultSypterGenerator;

class SypterValuesTest {
	
	public SypterValuesTest() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	void testObject() throws Exception {
		DefaultSypterGenerator g = new DefaultSypterGenerator();
		SypterValues v1 = g.generateValues();
		SypterValues v2 = g.generateValues();
		
		Assertions.assertNotNull(v1);
		Assertions.assertNotNull(v2);
		Assertions.assertNotEquals(v1, v2);
		Assertions.assertNotEquals(v1, new SypterValues(v1.key(), v2.iv()));
		Assertions.assertNotEquals(v1, new SypterValues(v2.key(), v1.iv()));
		Assertions.assertNotEquals(v1.hashCode(), v2.hashCode());
		Assertions.assertEquals(v1, new SypterValues(v1.key(), v1.iv()));
		Assertions.assertEquals(v1.toString(), v2.toString());
	}

}
