package io.sypt.core.keystore.factory.values;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KSMValuesDataTest {
	
	@Test
	void toStringEquals() {
		KSMValuesData v1 = new KSMValuesData("aa", "bb", "ab".toCharArray());
		KSMValuesData v2 = new KSMValuesData("aa", "bb", "ba".toCharArray());
		Assertions.assertEquals(v1, v1);
		Assertions.assertEquals(v1, v2);
		Assertions.assertEquals(v1.toString(), v2.toString());
		Assertions.assertEquals(v1.hashCode(), v2.hashCode());
	}
	
	@Test
	void toStringNotEquals() {
		KSMValuesData v1 = new KSMValuesData("aa", "bb", "ab".toCharArray());
		KSMValuesData v2 = new KSMValuesData("aa", "cc", "ba".toCharArray());
		Assertions.assertNotEquals(v1, v2);
		Assertions.assertNotEquals(v1.toString(), v2.toString());
		Assertions.assertNotEquals(v1.hashCode(), v2.hashCode());
		
		v1 = new KSMValuesData("aa", "bb", "ab".toCharArray());
		v2 = new KSMValuesData("bb", "bb", "ba".toCharArray());
		Assertions.assertNotEquals(v1, v2);
		Assertions.assertNotEquals(v1.toString(), v2.toString());
		Assertions.assertNotEquals(v1.hashCode(), v2.hashCode());
	}
	
	@Test
	void toStringNotEqualsNull() {
		KSMValuesData v1 = new KSMValuesData("aa", "bb", "ab".toCharArray());
		Assertions.assertNotEquals(null, v1);
		Assertions.assertNotEquals(v1, new Object());
	}
	
	@Test
	void toStringNotEqualsNullValue() {
		KSMValuesData v1 = new KSMValuesData("aa", "bb", "ab".toCharArray());
		KSMValuesData v2 = new KSMValuesData(null, "cc", "ba".toCharArray());
		Assertions.assertNotEquals(v1, v2);
		Assertions.assertNotEquals(v1.toString(), v2.toString());
		Assertions.assertNotEquals(v1.hashCode(), v2.hashCode());

		v1 = new KSMValuesData("aa", "bb", "ab".toCharArray());
		v2 = new KSMValuesData("aa", null, "ba".toCharArray());
		Assertions.assertNotEquals(v1, v2);
		Assertions.assertNotEquals(v1.toString(), v2.toString());
		Assertions.assertNotEquals(v1.hashCode(), v2.hashCode());
	}

}
