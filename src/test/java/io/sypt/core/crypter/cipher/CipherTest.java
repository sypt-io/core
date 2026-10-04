package io.sypt.core.crypter.cipher;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.entity.SymmetricSypterObject;

class CipherTest {
	
	@Test
	void symmetricCipherEncryptNoCipher() {
		SymmetricSypterCipher cipher = new SymmetricSypterCipher((javax.crypto.Cipher) null, "BC");
		Assertions.assertThrows(CrypterException.class, () -> cipher.encrypt(new byte[0]));
	}
	
	@Test
	void symmetricCipherDecryptNoCipher() {
		SymmetricSypterCipher cipher = new SymmetricSypterCipher((javax.crypto.Cipher) null, "BC");
		Assertions.assertThrows(CrypterException.class, () -> cipher.decrypt(new SymmetricSypterObject()));
	}
	
	@Test
	void ecAsymmetricCipherEncryptNoCipher() {
		AsymmetricEcSypterCipher cipher = new AsymmetricEcSypterCipher(null, "", (javax.crypto.Cipher) null);
		Assertions.assertThrows(CrypterException.class, () -> cipher.encrypt(new SymmetricSypterObject()));
	}
	
	@Test
	void ecAsymmetricCipherDecryptNoCipher() {
		AsymmetricEcSypterCipher cipher = new AsymmetricEcSypterCipher(null, "", (javax.crypto.Cipher) null);
		Assertions.assertThrows(CrypterException.class, () -> cipher.decrypt(new AsymmetricSypterObject()));
	}
	
	@Test
	void rsaAsymmetricCipherEncryptNoCipher() {
		AsymmetricRsaSypterCipher cipher = new AsymmetricRsaSypterCipher(null, "", (javax.crypto.Cipher) null);
		Assertions.assertThrows(CrypterException.class, () -> cipher.encrypt(new SymmetricSypterObject()));
	}
	
	@Test
	void rsaAsymmetricCipherDecryptNoCipher() {
		AsymmetricRsaSypterCipher cipher = new AsymmetricRsaSypterCipher(null, "", (javax.crypto.Cipher) null);
		Assertions.assertThrows(CrypterException.class, () -> cipher.decrypt(new AsymmetricSypterObject()));
	}

}
