package io.sypt.core.generator;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.stream.Collectors;

import javax.crypto.KeyGenerator;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;

import io.sypt.core.generator.entity.SypterValues;
import io.sypt.core.keystore.KSM;

public final class DefaultSypterGenerator implements SypterGenerator {
	
	private static final String CHARSET = "ABCDEFGHJKMNPQRSTVWXYZ23456789";
	private static final SecureRandom RANDOM_CHARSET = new SecureRandom();
	
	private final Random rand;
	private String provider;
	
	public DefaultSypterGenerator() { 
		try {
			this.rand = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	public DefaultSypterGenerator(String provider) { 
		try {
			this.rand = SecureRandom.getInstanceStrong();
			this.provider = provider;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	@Override
	public SypterValues generateValues() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		return new SypterValues(generateSecretKey(), generateIv());
	}

	@Override
	public Key generateSecretKey() throws NoSuchProviderException, NoSuchAlgorithmException {
		KeyGenerator keyGenerator = StringUtils.isBlank(provider) ? KeyGenerator.getInstance(KSM.AES) : KeyGenerator.getInstance(KSM.AES, provider);
	    keyGenerator.init(256);
	    
	    return keyGenerator.generateKey();
	}
	
	@Override
	public String generateId(String prefix, int length) {
		String r = RandomStringUtils.secureStrong().nextAlphanumeric(length);
		return prefix + r;
	}
	
	@Override
	public String generateUserCode(String prefix, int length) {
		return prefix + "-" + generateRandomString(length) + "-" + generateRandomString(length);
	}
	
	@Override
	public byte[] generateIv() {
		return generateRandomBytes(12);
	}
	
	private byte[] generateRandomBytes(int length) {
		byte[] bytes = new byte[length];
		rand.nextBytes(bytes);
		
		return bytes;
	}
	
	private String generateRandomString(int length) {
		return RANDOM_CHARSET.ints(length, 0, CHARSET.length())
			.mapToObj(i -> String.valueOf(CHARSET.charAt(i)))
			.collect(Collectors.joining());
    }

}
