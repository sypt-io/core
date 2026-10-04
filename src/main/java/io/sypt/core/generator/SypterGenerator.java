package io.sypt.core.generator;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import io.sypt.core.generator.entity.SypterValues;

public interface SypterGenerator {
	
	public SypterValues generateValues() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException;
	
	public Key generateSecretKey() throws NoSuchProviderException, NoSuchAlgorithmException;
	
	public String generateId(String prefix, int lenth);
	
	public String generateUserCode(String prefix, int lenth);
	
	public byte[] generateIv();

}