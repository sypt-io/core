package io.sypt.core.entity;

public class SymmetricSypterObject {

	private String encryptedData;
	private String secretKey;
	private String iv;

	public SymmetricSypterObject() {
		this("", "", "");
	}

	public SymmetricSypterObject(String encryptedData, String secretKey, String iv) {
		this.encryptedData = encryptedData;
		this.secretKey = secretKey;
		this.iv = iv;
	}

	public String getEncryptedData() {
		return encryptedData;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

}
