package io.sypt.core.entity;

public class AsymmetricSypterObject {

	private String encryptedData;
	private String encryptedSecretKey;
	private String iv;

	public AsymmetricSypterObject() {
		this("", "", "");
	}

	public AsymmetricSypterObject(String encryptedData, String encryptedSecretKey, String iv) {
		this.encryptedData = encryptedData;
		this.encryptedSecretKey = encryptedSecretKey;
		this.iv = iv;
	}

	public String getEncryptedData() {
		return encryptedData;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	public String getEncryptedSecretKey() {
		return encryptedSecretKey;
	}

	public void setEncryptedSecretKey(String encryptedSecretKey) {
		this.encryptedSecretKey = encryptedSecretKey;
	}

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

}
