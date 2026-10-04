package io.sypt.core.entity;

public class Syptered {

	private String key;
	private String encAlgo;
	private String sigAlgo;
	private String object;
	private String signature;
	private long timestamp;

	public Syptered() {
		this("", "", "", "", "", 0L);
	}

	public Syptered(String key, String encAlgo, String sigAlgo, String object, String signature, long timestamp) {
		this.key = key;
		this.encAlgo = encAlgo;
		this.sigAlgo = sigAlgo;
		this.object = object;
		this.signature = signature;
		this.timestamp = timestamp;
	}
	
	public String getKey() {
		return key;
	}
	
	public String getEncAlgo() {
		return encAlgo;
	}
	
	public String getSigAlgo() {
		return sigAlgo;
	}

	public String getObject() {
		return object;
	}

	public String getSignature() {
		return signature;
	}
	
	public long getTimestamp() {
		return timestamp;
	}

}
