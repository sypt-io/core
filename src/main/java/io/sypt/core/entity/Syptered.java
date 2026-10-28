package io.sypt.core.entity;

public class Syptered {

	/**
	 * Format without version (absent from the JSON): the signature covers the object, the key and the timestamp
	 */
	public static final int VERSION_1 = 1;

	/**
	 * Format where the signature also covers the version and the algorithms
	 */
	public static final int VERSION_2 = 2;

	/**
	 * Format used to sypt
	 */
	public static final int CURRENT_VERSION = VERSION_2;

	private int version;
	private String key;
	private String encAlgo;
	private String sigAlgo;
	private String object;
	private String signature;
	private long timestamp;

	public Syptered() {
		this(VERSION_1, "", "", "", "", "", 0L);
	}

	/**
	 * Construct a {@link Syptered} in {@link #VERSION_1}
	 */
	public Syptered(String key, String encAlgo, String sigAlgo, String object, String signature, long timestamp) {
		this(VERSION_1, key, encAlgo, sigAlgo, object, signature, timestamp);
	}

	public Syptered(int version, String key, String encAlgo, String sigAlgo, String object, String signature, long timestamp) {
		this.version = version;
		this.key = key;
		this.encAlgo = encAlgo;
		this.sigAlgo = sigAlgo;
		this.object = object;
		this.signature = signature;
		this.timestamp = timestamp;
	}
	
	public int getVersion() {
		return version;
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
