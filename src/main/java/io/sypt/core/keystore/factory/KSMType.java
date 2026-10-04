package io.sypt.core.keystore.factory;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.KSMProperties;

public enum KSMType {

	// --- Algorithmes Classiques ---
	EC_256(
		new KeySpec(KSM.EC, KSM.SHA256_WITH_ECDSA, null, new ECGenParameterSpec("secp256r1"), true),
		new KeySpec(KSM.EC, null, Crypter.CIPHER_ASYMMETRIC_ALGO_EC, new ECGenParameterSpec("secp256r1"), false)
	),
	EC_384(
		new KeySpec(KSM.EC, KSM.SHA384_WITH_ECDSA, null, new ECGenParameterSpec("secp384r1"), true),
		new KeySpec(KSM.EC, null, Crypter.CIPHER_ASYMMETRIC_ALGO_EC, new ECGenParameterSpec("secp384r1"), false)
	),
	RSA_2048(
		new KeySpec(KSM.RSA, KSM.SHA256_WITH_RSA, null, new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(0x10001)), true),
		new KeySpec(KSM.RSA, null, Crypter.CIPHER_ASYMMETRIC_ALGO_RSA, new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(0x10001)), false)
	),
	RSA_4096(
		new KeySpec(KSM.RSA, KSM.SHA512_WITH_RSA, null, new RSAKeyGenParameterSpec(4096, BigInteger.valueOf(0x10001)), true),
		new KeySpec(KSM.RSA, null, Crypter.CIPHER_ASYMMETRIC_ALGO_RSA, new RSAKeyGenParameterSpec(4096, BigInteger.valueOf(0x10001)), false)
	),

	// --- Algorithmes Post-Quantiques (PQC NIST FIPS 203 & 204) ---
	PQC_L2(
		new KeySpec(KSM.ML_DSA_65, KSM.ML_DSA_65, null, null, true),
		new KeySpec(KSM.ML_KEM_768, null, KSM.ML_KEM_768, null, false)
	),
	PQC_L5(
		new KeySpec(KSM.ML_DSA_87, KSM.ML_DSA_87, null, null, true),
		new KeySpec(KSM.ML_KEM_1024, null, KSM.ML_KEM_1024, null, false)
	);

	/**
	 * Définition d'une sous-clé (Signature ou Chiffrement/KEM)
	 */
	public record KeySpec(
		String keyPairGenerator,
		String contentSigner,
		String contentCrypter,
		AlgorithmParameterSpec params,
		boolean canSign
	) {}

	private final KeySpec signatureSpec;
	private final KeySpec encryptionSpec;

	private KSMType(KeySpec signatureSpec, KeySpec encryptionSpec) {
		this.signatureSpec = signatureSpec;
		this.encryptionSpec = encryptionSpec;
	}

	public KeySpec signatureSpec() {
		return signatureSpec;
	}

	public KeySpec encryptionSpec() {
		return encryptionSpec;
	}

	public static KSMType fromPublicKey(PublicKey key) {
	    if (key == null) {
	    	return null;
	    }

	    String alg = key.getAlgorithm().toUpperCase();
	    if (alg.contains("RSA")) {
	        return KSMProperties.getRsaType(); 
	    }
	    if (alg.contains("EC")) {
	        return KSMProperties.getEcType();
	    }
	    if (alg.contains("ML-DSA") || alg.contains("ML-KEM")) {
	        return KSMProperties.getPQCType();
	    }

	    return null;
	}
}