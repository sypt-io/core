package io.sypt.core.keystore.factory;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.keystore.KSM;

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

	/**
	 * Detect the {@link KSMType} from the real size / level of the key, whatever its provider
	 * <ul>
	 * <li>RSA: a modulus of 4096 bits or more gives <code>RSA_4096</code>, of 2048 bits or more <code>RSA_2048</code></li>
	 * <li>EC: a curve of more than 256 bits gives <code>EC_384</code>, of 256 bits <code>EC_256</code></li>
	 * <li>PQC: ML-DSA-87 / ML-KEM-1024 give <code>PQC_L5</code>, ML-DSA-65 / ML-KEM-768 <code>PQC_L2</code></li>
	 * </ul>
	 * @param key The public key
	 * @return The detected {@link KSMType}, or null if the key is not supported (unknown algorithm, too small key)
	 */
	public static KSMType fromPublicKey(PublicKey key) {
		return switch (key) {
			case null -> null;
			case RSAKey rsa -> fromRsaKeySize(rsa.getModulus().bitLength());
			case ECKey ec -> fromEcFieldSize(ec.getParams().getCurve().getField().getFieldSize());
			default -> fromAlgorithmIdentifier(key);
		};
	}

	private static KSMType fromRsaKeySize(int bits) {
		if (bits >= 4096) {
			return RSA_4096;
		}

		return (bits >= 2048) ? RSA_2048 : null;
	}

	private static KSMType fromEcFieldSize(int bits) {
		if (bits > 256) {
			return EC_384;
		}

		return (bits == 256) ? EC_256 : null;
	}

	/**
	 * ML-DSA / ML-KEM parameter sets are given by the algorithm OID of the encoded key (SubjectPublicKeyInfo)
	 */
	private static KSMType fromAlgorithmIdentifier(PublicKey key) {
		byte[] encoded = key.getEncoded();
		if (encoded == null) {
			return null;
		}

		try {
			ASN1ObjectIdentifier oid = SubjectPublicKeyInfo.getInstance(encoded).getAlgorithm().getAlgorithm();
			return PQC_TYPES.get(oid);
		} catch (IllegalArgumentException _) {
			return null;
		}
	}

	private static final Map<ASN1ObjectIdentifier, KSMType> PQC_TYPES = Map.of(
		NISTObjectIdentifiers.id_ml_dsa_65, PQC_L2,
		NISTObjectIdentifiers.id_alg_ml_kem_768, PQC_L2,
		NISTObjectIdentifiers.id_ml_dsa_87, PQC_L5,
		NISTObjectIdentifiers.id_alg_ml_kem_1024, PQC_L5
	);
}