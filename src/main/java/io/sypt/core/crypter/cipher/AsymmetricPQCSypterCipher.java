package io.sypt.core.crypter.cipher;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.security.auth.DestroyFailedException;

import org.apache.commons.lang3.StringUtils;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;

/**
 * PQC asymmetric cipher protecting the symmetric secret key with ML-KEM (RFC 9629 like):
 * <ol>
 * <li>ML-KEM encapsulation with the public key gives an encapsulation and a shared secret</li>
 * <li>HKDF derives an AES-256 KEK from the shared secret</li>
 * <li>The KEK wraps the symmetric secret key with AES-KWP (RFC 5649)</li>
 * </ol>
 * The protected secret key is <code>encapsulation || wrapped secret key</code>.
 * <p>
 * A protected secret key made only of the encapsulation is the legacy format, where the shared secret
 * was directly the symmetric secret key. It is still supported for decryption only.
 */
public final class AsymmetricPQCSypterCipher extends AbstractAsymmetricSypterCipher {

	private static final int KEK_LENGTH = 32;

	private final String kemAlgo;
	private final String hkdfAlgo;
	private final int encapsulationLength;
	private final String provider;

	public AsymmetricPQCSypterCipher(KSMType ksmType, KSM ksm, String ksmAlias) throws GeneralSecurityException {
		this(ksmType, ksm, ksmAlias, Cipher.getInstance(Crypter.CIPHER_KEY_WRAP_ALGO));
	}

	public AsymmetricPQCSypterCipher(KSMType ksmType, KSM ksm, String ksmAlias, javax.crypto.Cipher cipher) throws GeneralSecurityException {
		super(ksm, ksmAlias, cipher);
		this.hkdfAlgo = hkdfAlgo(ksmType);
		this.encapsulationLength = encapsulationLength(ksmType);
		this.kemAlgo = ksmType.encryptionSpec().keyPairGenerator();
		this.provider = (ksm != null) ? ksm.getProvider() : null;
	}

	@Override
	protected byte[] wrapKey(byte[] secretKey, Cipher cipher, PublicKey key) throws GeneralSecurityException {
		KEM.Encapsulated encapsulated = getKem().newEncapsulator(key).encapsulate();
		byte[] encapsulation = encapsulated.encapsulation();
		if (encapsulation.length != encapsulationLength) {
			throw new GeneralSecurityException("Unexpected " + kemAlgo + " encapsulation length: " + encapsulation.length);
		}

		SecretKey kek = deriveKek(encapsulated.key());
		try {
			cipher.init(Cipher.ENCRYPT_MODE, kek);
			byte[] wrapped = cipher.doFinal(secretKey);

			byte[] result = Arrays.copyOf(encapsulation, encapsulation.length + wrapped.length);
			System.arraycopy(wrapped, 0, result, encapsulation.length, wrapped.length);
			return result;
		} finally {
			destroy(encapsulated.key());
			destroy(kek);
		}
	}

	@Override
	protected byte[] unwrapKey(byte[] wrappedKey, Cipher cipher, PrivateKey key) throws GeneralSecurityException {
		if (wrappedKey.length < encapsulationLength) {
			throw new GeneralSecurityException("Invalid " + kemAlgo + " protected secret key length: " + wrappedKey.length);
		}

		SecretKey sharedSecret = getKem().newDecapsulator(key).decapsulate(Arrays.copyOf(wrappedKey, encapsulationLength));
		try {
			if (wrappedKey.length == encapsulationLength) {
				log.debug("Legacy PQC format: shared secret used as secret key");
				return Base64.getEncoder().encode(sharedSecret.getEncoded());
			}

			SecretKey kek = deriveKek(sharedSecret);
			try {
				cipher.init(Cipher.DECRYPT_MODE, kek);
				return cipher.doFinal(wrappedKey, encapsulationLength, wrappedKey.length - encapsulationLength);
			} finally {
				destroy(kek);
			}
		} finally {
			destroy(sharedSecret);
		}
	}

	private KEM getKem() throws GeneralSecurityException {
		return StringUtils.isBlank(provider) ? KEM.getInstance(kemAlgo) : KEM.getInstance(kemAlgo, provider);
	}

	private SecretKey deriveKek(SecretKey sharedSecret) throws GeneralSecurityException {
		byte[] ikm = sharedSecret.getEncoded();
		try {
			byte[] info = (Crypter.HKDF_INFO_PREFIX + kemAlgo + "|AES-256-KWP").getBytes(StandardCharsets.UTF_8);
			return KDF.getInstance(hkdfAlgo).deriveKey(KSM.AES, HKDFParameterSpec.ofExtract().addIKM(ikm).thenExpand(info, KEK_LENGTH));
		} finally {
			Arrays.fill(ikm, (byte) 0);
		}
	}

	private void destroy(SecretKey key) {
		if (key == null || key.isDestroyed()) {
			return;
		}

		try {
			key.destroy();
		} catch (DestroyFailedException _) {
			log.trace("Unable to destroy key");
		}
	}

	private static String hkdfAlgo(KSMType ksmType) throws InvalidAlgorithmParameterException {
		return switch (ksmType) {
			case PQC_L2 -> "HKDF-SHA256";
			case PQC_L5 -> "HKDF-SHA512";
			case null, default -> throw new InvalidAlgorithmParameterException("KSMType is not of type PQC");
		};
	}

	private static int encapsulationLength(KSMType ksmType) throws InvalidAlgorithmParameterException {
		return switch (ksmType) {
			case PQC_L2 -> 1088;
			case PQC_L5 -> 1568;
			case null, default -> throw new InvalidAlgorithmParameterException("KSMType is not of type PQC");
		};
	}

}
