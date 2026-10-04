package io.sypt.core.crypter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.generator.SypterGenerator;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;

/**
 * Default PQC crypter that generates double encryption from {@link byte[]} to a {@link AsymmetricSypterObject}
 */
public final class PQCCrypter implements Crypter<byte[], AsymmetricSypterObject> {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());

	private final KSMType ksmType;
	private final KSM ksm;
	private final String ksmAlias;
	private final SypterGenerator generator;

	public PQCCrypter(KSMType ksmType, KSM ksm, String ksmAlias) {
		this.ksmType = ksmType;
		this.ksm = ksm;
		this.ksmAlias = ksmAlias;
		this.generator = ksm.getProvider() == null ? new DefaultSypterGenerator()
				: new DefaultSypterGenerator(ksm.getProvider());
	}

	@Override
	public AsymmetricSypterObject encrypt(byte[] data) throws CrypterException {
		if (data == null || data.length == 0) {
			throw new CrypterException("Data cannot be empty");
		}

		log.debug("Encrypt data");
		try {
			PublicKey publicKey = ksm.getEncryptionKey(ksmAlias);
			String provider = ksm.getProvider();

			KEM kem = (provider != null && !provider.isBlank())
					? KEM.getInstance(ksmType.encryptionSpec().keyPairGenerator(), provider)
					: KEM.getInstance(ksmType.encryptionSpec().keyPairGenerator());

			KEM.Encapsulator encapsulator = kem.newEncapsulator(publicKey);
			KEM.Encapsulated encapsulated = encapsulator.encapsulate();

			byte[] encapsulatedKey = encapsulated.encapsulation();
			SecretKey sharedSecret = encapsulated.key();

			byte[] iv = generator.generateIv();

			Cipher cipher = Cipher.getInstance(Crypter.CIPHER_SYMMETRIC_ALGO_AES);
			SecretKey aesKey = new SecretKeySpec(sharedSecret.getEncoded(), "AES");
			cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

			AsymmetricSypterObject result = new AsymmetricSypterObject();
			result.setEncryptedSecretKey(Base64.getEncoder().encodeToString(encapsulatedKey));
			result.setEncryptedData(Base64.getEncoder().encodeToString(cipher.doFinal(data)));
			result.setIv(Base64.getEncoder().encodeToString(iv));

			return result;
		} catch (Exception e) {
			throw new CrypterException("Failed to encrypt data with PQC hybrid scheme", e);
		}
	}

	@Override
	public byte[] decrypt(AsymmetricSypterObject b) throws CrypterException {
		if (b == null) {
            throw new CrypterException("Data cannot be empty");
        }

		log.debug("Decrypt data");
        try {
            PrivateKey privateKey = ksm.getDecryptionKey(ksmAlias);
            String provider = ksm.getProvider();

            KEM kem = (provider != null && !provider.isBlank()) 
                    ? KEM.getInstance(ksmType.encryptionSpec().keyPairGenerator(), provider) 
                    : KEM.getInstance(ksmType.encryptionSpec().keyPairGenerator());

            KEM.Decapsulator decapsulator = kem.newDecapsulator(privateKey);
            SecretKey sharedSecret = decapsulator.decapsulate(Base64.getDecoder().decode(b.getEncryptedSecretKey()));

            Cipher aesCipher = Cipher.getInstance(Crypter.CIPHER_SYMMETRIC_ALGO_AES);
            SecretKey aesKey = new SecretKeySpec(sharedSecret.getEncoded(), "AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, Base64.getDecoder().decode(b.getIv())));

            return aesCipher.doFinal(Base64.getDecoder().decode(b.getEncryptedData()));
        } catch (Exception e) {
            throw new CrypterException("Failed to decrypt data with PQC hybrid scheme", e);
        }
	}

}
