package io.sypt.core.signer;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.core.signer.exception.SignerException;

public abstract sealed class AbstractSigner implements Signer permits EcSigner, RsaSigner, PQCSigner {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	private final KSMType ksmType;
	private final KSM ksm;
	private final String ksmAlias;
	
	protected AbstractSigner(KSMType ksmType, KSM ksm, String ksmAlias) {
		this.ksmType = ksmType;
		this.ksm = ksm;
		this.ksmAlias = ksmAlias;
	}

	@Override
	public String sign(byte[] text) throws SignerException {
		if (ksm == null) {
			throw new SignerException("'ksm' cannot be empty");
		}
		
		try {
			return sign(text, ksm.getSigningKey(ksmAlias), ksmType.signatureSpec().contentSigner());
		} catch (KSMException e) {
			log.warn(SignerException.CANNOT_SIGN);
			throw new SignerException(SignerException.CANNOT_SIGN, e);
		}
	}
	
	@Override
	public String sign(byte[] text, PrivateKey key, String algorithm) throws SignerException {
		log.debug("Sign data");
		
		if (ksm == null) {
			throw new SignerException("'ksm' cannot be empty");
		}
		
		try {
			Signature signature = StringUtils.isBlank(ksm.getProvider())
					? Signature.getInstance(algorithm)
					: Signature.getInstance(algorithm, ksm.getProvider());
			signature.initSign(key);
			signature.update(text);
			
			return new String(Base64.getEncoder().encode(signature.sign()));
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			log.warn(SignerException.CANNOT_SIGN);
			throw new SignerException(SignerException.CANNOT_SIGN, e);
		}
	}
	
	@Override
	public boolean verify(byte[] text, byte[] digitalSignature) throws SignerException {
		if (ksm == null) {
			throw new SignerException("'ksm' cannot be empty");
		}
		
		try {
			return verify(text, digitalSignature, ksm.getVerificationKey(ksmAlias), ksmType.signatureSpec().contentSigner());
		} catch (KSMException e) {
			log.warn(SignerException.CANNOT_VERIFY);
			throw new SignerException(SignerException.CANNOT_VERIFY, e);
		}
	}
	
	@Override
	public boolean verify(byte[] text, byte[] digitalSignature, PublicKey key, String algorithm) throws SignerException {
		log.debug("Verify signature");
		
		if (ksm == null) {
			throw new SignerException("'ksm' cannot be empty");
		}
		
		try {
			Signature signature = StringUtils.isBlank(ksm.getProvider())
					? Signature.getInstance(algorithm)
					: Signature.getInstance(algorithm, ksm.getProvider());
			signature.initVerify(key);
			
			signature.update(text);
			return signature.verify(Base64.getDecoder().decode(digitalSignature));
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			log.warn(SignerException.CANNOT_VERIFY);
			throw new SignerException(SignerException.CANNOT_VERIFY, e);
		}
	}

}
