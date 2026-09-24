package io.sypt.core.keystore.factory;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.generator.SypterGenerator;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType.KeySpec;
import io.sypt.core.keystore.factory.values.BasicKSMValues;
import io.sypt.core.keystore.factory.values.EncryptedKSMValues;
import io.sypt.core.keystore.factory.values.KSMValues;
import io.sypt.core.keystore.factory.values.KSMValuesData;

/**
 * KeyStore generator Factory
 * @author tazouxme
 */
public class KSMFactory {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	public enum Usage {
		/**
		 * Gives the ability to generate digital signature and encipher keys
		 */
		SYPT,
		
		/**
		 * Gives the ability to generate digital signature <b>as a client</b> in a mTLS context
		 */
		MTLS;
	}
	
	public static class Builder {
		
		private KSM ksm;
		private String ksmAlias;
		private KSMType type;
		private SypterGenerator generator;
		private String alias;
		private String domain;
		private Usage usage = Usage.SYPT;
		private int serialNumberBits = 128;
		private int validity = 730;
		private ChronoUnit validityUnit = ChronoUnit.DAYS;
		private boolean encryptedPassword = true;
		
		/**
		 * The master KSM used to generate and secure the subsequent generated KSM and its alias
		 * @param ksm - cannot be null
		 * @param ksmAlias - cannot be null
		 * @return
		 */
		public Builder keyStoreManager(KSM ksm, String ksmAlias) {
			this.ksm = ksm;
			this.ksmAlias = ksmAlias;
			return this;
		}
		
		/**
		 * The KSM type used for the newly generated KSM
		 * @param type - cannot be null
		 * @return
		 */
		public Builder type(KSMType type) {
			this.type = type;
			return this;
		}
		
		/**
		 * The alias used for the newly generated KSM
		 * @param alias - cannot be empty
		 * @return
		 */
		public Builder alias(String alias) {
			this.alias = alias;
			return this;
		}

		/**
		 * The domain used for the newly generated KSM
		 * @param domain - cannot be empty
		 * @return
		 */
		public Builder domain(String domain) {
			this.domain = domain;
			return this;
		}
		
		/**
		 * {@link Usage} for the generated Certificate
		 * @param usage - default Usage.SYPT
		 * @return
		 */
		public Builder usage(Usage usage) {
			this.usage = usage;
			return this;
		}
		
		/**
		 * Bits used for the certificate's serial number
		 * @param serialNumberBits - default 128 bits
		 * @return
		 */
		public Builder serialNumberBits(int serialNumberBits) {
			this.serialNumberBits = serialNumberBits;
			return this;
		}

		/**
		 * The validity in days of the newly generated KSM
		 * @param validity - default 730
		 * @param validityUnit - default ChronoUnit.DAYS
		 * @return
		 */
		public Builder validity(int validity, ChronoUnit validityUnit) {
			this.validity = validity;
			this.validityUnit = validityUnit;
			return this;
		}

		/**
		 * Whether the generated password of the KSM must be encrypted or not
		 * @param encryptedPassword - default true 
		 * @return
		 */
		public Builder encryptedPassword(boolean encryptedPassword) {
			this.encryptedPassword = encryptedPassword;
			return this;
		}

		/**
		 * The generator used for KSM data generation
		 * @param generator - can be null
		 * @return
		 */
		public Builder generator(SypterGenerator generator) {
			this.generator = generator;
			return this;
		}
		
		public KSMValues build() throws KSMException {
			Objects.requireNonNull(ksm, "KSMFactory parameter 'ksm' is not set");
			Objects.requireNonNull(ksmAlias, "KSMFactory parameter 'ksmAlias' is not set");
			Objects.requireNonNull(alias, "KSMFactory parameter 'alias' is not set");
			Objects.requireNonNull(domain, "KSMFactory parameter 'domain' is not set");
			Objects.requireNonNull(usage, "KSMFactory parameter 'usage' is not set");
			
			if (this.generator == null) {
	            this.generator = new DefaultSypterGenerator(ksm.getProvider());
	        }
			
			if (this.type == null) {
				this.type = ksm.getVerificationType(ksmAlias);
				
				if (this.type == null) {
					throw new KSMException("KSMFactory parameter 'type' cannot be null");
				}
			}
			
			KSMFactory factory = new KSMFactory();
			KSMData data = new KSMData(type, alias, domain, serialNumberBits, validity, validityUnit);
			
			return factory.generateKeyStore(data, ksm, ksmAlias, generator, usage, encryptedPassword);
		}
		
	}
	
	private KSMFactory() { }
	
	public static final Builder builder() {
		return new Builder();
	}

	/**
	 * Factory method to generate a new KeyStore
	 * @param data Includes the Type (EC or RSA), Alias, Domain and validity of the KeyStore
	 * @param masterKSM Used to encrypt and sign the password of the KeyStore
	 * @param masterAlias KeyStore's alias
	 * @param encryptPassword Whether the password should be encrypted or clear
	 * @return The KeyStore and its password
	 * @throws KSMException
	 */
	private KSMValues generateKeyStore(
		KSMData data,
		KSM masterKSM,
		String masterAlias,
		SypterGenerator generator,
		Usage usage,
		boolean encryptPassword
	) throws KSMException {
		if (masterKSM == null) {
			throw new KSMException("'masterKSM' cannot be null");
		}
		
		log.trace("Generating new password");
		char[] keyStorePassword = generator.generateId("SPASS-", 32).toCharArray();
		String provider = masterKSM.getProvider();
		
		try {
			log.trace("Generating new KeyStore");
			KeyStore ks = StringUtils.isBlank(provider)
					? KeyStore.getInstance(KSM.KEY_STORE_TYPE)
					: KeyStore.getInstance(KSM.KEY_STORE_TYPE, provider);
			ks.load(null, null);
			
			KeySpec sigSpec = data.type().signatureSpec();
			KeySpec encSpec = data.type().encryptionSpec();
			
			String sigAlias = data.alias() + "-sig";
			String encAlias = data.alias() + "-enc";
			
			log.trace("Generating new Signature Key pair ({})", sigSpec.keyPairGenerator());
			KeyPair sigKeyPair = generateKeyPair(sigSpec, provider);
			Certificate sigCert = createCertificate(data, sigKeyPair, sigSpec, usage, masterKSM, masterAlias, KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
			ks.setKeyEntry(sigAlias, sigKeyPair.getPrivate(), keyStorePassword, buildChain(sigCert, masterKSM, masterAlias));
			
			log.trace("Generating new Encryption Key pair ({})", encSpec.keyPairGenerator());
			KeyPair encKeyPair = generateKeyPair(encSpec, provider);
			Certificate encCert = createCertificate(data, encKeyPair, encSpec, usage, masterKSM, masterAlias, KeyUsage.keyEncipherment | KeyUsage.keyAgreement);
			ks.setKeyEntry(encAlias, encKeyPair.getPrivate(), keyStorePassword, buildChain(encCert, masterKSM, masterAlias));

			try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
				log.trace("Storing new KeyStore");
				ks.store(os, keyStorePassword);
				
				if (encryptPassword) {
					return new EncryptedKSMValues(
						new String(Base64.getEncoder().encode(os.toByteArray())),
						new KSMValuesData(data.alias(), data.domain(), keyStorePassword),
						masterKSM,
						masterAlias);
				}
				
				return new BasicKSMValues(
					new String(Base64.getEncoder().encode(os.toByteArray())),
					keyStorePassword
				);
			}
		} catch (Exception e) {
			throw new KSMException("Unable to generate a new key store", e);
		}
	}
	
	private KeyPair generateKeyPair(KeySpec spec, String provider) throws GeneralSecurityException {
		KeyPairGenerator generator = StringUtils.isBlank(provider)
				? KeyPairGenerator.getInstance(spec.keyPairGenerator())
				: KeyPairGenerator.getInstance(spec.keyPairGenerator(), provider);
		
		if (spec.params() != null) {
			generator.initialize(spec.params());
		}
		
		return generator.generateKeyPair();
	}
	
	private SecureRandom getSecureRandom(Provider provider) {
	    if (!Objects.isNull(provider)) {
	        try {
	            return SecureRandom.getInstance("DEFAULT", provider);
	        } catch (Exception _) {
	            log.warn("Unable to load SecureRandom from provider {}, back to default", provider);
	        }
	    }
	    
	    return new SecureRandom();
	}
	
	private Certificate createCertificate(
		KSMData data,
		KeyPair keyPair,
		KeySpec keySpec,
		Usage usage,
		KSM masterKSM,
		String masterAlias,
		int keyUsageBitmask
	) throws KSMException {
		Provider provider = Security.getProvider(masterKSM.getProvider());
		SubjectPublicKeyInfo subjectPublicKeyInfo;

		if (keySpec.canSign()) {
			try {
				ContentSigner csrSigner = new JcaContentSignerBuilder(keySpec.contentSigner())
						.setProvider(provider)
						.build(keyPair.getPrivate());
				PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + data.domain()), keyPair.getPublic())
						.build(csrSigner);
				subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();
			} catch (OperatorCreationException e) {
				throw new KSMException("Failed to build CSR for " + keySpec.keyPairGenerator(), e);
			}
		} else {
			subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		}

		try {
			ContentSigner certSigner = new JcaContentSignerBuilder(masterKSM.getVerificationType(masterAlias).signatureSpec().contentSigner())
					.setProvider(provider)
					.build(masterKSM.getSigningKey(masterAlias));

			X500Name issuer = new JcaX509CertificateHolder((X509Certificate) masterKSM.getVerificationCertificate(masterAlias)).getSubject();

			DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
			Instant now = Instant.now();

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
				issuer,
				new BigInteger(data.serialNumberBits(), getSecureRandom(provider)).abs(),
				Time.getInstance(new DERGeneralizedTime(fmt.format(now.minus(1, ChronoUnit.DAYS)))),
				Time.getInstance(new DERGeneralizedTime(fmt.format(now.plus(data.validity(), data.validityUnit())))),
				new X500Name("CN=" + data.domain()),
				subjectPublicKeyInfo
			);

			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageBitmask));

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier((X509Certificate) masterKSM.getVerificationCertificate(masterAlias)));
			builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo));

			builder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
	            new GeneralName(GeneralName.dNSName, data.domain())
	        }));
			
			if (usage == Usage.MTLS) {
				builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
			}

			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(provider)
					.getCertificate(builder.build(certSigner));

			cert.verify(masterKSM.getVerificationKey(masterAlias), provider);
			return cert;
		} catch (GeneralSecurityException | CertIOException | OperatorCreationException e) {
			throw new KSMException("Failed to issue certificate for " + keySpec.keyPairGenerator(), e);
		}
	}
	
	private Certificate[] buildChain(Certificate cert, KSM masterKSM, String masterAlias) throws KSMException {
		List<Certificate> chain = new ArrayList<>();
		chain.add(cert);
		
		Certificate[] masterChain = masterKSM.getVerificationCertificateChain(masterAlias);
		if (masterChain != null) {
			chain.addAll(Arrays.asList(masterChain));
		}
		
		return chain.toArray(new Certificate[0]);
	}

}
