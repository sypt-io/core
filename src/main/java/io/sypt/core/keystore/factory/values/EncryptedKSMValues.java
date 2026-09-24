package io.sypt.core.keystore.factory.values;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.exception.SypterException;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.sypter.KeyStoreSypter;
import io.sypt.core.keystore.sypter.entity.KeyStoreSypterable;
import io.sypt.core.signer.exception.SignerException;

public final class EncryptedKSMValues implements KSMValues {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final String keyStore;
    private final char[] password;
    
    public EncryptedKSMValues(
        String keyStore,
        KSMValuesData data,
        KSM masterKSM,
        String masterAlias
    ) throws KSMException {
        this.keyStore = keyStore;
        this.password = encryptPassword(data, masterKSM, masterAlias);
    }
    
    @Override
    public String getKeyStore() {
    	log.debug("Accessing EncryptedKSMValues::keyStore");
        return keyStore;
    }
    
    @Override
    public char[] getPassword() {
    	log.debug("Accessing EncryptedKSMValues::password");
        return (password != null) ? password.clone() : null;
    }
    
    private char[] encryptPassword(KSMValuesData data, KSM masterKSM, String masterAlias) throws KSMException {
    	log.debug("Encrypting EncryptedKSMValues::password");
        try {
            DefaultSypterGenerator gen = new DefaultSypterGenerator(masterKSM.getProvider());
            return new KeyStoreSypter(masterKSM, masterAlias).syptAndEncode(new KeyStoreSypterable(gen.generateId("SID-", 16), data)).toCharArray();
        } catch (SypterException | CrypterException | SignerException e) {
            throw new KSMException("Unable to encrypt KeyStore's password", e);
        }
    }

}