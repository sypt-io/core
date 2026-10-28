package io.sypt.core.keystore.factory.values;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.exception.SypterException;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.core.keystore.sypter.KeyStoreSypter;
import io.sypt.core.keystore.sypter.entity.KeyStoreSypterable;
import io.sypt.core.signer.exception.SignerException;

public final class EncryptedKSMValues extends AbstractKSMValues {
    
    public EncryptedKSMValues(
        String keyStore,
        KSMValuesData data,
        KSM masterKSM,
        String masterAlias,
        KSMType type
    ) throws KSMException {
        super(keyStore, encryptPassword(data, masterKSM, masterAlias), type);
    }
    
    private static char[] encryptPassword(KSMValuesData data, KSM masterKSM, String masterAlias) throws KSMException {
        try {
            DefaultSypterGenerator gen = new DefaultSypterGenerator(masterKSM.getProvider());
            return new KeyStoreSypter(masterKSM, masterAlias).syptAndEncode(new KeyStoreSypterable(gen.generateId("SID-", 16), data)).toCharArray();
        } catch (SypterException | CrypterException | SignerException e) {
            throw new KSMException("Unable to encrypt KeyStore's password", e);
        }
    }

}