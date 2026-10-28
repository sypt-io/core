package io.sypt.core.keystore.factory.values;

import io.sypt.core.keystore.factory.KSMType;

public final class BasicKSMValues extends AbstractKSMValues {
    
    public BasicKSMValues(String keyStore, char[] password, KSMType type) {
        super(keyStore, password, type);
    }

}