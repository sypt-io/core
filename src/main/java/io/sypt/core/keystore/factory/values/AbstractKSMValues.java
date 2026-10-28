package io.sypt.core.keystore.factory.values;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.keystore.factory.KSMType;

public abstract class AbstractKSMValues implements KSMValues {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final String keyStore;
    private final char[] password;
    private final KSMType type;
    
    AbstractKSMValues(String keyStore, char[] password, KSMType type) {
        this.keyStore = keyStore;
        this.password = (password != null) ? password.clone() : new char[0];
        this.type = type;
    }
    
    @Override
    public String getKeyStore() {
    	log.debug("Accessing BasicKSMValues::keyStore");
        return keyStore;
    }
    
    @Override
    public char[] getPassword() {
    	log.debug("Accessing BasicKSMValues::password");
        return password.clone();
    }
    
    @Override
    public KSMType getType() {
    	return type;
    }
}