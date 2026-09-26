package io.sypt.core.keystore.factory.values;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.keystore.factory.KSMType;

public final class BasicKSMValues implements KSMValues {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final String keyStore;
    private final char[] password;
    private final KSMType type;
    
    public BasicKSMValues(String keyStore, char[] password, KSMType type) {
        this.keyStore = keyStore;
        this.password = (password != null) ? password.clone() : null;
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
        return (password != null) ? password.clone() : null;
    }
    
    @Override
    public KSMType getType() {
    	return type;
    }
}