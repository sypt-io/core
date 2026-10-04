package io.sypt.core.keystore.factory.values;

import java.io.Serializable;
import java.util.Objects;

public record KSMValuesData(
    String alias,
    String domain,
    char[] password
) implements Serializable {
    
    public KSMValuesData {
        password = (password != null) ? password.clone() : null;
    }
    
    @Override
    public char[] password() {
        return (password != null) ? password.clone() : null;
    }

    @Override
    public final String toString() {
        StringBuilder b = new StringBuilder();
        b.append("alias = ");
        b.append(alias);
        b.append(", domain = ");
        b.append(domain);
        return b.toString();
    }
    
    @Override
    public final boolean equals(Object o) {
        if (this == o) {
        	return true;
        }
        if (o instanceof KSMValuesData(String vAlias, String vDomain, _)) {
        	return Objects.equals(alias, vAlias) 
                    && Objects.equals(domain, vDomain);
        }
        
        return false;
    }
    
    @Override
    public final int hashCode() {
        int result = Objects.hash(alias, domain);
        return 31 * result;
    }
}