package io.sypt.core.generator.entity;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public record SypterValues(Key key, byte[] iv) {

    public SypterValues {
        iv = (iv != null) ? iv.clone() : null;
    }

    @Override
    public byte[] iv() {
        return (iv != null) ? iv.clone() : null;
    }

    public String encodedIv() {
        return (iv != null) ? Base64.getEncoder().encodeToString(iv) : null;
    }

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) return true;

        if (obj instanceof SypterValues(Key vKey, byte[] vIv)) {
            return Objects.equals(key, vKey) && Arrays.equals(iv, vIv);
        }

        return false;
    }

    @Override
    public final int hashCode() {
        int result = Objects.hash(key);
        result = 31 * result + Arrays.hashCode(iv);
        return result;
    }

    @Override
    public final String toString() {
        if (key == null) {
        	return "Key: null";
        }
        
        StringBuilder b = new StringBuilder();
        b.append("Format: ");
        b.append(key.getFormat());
        b.append(", Algorithm: ");
        b.append(key.getAlgorithm());

        return b.toString();
    }
}