package io.sypt.core.keystore.factory;

import java.time.temporal.ChronoUnit;

public record KSMData(KSMType type, String alias, String domain, int serialNumberBits, int validity, ChronoUnit validityUnit) {

}
