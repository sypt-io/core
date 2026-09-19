package io.sypt.core.keystore;

import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

/**
 * Default RSA / EC KSMType to be used. Use with caution and <b>don't invert RSA / EC</b> !
 */
public class KSMProperties {
	
	private KSMProperties() { }
	
	private static KSMType ecType = KSMType.EC_384;
	private static KSMType rsaType = KSMType.RSA_4096;
	private static KSMType pqcType = KSMType.PQC_L5;
	
	/**
	 * Get the default PQC algorithm
	 * @return
	 */
	public static KSMType getPQCType() {
		return pqcType;
	}
	
	/**
	 * Set a new default PQC algorithm
	 * @param pqcType If null, default {@link KSMType} <code>PQC_L5</code> will be applied
	 * @throws KSMException 
	 */
	public static void setPQCType(KSMType pqcType) throws KSMException {
		KSMProperties.pqcType = pqcType == null ? KSMType.PQC_L5 : switch (pqcType) {
			case PQC_L2, PQC_L5 -> pqcType;
			default -> throw new KSMException("KSMType is not of type PQC");
		};
	}
	
	/**
	 * Get the default EC algorithm
	 * @return
	 */
	public static KSMType getEcType() {
		return ecType;
	}
	
	/**
	 * Set a new default EC algorithm
	 * @param ecType If null, default {@link KSMType} <code>EC_384</code> will be applied
	 * @throws KSMException 
	 */
	public static void setEcType(KSMType ecType) throws KSMException {
		KSMProperties.ecType = ecType == null ? KSMType.EC_384 : switch (ecType) {
			case EC_256, EC_384 -> ecType;
			default -> throw new KSMException("KSMType is not of type EC");
		};
	}

	/**
	 * Get the default EC algorithm
	 * @return
	 */
	public static KSMType getRsaType() {
		return rsaType;
	}
	
	/**
	 * Set a new default RSA algorithm
	 * @param rsaType If null, default {@link KSMType} <code>RSA_4096</code> will be applied
	 * @throws KSMException 
	 */
	public static void setRsaType(KSMType rsaType) throws KSMException {
		KSMProperties.rsaType = rsaType == null ? KSMType.RSA_4096 : switch (rsaType) {
			case RSA_2048, RSA_4096 -> rsaType;
			default -> throw new KSMException("KSMType is not of type RSA");
		};
	}

}
