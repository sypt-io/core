package io.sypt.core.keystore.factory;

import org.apache.commons.lang3.StringUtils;

import io.sypt.core.AbstractSypter;
import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.entity.TestSypterable;
import io.sypt.core.signer.exception.SignerException;

/**
 * Generate a double encrypted data
 * @author tazouxme
 */
public class TestSypter extends AbstractSypter<TestSypterable> {

	public TestSypter(KSM keyStoreManager) throws CrypterException, SignerException {
		super(keyStoreManager, "test");
	}

	@Override
	protected boolean isEntityValid(TestSypterable obj) {
		return obj != null && StringUtils.isNotBlank(obj.getId()) && StringUtils.isNotBlank(obj.getData());
	}

}
