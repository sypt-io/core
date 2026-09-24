package io.sypt.core.keystore.sypter;

import org.apache.commons.lang3.StringUtils;

import io.sypt.core.AbstractSypter;
import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.sypter.entity.KeyStoreSypterable;
import io.sypt.core.signer.exception.SignerException;

/**
 * Generate a double encrypted password
 * @author tazouxme
 */
public class KeyStoreSypter extends AbstractSypter<KeyStoreSypterable> {

	public KeyStoreSypter(KSM ksm, String alias) throws CrypterException, SignerException {
		super(ksm, alias);
	}

	@Override
	protected boolean isEntityValid(KeyStoreSypterable obj) {
		return obj != null && StringUtils.isNotBlank(obj.getId()) && obj.getPassword() != null
				 && StringUtils.isNotBlank(obj.getAlias()) && StringUtils.isNotBlank(obj.getDomain());
	}

}
