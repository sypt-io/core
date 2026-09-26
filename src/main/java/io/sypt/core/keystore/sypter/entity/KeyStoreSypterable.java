package io.sypt.core.keystore.sypter.entity;

import org.apache.commons.lang3.StringUtils;

import io.sypt.core.entity.Sypterable;
import io.sypt.core.keystore.factory.values.KSMValuesData;

public class KeyStoreSypterable implements Sypterable {

	private String id;
	private String alias;
	private String domain;
	private char[] password;

	public KeyStoreSypterable() {
		this(StringUtils.EMPTY, null);
	}

	public KeyStoreSypterable(String id, KSMValuesData data) {
		this.id = id;

		if (data != null) {
			this.alias = data.alias();
			this.domain = data.domain();
			this.password = (data.password() != null) ? data.password().clone() : null;
		}
	}

	@Override
	public String getId() {
		return id;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public char[] getPassword() {
		return (password != null) ? password.clone() : null;
	}

	public void setPassword(char[] password) {
		this.password = (password != null) ? password.clone() : null;
	}

}