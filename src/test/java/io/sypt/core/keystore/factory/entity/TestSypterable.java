package io.sypt.core.keystore.factory.entity;

import org.apache.commons.lang3.StringUtils;

import io.sypt.core.entity.Sypterable;

public class TestSypterable implements Sypterable {
	
	private String id;
	private String data;
	
	public TestSypterable() {
		this(StringUtils.EMPTY, StringUtils.EMPTY);
	}
	
	public TestSypterable(String id, String data) {
		this.id = id;
		this.data = data;
	}

	@Override
	public String getId() {
		return id;
	}
	
	public void setId(String id) {
		this.id = id;
	}
	
	public String getData() {
		return data;
	}
	
	public void setData(String data) {
		this.data = data;
	}

}
