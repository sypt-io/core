package io.sypt.core.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

public class KSMResourceLoader {

	public InputStream getResource(String location) throws FileNotFoundException {
	    File file = new File(location);
	    if (file.exists() && file.isFile()) {
	        return new FileInputStream(file);
	    }

	    String cleanPath = location.replace("classpath:", "");
	    if (cleanPath.startsWith("/")) {
	        cleanPath = cleanPath.substring(1);
	    }

	    InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(cleanPath);

	    if (is == null) {
	        throw new FileNotFoundException("Ressource introuvable : " + location);
	    }

	    return is;
	}

}
