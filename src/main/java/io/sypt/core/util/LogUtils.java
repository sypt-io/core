package io.sypt.core.util;

/**
 * Logging helpers
 * @author tazouxme
 */
public final class LogUtils {

	private LogUtils() { }

	/**
	 * Neutralize CR / LF characters so that a value cannot forge log entries
	 * @param value The value to be logged
	 * @return The value without CR / LF characters
	 */
	public static String sanitize(String value) {
		if (value == null) {
			return null;
		}

		return value.replace("\r", "_").replace("\n", "_");
	}

}
