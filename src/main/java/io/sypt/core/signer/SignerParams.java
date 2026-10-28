package io.sypt.core.signer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import io.sypt.core.entity.Syptered;
import io.sypt.core.signer.exception.SignerException;

/**
 * Data covered by the signature of a {@link Syptered}
 * <ul>
 * <li>{@link Syptered#VERSION_1}: <code>object::keyId::timestamp</code></li>
 * <li>{@link Syptered#VERSION_2}: a domain label, the version, the object, the keyId, the timestamp and the algorithms,
 * each field prefixed by its length so that no field can be shifted into another</li>
 * </ul>
 */
public record SignerParams(int version, String object, String keyId, long timestamp, String encAlgo, String sigAlgo) {

	private static final byte[] VERSION_2_LABEL = "sypt-core/syptered".getBytes(StandardCharsets.UTF_8);

	/**
	 * Construct the {@link SignerParams} of a {@link Syptered#VERSION_1}
	 */
	public SignerParams(String object, String keyId, long timestamp) {
		this(Syptered.VERSION_1, object, keyId, timestamp, null, null);
	}

	public byte[] digest() throws SignerException {
		byte[] input = switch (version) {
			case Syptered.VERSION_1 -> (object + Signer.ID_SEPARATOR + keyId + Signer.ID_SEPARATOR + Long.valueOf(timestamp)).getBytes(StandardCharsets.UTF_8);
			case Syptered.VERSION_2 -> encodeVersion2();
			default -> throw new SignerException("Unsupported Syptered version: " + version);
		};

		try {
            return MessageDigest.getInstance("SHA3-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new SignerException("Algorithm SHA3-256 not found", e);
        }
	}

	private byte[] encodeVersion2() throws SignerException {
		try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream out = new DataOutputStream(bytes)) {
			write(out, VERSION_2_LABEL);
			out.writeInt(version);
			write(out, object);
			write(out, keyId);
			out.writeLong(timestamp);
			write(out, encAlgo);
			write(out, sigAlgo);
			out.flush();

			return bytes.toByteArray();
		} catch (IOException e) {
			throw new SignerException("Unable to encode the signed data", e);
		}
	}

	private static void write(DataOutputStream out, String value) throws IOException {
		write(out, Objects.toString(value, "").getBytes(StandardCharsets.UTF_8));
	}

	private static void write(DataOutputStream out, byte[] value) throws IOException {
		out.writeInt(value.length);
		out.write(value);
	}

}
