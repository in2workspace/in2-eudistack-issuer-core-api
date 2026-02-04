package es.in2.issuer.backend.statuslist.domain.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Utility for encoding/decoding Bitstring Status List encodedList.
 *
 * Format:
 * - Uncompressed payload: raw bytes representing the bitstring
 * - Compressed: GZIP
 * - Encoded: Multibase base64url (prefix 'u', no padding)
 */
public class BitstringEncoder {

    public static final char MULTIBASE_BASE64URL_PREFIX = 'u';

    public boolean getBit(String encodedList, int idx) {
        if (encodedList == null || encodedList.isBlank()) {
            throw new IllegalArgumentException("encodedList cannot be blank");
        }
        if (idx < 0) {
            throw new IllegalArgumentException("idx must be >= 0");
        }
        byte[] rawBytes = decodeToRawBytes(encodedList);
        return isBitSet(rawBytes, idx);
    }

    /**
     * Creates a new empty bitstring with the given number of bits, encoded as multibase base64url gzip.
     * Bits will be initialized to 0.
     */
    public String createEmptyEncodedList(int bitCount) {
        if (bitCount <= 0) {
            throw new IllegalArgumentException("bitCount must be > 0");
        }
        if (bitCount % 8 != 0) {
            throw new IllegalArgumentException("bitCount must be a multiple of 8 (full bytes)");
        }

        int byteCount = bitCount / 8;
        byte[] raw = new byte[byteCount];
        return encode(raw);
    }

    /**
     * Encodes raw bitstring bytes into multibase base64url gzip (prefix 'u').
     */
    public String encode(byte[] rawBytes) {
        if (rawBytes == null) {
            throw new IllegalArgumentException("rawBytes");
        }

        byte[] gzipped = gzip(rawBytes);
        String b64url = Base64.getUrlEncoder().withoutPadding().encodeToString(gzipped);
        return MULTIBASE_BASE64URL_PREFIX + b64url;
    }

    /**
     * Decodes an encodedList into raw bitstring bytes (gunzipped).
     * Accepts values with or without the multibase 'u' prefix.
     */
    public byte[] decodeToRawBytes(String encodedList) {
        if (encodedList == null || encodedList.isBlank()) {
            throw new IllegalArgumentException("encodedList cannot be blank");
        }

        String payload = encodedList;
        if (payload.charAt(0) == MULTIBASE_BASE64URL_PREFIX) {
            payload = payload.substring(1);
        }

        final byte[] gzipped;
        try {
            gzipped = Base64.getUrlDecoder().decode(payload);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("encodedList is not valid base64url", e);
        }

        try {
            return gunzip(gzipped);
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException("encodedList is not valid gzip content", e);
        }
    }

    /**
     * Returns true if the bit at the given index is set (1).
     */
    public boolean isBitSet(byte[] rawBytes, int bitIndex) {
        validateBitIndex(rawBytes, bitIndex);

        int byteIndex = bitIndex / 8;
        int bitInByte = 7 - (bitIndex % 8); // MSB-first ordering

        int mask = 1 << bitInByte;
        return (rawBytes[byteIndex] & mask) != 0;
    }

    /**
     * Sets or clears the bit at the given index (mutates the provided array).
     */
    public void setBit(byte[] rawBytes, int bitIndex, boolean value) {
        validateBitIndex(rawBytes, bitIndex);

        int byteIndex = bitIndex / 8;
        int bitInByte = 7 - (bitIndex % 8); // MSB-first ordering

        int mask = 1 << bitInByte;
        if (value) {
            rawBytes[byteIndex] = (byte) (rawBytes[byteIndex] | mask);
        } else {
            rawBytes[byteIndex] = (byte) (rawBytes[byteIndex] & ~mask);
        }
    }

    /**
     * Convenience method: decodes, sets the bit, re-encodes.
     * Useful for simple updates (e.g., revoke sets bit to 1).
     */
    public String setBit(String encodedList, int bitIndex, boolean value) {
        byte[] raw = decodeToRawBytes(encodedList);
        setBit(raw, bitIndex, value);
        return encode(raw);
    }

    private void validateBitIndex(byte[] rawBytes, int bitIndex) {
        if (rawBytes == null) {
            throw new IllegalArgumentException("rawBytes");
        }
        if (bitIndex < 0) {
            throw new IllegalArgumentException("bitIndex must be >= 0");
        }
        int maxBits = rawBytes.length * 8;
        if (bitIndex >= maxBits) {
            throw new IllegalArgumentException("bitIndex out of range. maxBits=" + maxBits + ", bitIndex=" + bitIndex);
        }
    }

    private byte[] gzip(byte[] input) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(input);
            gzip.finish();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to gzip bitstring", e);
        }
    }

    private byte[] gunzip(byte[] input) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(input);
             GZIPInputStream gzip = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = gzip.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to gunzip bitstring", e);
        }
    }
}

