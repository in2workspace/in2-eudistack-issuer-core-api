package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class UVarIntTest {
    @Test
    void uVarInt_correctByteArrayForSmallValue() {
        UVarInt uVarInt = new UVarInt(127);
        byte[] expectedBytes = new byte[]{127};
        assertArrayEquals(expectedBytes, uVarInt.getBytes());
    }

    @Test
    void uVarInt_correctByteArrayForLargeValue() {
        UVarInt uVarInt = new UVarInt(128);
        byte[] expectedBytes = new byte[]{(byte) 0x80, 1};
        assertArrayEquals(expectedBytes, uVarInt.getBytes());
    }

    @Test
    void uVarInt_correctByteArrayForMaxValue() {
        UVarInt uVarInt = new UVarInt(Long.MAX_VALUE);
        byte[] expectedBytes = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x7F};
        assertArrayEquals(expectedBytes, uVarInt.getBytes());
    }

    @Test
    void uVarInt_correctLengthForSmallValue() {
        UVarInt uVarInt = new UVarInt(127);
        assertEquals(1, uVarInt.getLength());
    }

    @Test
    void uVarInt_correctLengthForLargeValue() {
        UVarInt uVarInt = new UVarInt(128);
        assertEquals(2, uVarInt.getLength());
    }

    @Test
    void uVarInt_correctLengthForMaxValue() {
        UVarInt uVarInt = new UVarInt(Long.MAX_VALUE);
        assertEquals(9, uVarInt.getLength());
    }

    @Test
    void uVarInt_toStringReturnsHexRepresentation() {
        UVarInt uVarInt = new UVarInt(255);
        assertEquals("0xff", uVarInt.toString());
    }
}
