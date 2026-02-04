package es.in2.issuer.backend.statuslist.domain.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BitstringEncoderTest {

    private BitstringEncoder bitstringEncoder;

    @BeforeEach
    void setUp() {
        bitstringEncoder = new BitstringEncoder();
    }

    @Test
    @DisplayName("Should create an empty encoded list and verify it is all zeros")
    void shouldCreateEmptyList() {
        int bitCount = 16; // 2 bytes
        String encoded = bitstringEncoder.createEmptyEncodedList(bitCount);

        assertThat(encoded).startsWith("u");
        byte[] raw = bitstringEncoder.decodeToRawBytes(encoded);
        assertThat(raw).hasSize(2);
        assertThat(bitstringEncoder.getBit(encoded, 0)).isFalse();
        assertThat(bitstringEncoder.getBit(encoded, 15)).isFalse();
    }

    @Test
    @DisplayName("Should set and get bits correctly")
    void shouldSetAndGetBits() {
        String list = bitstringEncoder.createEmptyEncodedList(8);

        String updated = bitstringEncoder.setBit(list, 3, true);
        updated = bitstringEncoder.setBit(updated, 7, true);

        assertThat(bitstringEncoder.getBit(updated, 3)).isTrue();
        assertThat(bitstringEncoder.getBit(updated, 7)).isTrue();
        assertThat(bitstringEncoder.getBit(updated, 0)).isFalse();
    }

    @Test
    @DisplayName("Should handle decoding without 'u' prefix")
    void shouldDecodeWithoutPrefix() {
        byte[] raw = new byte[]{0, 1};
        String encodedWithPrefix = bitstringEncoder.encode(raw);
        String noPrefix = encodedWithPrefix.substring(1);

        byte[] decoded = bitstringEncoder.decodeToRawBytes(noPrefix);
        assertThat(decoded).containsExactly(0, 1);
    }

    @Test
    @DisplayName("Should clear a bit (set to false)")
    void shouldClearBit() {
        byte[] raw = new byte[]{(byte) 0xFF}; // 11111111
        bitstringEncoder.setBit(raw, 0, false);

        assertThat(raw[0]).isEqualTo((byte) 127);
        assertThat(bitstringEncoder.isBitSet(raw, 0)).isFalse();
    }

    @Test
    void createEmptyList_ShouldThrow_WhenInvalidBitCount() {
        assertThatThrownBy(() -> bitstringEncoder.createEmptyEncodedList(0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bitstringEncoder.createEmptyEncodedList(7))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getBit_ShouldThrow_WhenInvalidInput() {
        assertThatThrownBy(() -> bitstringEncoder.getBit(null, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bitstringEncoder.getBit("", 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bitstringEncoder.getBit("uABC", -1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encode_ShouldThrow_WhenNull() {
        assertThatThrownBy(() -> bitstringEncoder.encode(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decode_ShouldThrow_WhenInvalidBase64() {
        assertThatThrownBy(() -> bitstringEncoder.decodeToRawBytes("u!!!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not valid base64url");
    }

    @Test
    void decode_ShouldThrow_WhenNotGzip() {
        // "uY2V0YQ" is "ceta" in base64url, it isn't a valid gzip
        assertThatThrownBy(() -> bitstringEncoder.decodeToRawBytes("uY2V0YQ"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not valid gzip content");
    }

    @Test
    void validateBitIndex_ShouldThrow_WhenIndexOutOfRange() {
        byte[] raw = new byte[1]; // 8 bits (0-7)
        assertThatThrownBy(() -> bitstringEncoder.isBitSet(raw, 8))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("out of range");

        assertThatThrownBy(() -> bitstringEncoder.isBitSet(null, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("createEmptyEncodedList: Should create a valid GZIP base64url list")
    void createEmptyEncodedList_Success() {
        int bitCount = 24; // 3 bytes
        String encoded = bitstringEncoder.createEmptyEncodedList(bitCount);

        assertThat(encoded).startsWith("u");
        byte[] decoded = bitstringEncoder.decodeToRawBytes(encoded);
        assertThat(decoded).hasSize(3).containsOnly(0);
    }

    @ParameterizedTest
    @CsvSource({
            "0, bitCount must be > 0",
            "7, bitCount must be a multiple of 8",
            "15, bitCount must be a multiple of 8"
    })
    void createEmptyEncodedList_InvalidInputs(int size, String expectedError) {
        assertThatThrownBy(() -> bitstringEncoder.createEmptyEncodedList(size))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(expectedError);
    }

    @Test
    @DisplayName("setBit & getBit: Comprehensive bit manipulation test")
    void bitManipulation_Success() {
        String list = bitstringEncoder.createEmptyEncodedList(8);

        String step1 = bitstringEncoder.setBit(list, 0, true);  // 10000000 (128)
        String step2 = bitstringEncoder.setBit(step1, 7, true); // 10000001 (129)

        assertThat(bitstringEncoder.getBit(step2, 0)).isTrue();
        assertThat(bitstringEncoder.getBit(step2, 7)).isTrue();
        assertThat(bitstringEncoder.getBit(step2, 4)).isFalse();

        // Test direct mutation over bytes array
        byte[] raw = bitstringEncoder.decodeToRawBytes(step2);
        bitstringEncoder.setBit(raw, 0, false);
        assertThat(bitstringEncoder.isBitSet(raw, 0)).isFalse();
        assertThat(raw[0]).isEqualTo((byte) 1);
    }

    @Test
    @DisplayName("decodeToRawBytes: Should handle various string formats")
    void decodeToRawBytes_Variants() {
        byte[] data = {1, 2, 3};
        String withPrefix = bitstringEncoder.encode(data);
        String withoutPrefix = withPrefix.substring(1);

        assertThat(bitstringEncoder.decodeToRawBytes(withPrefix)).containsExactly(data);
        assertThat(bitstringEncoder.decodeToRawBytes(withoutPrefix)).containsExactly(data);
    }

    @Test
    @DisplayName("validateBitIndex: Coverage for index boundaries")
    void validateBitIndex_Boundaries() {
        byte[] raw = new byte[2]; // 16 bits (0-15)

        // Invalid
        bitstringEncoder.setBit(raw, 0, true);
        bitstringEncoder.setBit(raw, 15, true);

        // Valid
        assertThatThrownBy(() -> bitstringEncoder.isBitSet(raw, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bitIndex must be >= 0");

        assertThatThrownBy(() -> bitstringEncoder.isBitSet(raw, 16))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("out of range");

        assertThatThrownBy(() -> bitstringEncoder.isBitSet(null, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("rawBytes");
    }

    @Test
    @DisplayName("Exceptions: Coverage for null/blank inputs")
    void nullAndBlankInputs_Coverage() {
        assertThatThrownBy(() -> bitstringEncoder.getBit(null, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bitstringEncoder.getBit("  ", 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bitstringEncoder.encode(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bitstringEncoder.decodeToRawBytes(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("GZIP/Base64 Errors: Coverage for catch blocks")
    void errorHandling_CatchBlocks() {
        // Invalid Base64
        assertThatThrownBy(() -> bitstringEncoder.decodeToRawBytes("u###"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("is not valid base64url");

        assertThatThrownBy(() -> bitstringEncoder.decodeToRawBytes("uY2V0YQ"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("is not valid gzip content");
    }
}
