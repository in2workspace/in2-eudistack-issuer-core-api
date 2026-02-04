package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListCredentialSerializationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StatusListSignerTest {

    @Mock
    private RemoteSignatureService remoteSignatureService;

    @Mock
    private ObjectMapper objectMapper;

    @Captor
    private ArgumentCaptor<SignatureRequest> signatureRequestCaptor;

    @Test
    void sign_shouldReturnJwt_whenRemoteSignatureSucceeds() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(remoteSignatureService, objectMapper);

        Map<String, Object> payload = Map.of("id", "abc", "foo", "bar");
        String token = "token-123";
        Long listId = 99L;

        String json = "{\"id\":\"abc\",\"foo\":\"bar\"}";
        when(objectMapper.writeValueAsString(payload)).thenReturn(json);

        SignedData signedData = new SignedData(SignatureType.JADES, "jwt-value");

        when(remoteSignatureService.signSystemCredential(any(), eq(token)))
                .thenReturn(Mono.just(signedData));

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectNext("jwt-value")
                .verifyComplete();

        // Verify request contents (light but useful checks)
        verify(remoteSignatureService, times(1)).signSystemCredential(signatureRequestCaptor.capture(), eq(token));
        Object req = signatureRequestCaptor.getValue();

        Object dataValue = readProperty(req, "data");
        assertThat(dataValue).isEqualTo(json);

        Object configValue = readProperty(req, "configuration");
        assertThat(configValue).isNotNull();

        // Using hasToString() instead of toString().isEqualTo()
        Object typeValue = readProperty(configValue, "type");
        assertThat(typeValue).hasToString("JADES");

        Object paramsValue = readProperty(configValue, "parameters");
        assertThat(paramsValue).isInstanceOf(Map.class);
        assertThat((Map<?, ?>) paramsValue).isEmpty();
    }

    @Test
    void sign_shouldWrapRemoteErrorsIntoRemoteSignatureException_withListId() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(remoteSignatureService, objectMapper);

        Map<String, Object> payload = Map.of("a", 1);
        String token = "t";
        Long listId = 123L;

        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"a\":1}");

        RuntimeException remoteError = new RuntimeException("boom");
        when(remoteSignatureService.signSystemCredential(any(), eq(token)))
                .thenReturn(Mono.error(remoteError));

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(RemoteSignatureException.class);
                    assertThat(ex.getMessage()).isEqualTo("Remote signature failed; list ID: " + listId);
                    assertThat(ex.getCause()).isSameAs(remoteError);
                })
                .verify();
    }

    @Test
    void sign_shouldWrapSerializationErrorIntoRemoteSignatureException_andKeepCauseChain() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(remoteSignatureService, objectMapper);

        Map<String, Object> payload = Map.of("a", 1);
        String token = "t";
        Long listId = 777L;

        JsonProcessingException jacksonEx = new JsonProcessingException("json fail") {};
        when(objectMapper.writeValueAsString(payload)).thenThrow(jacksonEx);

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(RemoteSignatureException.class);
                    assertThat(ex.getMessage()).isEqualTo("Remote signature failed; list ID: " + listId);

                    // Cause should be StatusListCredentialSerializationException (mapped in toSignatureRequest)
                    assertThat(ex.getCause()).isInstanceOf(StatusListCredentialSerializationException.class);
                    assertThat(ex.getCause().getCause()).isSameAs(jacksonEx);
                })
                .verify();

        // The remote service must not be called if serialization fails
        verifyNoInteractions(remoteSignatureService);
    }

    @Test
    void sign_shouldErrorWhenRemoteReturnsEmptySignedData() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(remoteSignatureService, objectMapper);

        Map<String, Object> payload = Map.of("a", 1);
        String token = "t";
        Long listId = 5L;

        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"a\":1}");

        when(remoteSignatureService.signSystemCredential(any(), eq(token)))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, "   ")));

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(RemoteSignatureException.class);
                    assertThat(ex.getMessage()).isEqualTo("Remote signer returned empty SignedData; list ID: " + listId);
                    assertThat(ex.getCause()).isNull();
                })
                .verify();
    }

    @Test
    void sign_shouldThrowImmediately_whenPayloadIsNull() {
        // Arrange
        StatusListSigner signer = new StatusListSigner(remoteSignatureService, objectMapper);

        // Act + Assert
        assertThrows(RuntimeException.class, () -> signer.sign(null, "token", 1L));
    }

    @Test
    void sign_shouldThrowImmediately_whenTokenIsNull() {
        // Arrange
        StatusListSigner signer = new StatusListSigner(remoteSignatureService, objectMapper);

        // Act + Assert
        assertThatThrownBy(() -> signer.sign(Map.of("a", 1), null, 1L))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("token");
    }

    /**
     * Reads a property from either:
     * - a Java record component accessor (e.g. data())
     * - a standard getter (e.g. getData())
     */
    private static Object readProperty(Object target, String property) {
        try {
            return tryRecordStyleAccess(target, property);
        } catch (NoSuchMethodException ignored) {
            return tryBeanStyleAccess(target, property);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Object tryRecordStyleAccess(Object target, String property) throws Exception {
        Method recordStyle = target.getClass().getMethod(property);
        return recordStyle.invoke(target);
    }

    private static Object tryBeanStyleAccess(Object target, String property) {
        String getter = "get" + Character.toUpperCase(property.charAt(0)) + property.substring(1);
        try {
            Method beanStyle = target.getClass().getMethod(getter);
            return beanStyle.invoke(target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}