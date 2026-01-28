package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.service.NotificationService;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationControllerTest {

    @Mock
    private NotificationService notificationService;

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private NotificationController notificationController;

    @Test
    void handleNotification_ok_shouldCleanBearerAndCallService_andComplete() {
        // given
        NotificationRequest request = mock(NotificationRequest.class);
        String authorization = "Bearer abc.def.ghi";
        String cleanToken = "abc.def.ghi";

        when(accessTokenService.getCleanBearerToken(authorization)).thenReturn(Mono.just(cleanToken));
        when(notificationService.handleNotification(anyString(), eq(request))).thenReturn(Mono.empty());

        // when
        Mono<Void> result = notificationController.handleNotification(request, authorization);

        // then
        StepVerifier.create(result).verifyComplete();

        verify(accessTokenService).getCleanBearerToken(authorization);

        ArgumentCaptor<String> processIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(notificationService).handleNotification(processIdCaptor.capture(), eq(request));

        String processId = processIdCaptor.getValue();
        assertNotNull(processId);
        assertFalse(processId.isBlank());

        UUID parsed = UUID.fromString(processId);
        assertNotNull(parsed);

        verifyNoMoreInteractions(accessTokenService, notificationService);
    }

    @Test
    void handleNotification_whenBearerCleaningFails_shouldError_andNotCallNotificationService() {
        // given
        NotificationRequest request = mock(NotificationRequest.class);
        String authorization = "Bearer whatever";
        RuntimeException error = new RuntimeException("invalid auth header");

        when(accessTokenService.getCleanBearerToken(authorization)).thenReturn(Mono.error(error));

        // when
        Mono<Void> result = notificationController.handleNotification(request, authorization);

        // then
        StepVerifier.create(result)
                .expectErrorSatisfies(e -> assertFalse(e.getMessage().isBlank()))
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorization);
        verifyNoInteractions(notificationService);
        verifyNoMoreInteractions(accessTokenService);
    }

    @Test
    void handleNotification_whenNotificationServiceFails_shouldError() {
        // given
        NotificationRequest request = mock(NotificationRequest.class);
        String authorization = "Bearer token";
        String cleanToken = "token";
        RuntimeException error = new RuntimeException("service failed");

        when(accessTokenService.getCleanBearerToken(authorization)).thenReturn(Mono.just(cleanToken));
        when(notificationService.handleNotification(anyString(), eq(request))).thenReturn(Mono.error(error));

        // when
        Mono<Void> result = notificationController.handleNotification(request, authorization);

        // then
        StepVerifier.create(result)
                .expectErrorSatisfies(e -> assertFalse(e.getMessage().isBlank()))
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorization);
        verify(notificationService).handleNotification(anyString(), eq(request));
        verifyNoMoreInteractions(accessTokenService, notificationService);
    }
}
