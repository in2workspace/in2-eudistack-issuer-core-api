package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.service.NonceValidationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NonceValidationWorkflowImplTest {

    @Mock
    private NonceValidationService nonceValidationService;

    @InjectMocks
    private NonceValidationWorkflowImpl nonceValidationWorkflow;

    @Captor
    private ArgumentCaptor<Mono<String>> validNonceArgumentCaptor;

    @Test
    void shouldReturnTrueWhenNonceIsValid() {
        String validNonce = "12345";
        when(nonceValidationService.isValid(anyString(), any()))
                .thenReturn(Mono.just(true));

        StepVerifier.create(nonceValidationWorkflow.isValid(Mono.just(validNonce)))
                .assertNext(result -> assertThat(result).isTrue())
                .verifyComplete();

        verify(nonceValidationService, times(1)).isValid(
                anyString(),
                validNonceArgumentCaptor.capture());

        StepVerifier
                .create(validNonceArgumentCaptor.getValue())
                .assertNext(validNonceResult ->
                        assertThat(validNonceResult).isEqualTo(validNonce));
    }
}