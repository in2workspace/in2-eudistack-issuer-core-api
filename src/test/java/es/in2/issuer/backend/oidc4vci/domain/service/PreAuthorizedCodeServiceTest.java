package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.service.impl.PreAuthorizedCodeServiceImpl;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialIdAndTxCode;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.shared.objectmother.PreAuthorizedCodeResponseMother;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.security.SecureRandom;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PreAuthorizedCodeServiceTest {

    @Mock
    private SecureRandom random;

    @Mock
    private CacheStore<CredentialIdAndTxCode> credentialIdAndTxCodeByPreAuthorizedCodeCacheStore;

    @InjectMocks
    private PreAuthorizedCodeServiceImpl preAuthorizedCodeService;

    @Test
    void itShouldReturnPreAuthorizedCode() {
        String expectedPreAuthorizedCode = "1234";
        int randomNextInt = 5678;
        int expectedTxCode = randomNextInt + 1000;
        String expectedTxCodeStr = String.valueOf(expectedTxCode);
        PreAuthorizedCodeResponse expected =
                PreAuthorizedCodeResponseMother
                        .withPreAuthorizedCodeAndPin(expectedPreAuthorizedCode, expectedTxCodeStr);
        UUID credentialId = UUID.fromString("2e10cbfc-b381-45ec-b987-0b1dd4ae4e10");

        when(random.nextInt(9000)).thenReturn(randomNextInt);
        when(credentialIdAndTxCodeByPreAuthorizedCodeCacheStore.add(anyString(), eq(new CredentialIdAndTxCode(credentialId, expectedTxCodeStr))))
                .thenReturn(Mono.just(expectedPreAuthorizedCode));

        Mono<PreAuthorizedCodeResponse> resultMono = preAuthorizedCodeService
                .generatePreAuthorizedCode("", Mono.just(credentialId));

        StepVerifier
                .create(resultMono)
                .assertNext(result ->
                        assertThat(result).isEqualTo(expected))
                .verifyComplete();

        verify(random, times(1))
                .nextInt(9000);

        verify(credentialIdAndTxCodeByPreAuthorizedCodeCacheStore, times(1))
                .add(anyString(), eq(new CredentialIdAndTxCode(credentialId, expectedTxCodeStr)));
    }
}