package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.service.impl.PreAuthorizedCodeServiceImpl;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.util.Utils;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.shared.objectmother.PreAuthorizedCodeResponseMother;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PreAuthorizedCodeServiceTest {

    @Mock
    private SecureRandom random;

    @Mock
    private CacheStore<String> txCodeByPreAuthorizedCodeCacheStore;

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

        try (MockedStatic<Utils> mockUtils = mockStatic(Utils.class)) {
            mockUtils.when(Utils::generateCustomNonce)
                    .thenReturn(Mono.just(expectedPreAuthorizedCode));

            when(random.nextInt(9000)).thenReturn(randomNextInt);
            when(txCodeByPreAuthorizedCodeCacheStore.add(anyString(), eq(expectedTxCodeStr)))
                    .thenReturn(Mono.just(expectedPreAuthorizedCode));

            Mono<PreAuthorizedCodeResponse> resultMono = preAuthorizedCodeService
                    .generatePreAuthorizedCode("");

            StepVerifier
                    .create(resultMono)
                    .assertNext(result ->
                            assertThat(result).isEqualTo(expected))
                    .verifyComplete();

            verify(random, times(1))
                    .nextInt(9000);

            verify(txCodeByPreAuthorizedCodeCacheStore, times(1))
                    .add(anyString(), eq(expectedTxCodeStr));
        }
    }
}