//package es.in2.issuer.backend.oidc4vci.application.workflow;
//
//import es.in2.issuer.backend.oidc4vci.application.workflow.impl.PreAuthorizedCodeWorkflowImpl;
//import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
//import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
////import es.in2.issuer.backend.shared.objectmother.PreAuthorizedCodeResponseMother;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.ArgumentCaptor;
//import org.mockito.Captor;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.junit.jupiter.MockitoExtension;
//import reactor.core.publisher.Mono;
//import reactor.test.StepVerifier;
//
//import java.util.UUID;
//
//import static org.assertj.core.api.Assertions.assertThat;
//import static org.mockito.ArgumentMatchers.anyString;
//import static org.mockito.Mockito.*;
//
//@ExtendWith(MockitoExtension.class)
//class PreAuthorizedCodeWorkflowTest {
//    @Mock
//    private PreAuthorizedCodeService preAuthorizedCodeService;
//
//    @InjectMocks
//    PreAuthorizedCodeWorkflowImpl preAuthorizedCodeWorkflow;
//
//    @Captor
//    private ArgumentCaptor<Mono<UUID>> credentialIdCaptor;
//
//    @Test
//    void itShouldReturnPreAuthorizedCode() {
//        PreAuthorizedCodeResponse expected = PreAuthorizedCodeResponseMother.dummy();
//        UUID credentialId = UUID.fromString("cfcd6d7c-5cc2-4601-a992-86f96afb0706");
//
//        when(preAuthorizedCodeService.generatePreAuthorizedCode(anyString(), any()))
//                .thenReturn(Mono.just(expected));
//
//        Mono<PreAuthorizedCodeResponse> resultMono = preAuthorizedCodeWorkflow
//                .generatePreAuthorizedCode(
//                        Mono.just(credentialId));
//
//        StepVerifier
//                .create(resultMono)
//                .assertNext(result ->
//                        assertThat(result).isEqualTo(expected))
//                .verifyComplete();
//
//        verify(preAuthorizedCodeService, times(1))
//                .generatePreAuthorizedCode(anyString(), credentialIdCaptor.capture());
//        verifyNoMoreInteractions(preAuthorizedCodeService);
//        StepVerifier
//                .create(credentialIdCaptor.getValue())
//                .assertNext(passedCredentialId -> assertThat(passedCredentialId)
//                        .isEqualTo(credentialId))
//                .verifyComplete();
//    }
//}