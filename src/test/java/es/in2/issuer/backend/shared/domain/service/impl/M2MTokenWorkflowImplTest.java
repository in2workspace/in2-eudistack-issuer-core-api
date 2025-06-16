package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.VerifierOauth2AccessToken;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Base64;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CLIENT_ASSERTION_TYPE_VALUE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.CLIENT_CREDENTIALS_GRANT_TYPE_VALUE;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class M2MTokenWorkflowImplTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private VerifierService verifierService;

    @InjectMocks
    private M2MTokenServiceImpl m2MTokenService;

    private String clientId;

    @BeforeEach
    void setUp() {
        // Valores comunes para las pruebas
        clientId = "did:example:123456789";
        String verifierUrl = "https://verifier.example.com";
        String jwtCredential = Base64.getEncoder().encodeToString("vc_jwt_content".getBytes());

        // Configurar AppConfig
        when(appConfig.getCredentialSubjectDidKey()).thenReturn(clientId);
        when(appConfig.getJwtCredential()).thenReturn(jwtCredential);

        // Configurar VerifierConfig
        when(appConfig.getVerifierUrl()).thenReturn(verifierUrl);
    }

    @Test
    void getM2MToken_shouldReturnVerifierOauth2AccessToken() {
        // Arrange
        String vcMachineString = "vc_jwt_content";

        when(appConfig.getJwtCredential()).thenReturn(Base64.getEncoder().encodeToString(vcMachineString.getBytes()));

        // Mock de jwtService.generateJWT()
        String vpTokenJWTString = "vp_token_jwt_string";
        String clientAssertionJWT = "generated_client_assertion_jwt";
        when(jwtService.generateJWT(anyString()))
                .thenReturn(vpTokenJWTString)  // Primero para vpTokenJWT
                .thenReturn(clientAssertionJWT); // Luego para client assertion

        // Preparar el cuerpo de la solicitud esperado
        String expectedFormUrlEncodedBody = OAuth2ParameterNames.GRANT_TYPE + "=" + CLIENT_CREDENTIALS_GRANT_TYPE_VALUE + "&" +
                OAuth2ParameterNames.CLIENT_ID + "=" + clientId + "&" +
                OAuth2ParameterNames.CLIENT_ASSERTION_TYPE + "=" + CLIENT_ASSERTION_TYPE_VALUE + "&" +
                OAuth2ParameterNames.CLIENT_ASSERTION + "=" + clientAssertionJWT;

        // Mock de verifierService.performTokenRequest()
        VerifierOauth2AccessToken expectedToken = new VerifierOauth2AccessToken("access_token_value", "Bearer", "3600");
        when(verifierService.performTokenRequest(expectedFormUrlEncodedBody)).thenReturn(Mono.just(expectedToken));

        // Act
        Mono<VerifierOauth2AccessToken> result = m2MTokenService.getM2MToken();

        // Assert
        StepVerifier.create(result)
                .expectNext(expectedToken)
                .verifyComplete();

        // Verificar interacciones
        verify(appConfig).getJwtCredential();
        verify(appConfig, times(2)).getCredentialSubjectDidKey();

        verify(appConfig).getVerifierUrl();

        verify(jwtService, times(2)).generateJWT(anyString());

        verify(verifierService).performTokenRequest(expectedFormUrlEncodedBody);

        verifyNoMoreInteractions(appConfig, jwtService, verifierService);
    }

    @Test
    void getM2MToken_whenVerifierServiceReturnsError_shouldPropagateError() {
        // Arrange
        String vcMachineString = "vc_jwt_content";

        when(appConfig.getJwtCredential()).thenReturn(Base64.getEncoder().encodeToString(vcMachineString.getBytes()));

        // Mock de jwtService.generateJWT()
        String vpTokenJWTString = "vp_token_jwt_string";
        String clientAssertionJWT = "generated_client_assertion_jwt";
        when(jwtService.generateJWT(anyString()))
                .thenReturn(vpTokenJWTString)
                .thenReturn(clientAssertionJWT);

        // Preparar el cuerpo de la solicitud esperado
        String expectedFormUrlEncodedBody = OAuth2ParameterNames.GRANT_TYPE + "=" + CLIENT_CREDENTIALS_GRANT_TYPE_VALUE + "&" +
                OAuth2ParameterNames.CLIENT_ID + "=" + clientId + "&" +
                OAuth2ParameterNames.CLIENT_ASSERTION_TYPE + "=" + CLIENT_ASSERTION_TYPE_VALUE + "&" +
                OAuth2ParameterNames.CLIENT_ASSERTION + "=" + clientAssertionJWT;

        // Mock de verifierService.performTokenRequest() para retornar un error
        when(verifierService.performTokenRequest(expectedFormUrlEncodedBody))
                .thenReturn(Mono.error(new RuntimeException("Verifier service error")));

        // Act
        Mono<VerifierOauth2AccessToken> result = m2MTokenService.getM2MToken();

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                        throwable.getMessage().equals("Verifier service error"))
                .verify();

        // Verificar interacciones (similar a la prueba anterior)
        verify(appConfig).getJwtCredential();
        verify(appConfig, times(2)).getCredentialSubjectDidKey();

        verify(appConfig).getVerifierUrl();

        verify(verifierService).performTokenRequest(expectedFormUrlEncodedBody);

        verifyNoMoreInteractions(appConfig, jwtService, verifierService);
    }
}