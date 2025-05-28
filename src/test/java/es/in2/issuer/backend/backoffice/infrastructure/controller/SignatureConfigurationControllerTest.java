package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.exception.MissingRequiredDataException;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CompleteSignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigWithProviderName;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import es.in2.issuer.backend.backoffice.domain.model.dtos.UpdateSignatureConfigurationRequest;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;
import es.in2.issuer.backend.backoffice.domain.service.SignatureConfigurationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignatureConfigurationControllerTest {

    @Mock
    SignatureConfigurationService signatureConfigurationService;

    @Mock
    AccessTokenService accessTokenService;

    @InjectMocks
    SignatureConfigurationController controller;

    private static final String AUTH = "Bearer token";
    private static final String ORG_ID = "org-ABC";
    private static final UUID CONFIG_ID = UUID.randomUUID();

    private CompleteSignatureConfiguration sampleConfig;
    private SignatureConfiguration sampleSavedEntity;
    private SignatureConfigWithProviderName sampleWithProvider;
    private SignatureConfigurationResponse sampleResponse;

    @BeforeEach
    void setUp() {
        sampleConfig = CompleteSignatureConfiguration.builder()
                .id(null)
                .organizationIdentifier(ORG_ID)
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.LOCAL)
                .cloudProviderId(null)
                .clientId(null)
                .credentialId(null)
                .credentialName(null)
                .secretRelativePath(null)
                .clientSecret(null)
                .credentialPassword(null)
                .secret(null)
                .build();

        sampleSavedEntity = SignatureConfiguration.builder()
                .id(CONFIG_ID)
                .organizationIdentifier(ORG_ID)
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.LOCAL)
                .build();

        sampleWithProvider = new SignatureConfigWithProviderName(
                CONFIG_ID, ORG_ID, true, SignatureMode.LOCAL,
                null, null, null, null
        );

        sampleResponse = SignatureConfigurationResponse.builder()
                .id(CONFIG_ID)
                .organizationIdentifier(ORG_ID)
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.LOCAL)
                .cloudProviderId(null)
                .clientId(null)
                .credentialId(null)
                .credentialName(null)
                .build();
    }

    @Test
    void createSignatureConfiguration_success() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG_ID));
        when(signatureConfigurationService.saveSignatureConfig(sampleConfig, ORG_ID))
                .thenReturn(Mono.just(sampleSavedEntity));

        Mono<SignatureConfiguration> result =
                controller.createSignatureConfiguration(AUTH, sampleConfig);

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertThat(resp).isEqualTo(sampleSavedEntity);
                })
                .verifyComplete();

        verify(accessTokenService).getOrganizationId(AUTH);
        verify(signatureConfigurationService).saveSignatureConfig(sampleConfig, ORG_ID);
    }

    @Test
    void createSignatureConfiguration_accessTokenError() {
        when(accessTokenService.getOrganizationId(AUTH))
                .thenReturn(Mono.error(new RuntimeException("no auth")));

        StepVerifier.create(controller.createSignatureConfiguration(AUTH, sampleConfig))
                .expectErrorMatches(e ->
                        e instanceof RuntimeException && e.getMessage().equals("no auth")
                )
                .verify();
    }

    @Test
    void getAllSignatureConfigurations_success() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG_ID));
        when(signatureConfigurationService.findAllByOrganizationIdentifierAndMode(ORG_ID, SignatureMode.CLOUD))
                .thenReturn(Flux.just(sampleWithProvider));

        Flux<SignatureConfigWithProviderName> result =
                controller.getAllSignatureConfigurations(AUTH, SignatureMode.CLOUD);

        StepVerifier.create(result)
                .assertNext(item -> assertThat(item).isEqualTo(sampleWithProvider))
                .verifyComplete();

        verify(accessTokenService).getOrganizationId(AUTH);
    }

    @Test
    void getCompleteConfigurationById_found() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG_ID));
        when(signatureConfigurationService.getCompleteConfigurationById(CONFIG_ID.toString(), ORG_ID))
                .thenReturn(Mono.just(sampleResponse));

        Mono<ResponseEntity<SignatureConfigurationResponse>> result =
                controller.getCompleteConfigurationById(AUTH, CONFIG_ID.toString());

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(resp.getBody()).isEqualTo(sampleResponse);
                })
                .verifyComplete();

        verify(accessTokenService).getOrganizationId(AUTH);
    }

    @Test
    void getCompleteConfigurationById_notFound() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG_ID));
        when(signatureConfigurationService.getCompleteConfigurationById(CONFIG_ID.toString(), ORG_ID))
                .thenReturn(Mono.empty());

        Mono<ResponseEntity<SignatureConfigurationResponse>> result =
                controller.getCompleteConfigurationById(AUTH, CONFIG_ID.toString());

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(resp.getBody()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void updateSignatureConfiguration_missingRationale() {
        UpdateSignatureConfigurationRequest req = new UpdateSignatureConfigurationRequest(
                null, null, null, null, null, null, null, null, null, null,null,null,null);

        StepVerifier.create(controller.updateSignatureConfiguration(AUTH, CONFIG_ID.toString(), req))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(MissingRequiredDataException.class))
                .verify();
    }

    @Test
    void updateSignatureConfiguration_success() {
        UpdateSignatureConfigurationRequest req = new UpdateSignatureConfigurationRequest(
                null, null, null, null, null, null, null, null, null, "user@e.com", null, null, "reason"
        );
        CompleteSignatureConfiguration toComplete = req.toCompleteSignatureConfiguration();

        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG_ID));
        when(accessTokenService.getMandateeEmail(AUTH)).thenReturn(Mono.just("user@e.com"));
        when(signatureConfigurationService.updateSignatureConfiguration(
                CONFIG_ID.toString(), ORG_ID, toComplete, "reason", "user@e.com"))
                .thenReturn(Mono.empty());

        Mono<Void> result = controller.updateSignatureConfiguration(AUTH, CONFIG_ID.toString(), req);

        StepVerifier.create(result)
                .verifyComplete();

        verify(signatureConfigurationService)
                .updateSignatureConfiguration(CONFIG_ID.toString(), ORG_ID, toComplete, "reason", "user@e.com");
    }

    @Test
    void deleteSignatureConfiguration_success() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG_ID));
        when(accessTokenService.getMandateeEmail(AUTH)).thenReturn(Mono.just("user@e.com"));
        when(signatureConfigurationService.deleteSignatureConfiguration(
                CONFIG_ID.toString(), ORG_ID, "delReason", "user@e.com"))
                .thenReturn(Mono.empty());

        Mono<Void> result = controller.deleteSignatureConfiguration(AUTH, CONFIG_ID.toString(), "delReason");

        StepVerifier.create(result)
                .verifyComplete();

        verify(signatureConfigurationService)
                .deleteSignatureConfiguration(CONFIG_ID.toString(), ORG_ID, "delReason", "user@e.com");
    }
}

