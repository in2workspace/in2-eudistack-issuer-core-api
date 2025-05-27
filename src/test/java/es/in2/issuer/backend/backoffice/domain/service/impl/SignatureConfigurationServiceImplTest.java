package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.exception.InvalidSignatureConfigurationException;
import es.in2.issuer.backend.backoffice.domain.exception.NoSuchEntityException;
import es.in2.issuer.backend.backoffice.domain.exception.OrganizationIdentifierMismatchException;
import es.in2.issuer.backend.backoffice.domain.model.dtos.ChangeSet;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CompleteSignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import es.in2.issuer.backend.backoffice.domain.model.entities.CloudProvider;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;
import es.in2.issuer.backend.backoffice.domain.repository.SignatureConfigurationRepository;
import es.in2.issuer.backend.backoffice.domain.service.CloudProviderService;
import es.in2.issuer.backend.backoffice.domain.service.SignatureConfigurationAuditService;
import es.in2.issuer.backend.backoffice.domain.service.VaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignatureConfigurationServiceImplTest {

    @Mock VaultService vaultService;
    @Mock SignatureConfigurationRepository repository;
    @Mock CloudProviderService cloudProviderService;
    @Mock SignatureConfigurationAuditService auditService;
    @Mock ObjectMapper mockObjectMapper;
    @InjectMocks SignatureConfigurationServiceImpl service;

    private static final String ORG = "org-1";
    private static final String CREDENTIAL_PASSWORD = "credentialPassword";
    private static final String CLIENT_SECRET = "clientSecret";
    private static final String SECRET = "secret";
    private static final String SLASH = "/";

    // --- saveSignatureConfig LOCAL mode ---
    @Test
    void saveSignatureConfig_local() {
        CompleteSignatureConfiguration cfg = CompleteSignatureConfiguration.builder()
                .id(null)
                .organizationIdentifier("ignored")
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

        when(repository.save(any(SignatureConfiguration.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        StepVerifier.create(service.saveSignatureConfig(cfg, ORG))
                .assertNext(saved -> {
                    assertThat(saved.getOrganizationIdentifier()).isEqualTo(ORG);
                    assertThat(saved.isEnableRemoteSignature()).isTrue();
                    assertThat(saved.getSignatureMode()).isEqualTo(SignatureMode.LOCAL);
                    assertThat(saved.isNewTransaction()).isTrue();
                    assertThat(saved.getClientId()).isNull();
                    assertThat(saved.getCloudProviderId()).isNull();
                })
                .verifyComplete();

        ArgumentCaptor<SignatureConfiguration> cap = ArgumentCaptor.forClass(SignatureConfiguration.class);
        verify(repository).save(cap.capture());
        assertThat(cap.getValue().getOrganizationIdentifier()).isEqualTo(ORG);
    }

    // --- saveSignatureConfig SERVER mode success ---
    @Test
    void saveSignatureConfig_server_success() {
        CompleteSignatureConfiguration cfg = CompleteSignatureConfiguration.builder()
                .id(null)
                .organizationIdentifier("ignored")
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.SERVER)
                .cloudProviderId(null)
                .clientId(null)
                .credentialId("cred1")
                .credentialName("name1")
                .secretRelativePath(null)
                .clientSecret(null)
                .credentialPassword(null)
                .secret(null)
                .build();

        when(repository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        StepVerifier.create(service.saveSignatureConfig(cfg, ORG))
                .assertNext(saved -> {
                    assertThat(saved.getSignatureMode()).isEqualTo(SignatureMode.SERVER);
                    assertThat(saved.getCredentialId()).isEqualTo("cred1");
                    assertThat(saved.getCredentialName()).isEqualTo("name1");
                })
                .verifyComplete();
    }

    @Test
    void saveSignatureConfig_server_missingFields() {
        CompleteSignatureConfiguration cfg = CompleteSignatureConfiguration.builder()
                .id(null).organizationIdentifier("ignored")
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.SERVER)
                .cloudProviderId(null)
                .clientId(null)              // missing
                .credentialId("cred1")
                .credentialName(null)        // missing
                .secretRelativePath(null)
                .clientSecret(null)
                .credentialPassword(null)
                .secret(null)
                .build();

        StepVerifier.create(service.saveSignatureConfig(cfg, ORG))
                .expectError(InvalidSignatureConfigurationException.class)
                .verify();
    }

    @Test
    void saveSignatureConfig_cloud_success() throws Exception {
        // arrange
        UUID pid = UUID.randomUUID();
        CompleteSignatureConfiguration cfg = CompleteSignatureConfiguration.builder()
                .id(null)
                .organizationIdentifier("ignored")
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.CLOUD)
                .cloudProviderId(pid)
                .clientId("clientX")
                .credentialId("credX")
                .credentialName("nameX")
                .secretRelativePath(null)
                .clientSecret("sec123")
                .credentialPassword("pwd123")
                .secret("totp456")
                .build();


        when(cloudProviderService.requiresTOTP(pid)).thenReturn(Mono.just(true));
        when(vaultService.saveSecrets(anyString(), anyMap())).thenReturn(Mono.empty());
        when(repository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Map<String,String> expectedHashed = new HashMap<>();
        expectedHashed.put(CLIENT_SECRET,    sha256Base64Url("sec123"));
        expectedHashed.put(CREDENTIAL_PASSWORD, sha256Base64Url("pwd123"));
        expectedHashed.put(SECRET,            sha256Base64Url("totp456"));

        String expectedJson = new ObjectMapper().writeValueAsString(expectedHashed);
        when(mockObjectMapper.writeValueAsString(expectedHashed))
                .thenReturn(expectedJson);

        // act + assert
        StepVerifier.create(service.saveSignatureConfig(cfg, ORG))
                .assertNext(saved -> {
                    assertThat(saved.getSignatureMode()).isEqualTo(SignatureMode.CLOUD);
                    assertThat(saved.getClientId()).isEqualTo("clientX");
                    assertThat(saved.getSecretRelativePath()).startsWith(ORG + SLASH);

                    assertThat(saved.getVaultHashedSecretValues()).isEqualTo(expectedJson);
                })
                .verifyComplete();

        verify(vaultService).saveSecrets(startsWith(ORG + SLASH), argThat(map ->
                "sec123".equals(map.get(CLIENT_SECRET)) &&
                        "pwd123".equals(map.get(CREDENTIAL_PASSWORD)) &&
                        "totp456".equals(map.get(SECRET))
        ));
    }

    @Test
    void saveSignatureConfig_cloud_requiresTOTP_butMissingSecret() {
        UUID pid = UUID.randomUUID();
        CompleteSignatureConfiguration cfg = CompleteSignatureConfiguration.builder()
                .id(null).organizationIdentifier("ignored")
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.CLOUD)
                .cloudProviderId(pid)
                .clientId("c")
                .credentialId("d")
                .credentialName("n")
                .secretRelativePath(null)
                .clientSecret("s")
                .credentialPassword("p")
                .secret(null) // missing
                .build();

        when(cloudProviderService.requiresTOTP(pid)).thenReturn(Mono.just(true));

        StepVerifier.create(service.saveSignatureConfig(cfg, ORG))
                .expectError(InvalidSignatureConfigurationException.class)
                .verify();
    }

    // --- getSignatureCredentials ---
    @Test
    void getSignatureCredentials_delegates() {
        Map<String, Object> secrets = Map.of("foo", 42);
        when(vaultService.getSecrets("mypath")).thenReturn(Mono.just(secrets));

        StepVerifier.create(service.getSignatureCredentials("mypath"))
                .assertNext(m -> assertThat(m).containsEntry("foo", 42))
                .verifyComplete();
    }

    // --- findAllByOrganizationIdentifierAndMode ---
    @Test
    void findAllByOrganizationIdentifierAndMode_local() {
        SignatureConfiguration cfg = SignatureConfiguration.builder()
                .id(UUID.randomUUID())
                .organizationIdentifier(ORG)
                .enableRemoteSignature(false)
                .signatureMode(SignatureMode.LOCAL)
                .build();

        when(repository.findAllByOrganizationIdentifierAndSignatureMode(ORG, SignatureMode.LOCAL))
                .thenReturn(Flux.just(cfg));

        StepVerifier.create(service.findAllByOrganizationIdentifierAndMode(ORG, SignatureMode.LOCAL))
                .assertNext(item -> {
                    assertThat(item.id()).isEqualTo(cfg.getId());
                    assertThat(item.cloudProviderName()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void findAllByOrganizationIdentifierAndMode_cloud() {
        UUID pid = UUID.randomUUID();
        SignatureConfiguration cfg = SignatureConfiguration.builder()
                .id(UUID.randomUUID())
                .organizationIdentifier(ORG)
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.CLOUD)
                .cloudProviderId(pid)
                .build();

        when(repository.findAllByOrganizationIdentifierAndSignatureMode(ORG, SignatureMode.CLOUD))
                .thenReturn(Flux.just(cfg));
        when(cloudProviderService.findById(pid))
                .thenReturn(Mono.just(CloudProvider.builder()
                        .id(pid)
                        .provider("ProvName")
                        .url("u")
                        .authMethod("m")
                        .authGrantType("g")
                        .requiresTOTP(false)
                        .build()
                ));

        StepVerifier.create(service.findAllByOrganizationIdentifierAndMode(ORG, SignatureMode.CLOUD))
                .assertNext(item -> {
                    assertThat(item.id()).isEqualTo(cfg.getId());
                    assertThat(item.cloudProviderName()).isEqualTo("ProvName");
                })
                .verifyComplete();
    }

    // --- getCompleteConfigurationById ---
    @Test
    void getCompleteConfigurationById_success() {
        UUID id = UUID.randomUUID();
        SignatureConfiguration cfg = SignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier(ORG)
                .enableRemoteSignature(false)
                .signatureMode(SignatureMode.LOCAL)
                .clientId("cid")
                .credentialId("cred")
                .credentialName("name")
                .build();

        when(repository.findById(id)).thenReturn(Mono.just(cfg));

        StepVerifier.create(service.getCompleteConfigurationById(id.toString(), ORG))
                .assertNext(resp -> {
                    assertThat(resp.id()).isEqualTo(id);
                    assertThat(resp.organizationIdentifier()).isEqualTo(ORG);
                    assertThat(resp.signatureMode()).isEqualTo(SignatureMode.LOCAL);
                })
                .verifyComplete();
    }

    @Test
    void getCompleteConfigurationById_invalidUuid() {
        StepVerifier.create(service.getCompleteConfigurationById("no-uuid", ORG))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void getCompleteConfigurationById_notFound() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Mono.empty());

        StepVerifier.create(service.getCompleteConfigurationById(id.toString(), ORG))
                .expectError(NoSuchEntityException.class)
                .verify();
    }

    @Test
    void getCompleteConfigurationById_orgMismatch() {
        UUID id = UUID.randomUUID();
        SignatureConfiguration cfg = SignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier("other")
                .build();

        when(repository.findById(id)).thenReturn(Mono.just(cfg));

        StepVerifier.create(service.getCompleteConfigurationById(id.toString(), ORG))
                .expectError(OrganizationIdentifierMismatchException.class)
                .verify();
    }

    // --- deleteSignatureConfiguration ---
    @Test
    void deleteSignatureConfiguration_success() {
        UUID id = UUID.randomUUID();
        SignatureConfiguration cfg = SignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier(ORG)
                .secretRelativePath("path/1")
                .build();

        when(repository.findById(id)).thenReturn(Mono.just(cfg));
        when(vaultService.deleteSecret("path/1")).thenReturn(Mono.empty());
        when(repository.deleteById(id)).thenReturn(Mono.empty());
        when(auditService.saveDeletionAudit(any(SignatureConfigurationResponse.class), eq("r"), eq("u")))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.deleteSignatureConfiguration(id.toString(), ORG, "r", "u"))
                .verifyComplete();

        verify(vaultService).deleteSecret("path/1");
        verify(repository).deleteById(id);
        verify(auditService).saveDeletionAudit(any(SignatureConfigurationResponse.class), eq("r"), eq("u"));
    }

    @Test
    void updateSignatureConfiguration_patchesSecrets_and_savesAndAudits() throws JsonProcessingException {
        // arrange
        UUID id = UUID.randomUUID();
        String path = ORG + SLASH + id;
        SignatureConfiguration existing = SignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier(ORG)
                .secretRelativePath(path)
                .vaultHashedSecretValues(null)
                .build();

        when(repository.findById(id)).thenReturn(Mono.just(existing));

        when(vaultService.patchSecrets(eq(path), anyMap()))
                .thenReturn(Mono.empty());
        when(repository.save(any()))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Now auditService expects a ChangeSet, not the DTO:
        when(auditService.saveAudit(
                any(SignatureConfigurationResponse.class),
                any(ChangeSet.class),
                eq("rationale"),
                eq("user@mail")
        )).thenReturn(Mono.empty());

        String fakeJson = "{\"dummy\":\"h\"}";
        when(mockObjectMapper.writeValueAsString(anyMap()))
                .thenReturn(fakeJson);

        CompleteSignatureConfiguration newCfg = CompleteSignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier(ORG)
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.SERVER)
                .cloudProviderId(UUID.randomUUID())
                .clientId("c")
                .credentialId("cid")
                .credentialName("cname")
                .secretRelativePath(null)
                .clientSecret("sec1")
                .credentialPassword("pass1")
                .secret("totp1")
                .build();

        // act
        Mono<Void> result = service.updateSignatureConfiguration(
                id.toString(), ORG, newCfg, "rationale", "user@mail"
        );

        // assert
        StepVerifier.create(result)
                .verifyComplete();

        // Vault was patched with the plain secrets:
        verify(vaultService).patchSecrets(eq(path), argThat(map ->
                "sec1".equals(map.get(CLIENT_SECRET)) &&
                        "pass1".equals(map.get(CREDENTIAL_PASSWORD)) &&
                        "totp1".equals(map.get(SECRET))
        ));

        // Repository save includes the fakeJson for the updated hash JSON:
        ArgumentCaptor<SignatureConfiguration> saveCap =
                ArgumentCaptor.forClass(SignatureConfiguration.class);
        verify(repository).save(saveCap.capture());
        SignatureConfiguration saved = saveCap.getValue();
        assertThat(saved.getVaultHashedSecretValues()).isEqualTo(fakeJson);
        assertThat(saved.getClientId()).isEqualTo("c");
        assertThat(saved.getCredentialName()).isEqualTo("cname");

        // Capture the ChangeSet passed to auditService:
        ArgumentCaptor<ChangeSet> csCap =
                ArgumentCaptor.forClass(ChangeSet.class);
        ArgumentCaptor<SignatureConfigurationResponse> oldRespCap =
                ArgumentCaptor.forClass(SignatureConfigurationResponse.class);

        verify(auditService).saveAudit(
                oldRespCap.capture(),
                csCap.capture(),
                eq("rationale"),
                eq("user@mail")
        );

        SignatureConfigurationResponse oldResp = oldRespCap.getValue();
        assertThat(oldResp.id()).isEqualTo(id);
        assertThat(oldResp.organizationIdentifier()).isEqualTo(ORG);

        ChangeSet cs = csCap.getValue();
        // The ChangeSet.newValues() should contain only the fields that changed:
        assertThat(cs.newValues())
                .containsEntry("clientId", "c")
                .containsEntry("credentialId", "cid")
                .containsEntry("credentialName", "cname")
                .containsEntry("vaultHashedSecretValues", fakeJson);
    }

    // helper to compute the same SHA-256 + Base64URL without padding
    private static String sha256Base64Url(String value) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

