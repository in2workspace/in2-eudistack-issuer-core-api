package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.exception.InvalidSignatureConfigurationException;
import es.in2.issuer.backend.backoffice.domain.exception.MissingRequiredDataException;
import es.in2.issuer.backend.backoffice.domain.exception.NoSuchEntityException;
import es.in2.issuer.backend.backoffice.domain.exception.OrganizationIdentifierMismatchException;
import es.in2.issuer.backend.backoffice.domain.model.dtos.ChangeSet;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CompleteSignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigWithProviderName;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;
import es.in2.issuer.backend.backoffice.domain.repository.SignatureConfigurationRepository;
import es.in2.issuer.backend.backoffice.domain.service.CloudProviderService;
import es.in2.issuer.backend.backoffice.domain.service.SignatureConfigurationAuditService;
import es.in2.issuer.backend.backoffice.domain.service.SignatureConfigurationService;
import es.in2.issuer.backend.backoffice.domain.service.VaultService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Slf4j
@RequiredArgsConstructor
public class SignatureConfigurationServiceImpl implements SignatureConfigurationService {
    private final VaultService vaultService;
    private final SignatureConfigurationRepository repository;
    private final CloudProviderService cloudProviderService;
    private final SignatureConfigurationAuditService signatureConfigurationAuditService;
    private final ObjectMapper objectMapper;

    private static final String CREDENTIAL_PASSWORD = "credentialPassword";
    private static final String CLIENT_SECRET = "clientSecret";
    private static final String SECRET = "secret";
    private static final String SLASH = "/";

    @Override
    public Mono<SignatureConfiguration> saveSignatureConfig(
            CompleteSignatureConfiguration config,
            String organizationIdentifier) {

        validateBasicConfig(config);

        UUID generatedId = UUID.randomUUID();
        String secretRelativePath = organizationIdentifier + SLASH + generatedId;
        SignatureConfiguration baseConfig = buildBaseConfig(config, organizationIdentifier, generatedId);

        return switch (config.signatureMode()) {
            case CLOUD   -> handleCloudMode(config, baseConfig, secretRelativePath);
            case SERVER  -> handleServerMode(config, baseConfig);
            case LOCAL   -> repository.save(baseConfig);
        };
    }

    private void validateBasicConfig(CompleteSignatureConfiguration config) {
        if (config.signatureMode() == null) {
            throw new MissingRequiredDataException("SignatureMode must not be null");
        }
        if (Boolean.FALSE.equals(config.enableRemoteSignature()) && config.signatureMode() != SignatureMode.LOCAL) {
            throw new InvalidSignatureConfigurationException(
                    "Remote signature must be enabled for SERVER or CLOUD modes"
            );
        }
    }

    private SignatureConfiguration buildBaseConfig(
            CompleteSignatureConfiguration config,
            String orgId,
            UUID id) {

        return SignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier(orgId)
                .enableRemoteSignature(config.enableRemoteSignature())
                .signatureMode(config.signatureMode())
                .newTransaction(true)
                .build();
    }

    //--- CLOUD mode ---
    private Mono<SignatureConfiguration> handleCloudMode(
            CompleteSignatureConfiguration config,
            SignatureConfiguration signatureConfigData,
            String secretRelativePath) {

        // Validate required fields for CLOUD mode
        if ( Stream.of(
                config.clientId(),
                config.clientSecret(),
                config.credentialId(),
                config.credentialName(),
                config.credentialPassword(),
                config.cloudProviderId()
        ).anyMatch(Objects::isNull) ) {
            return Mono.error(new InvalidSignatureConfigurationException(
                    "Secret (TOTP) is required by the provider"
            ));
        }

        signatureConfigData.setClientId(config.clientId());
        signatureConfigData.setCredentialId(config.credentialId());
        signatureConfigData.setCredentialName(config.credentialName());
        signatureConfigData.setCloudProviderId(config.cloudProviderId());
        signatureConfigData.setSecretRelativePath(secretRelativePath);

        // Flow to check if TOTP is required and save secrets
        return cloudProviderService.requiresTOTP(config.cloudProviderId())
                .switchIfEmpty(Mono.error(new InvalidSignatureConfigurationException(
                        "Cloud provider not found")))
                .flatMap(requiresTOTP -> {
                    if (Boolean.TRUE.equals(requiresTOTP) && config.secret() == null) {
                        return Mono.error(new InvalidSignatureConfigurationException(
                                "Secret (TOTP) is required by the provider"
                        ));
                    }
                    Map<String, String> secrets = new HashMap<>();
                    secrets.put(CLIENT_SECRET, config.clientSecret());
                    secrets.put(CREDENTIAL_PASSWORD, config.credentialPassword());
                    if (Boolean.TRUE.equals(requiresTOTP)) {
                        secrets.put(SECRET, config.secret());
                    }

                    return vaultService
                            .saveSecrets(secretRelativePath, secrets)
                            .then(Mono.fromSupplier(() -> {
                                // Calculate hashes
                                Map<String, String> hashed = secrets.entrySet().stream()
                                        .collect(Collectors.toMap(
                                                Map.Entry::getKey,
                                                e -> hashS256(e.getValue())
                                        ));
                                try {
                                    String json = objectMapper.writeValueAsString(hashed);
                                    signatureConfigData.setVaultHashedSecretValues(json);
                                } catch (JsonProcessingException ex) {
                                    throw new IllegalStateException("Error serializing hashes", ex);
                                }
                                return signatureConfigData;
                            }))
                            .flatMap(repository::save);
                });
    }

    //--- SERVER mode ---
    private Mono<SignatureConfiguration> handleServerMode(
            CompleteSignatureConfiguration config,
            SignatureConfiguration signatureConfigData) {

        if (config.credentialId() == null || config.credentialName() == null) {
            return Mono.error(new InvalidSignatureConfigurationException(
                    "Missing required fields for SERVER mode"
            ));
        }
        signatureConfigData.setCredentialId(config.credentialId());
        signatureConfigData.setCredentialName(config.credentialName());
        return repository.save(signatureConfigData);
    }

    @Override
    public Mono<Map<String, Object>> getSignatureCredentials(String secretRelativePath) {
        return vaultService.getSecrets(secretRelativePath);
    }

    @Override
    public Flux<SignatureConfigWithProviderName> findAllByOrganizationIdentifierAndMode(String organizationIdentifier, SignatureMode signatureMode) {
        Flux<SignatureConfiguration> configs = (signatureMode != null)
                ? repository.findAllByOrganizationIdentifierAndSignatureMode(organizationIdentifier, signatureMode)
                : repository.findAllByOrganizationIdentifier(organizationIdentifier);

        return configs.flatMap(config -> {
            if (config.getCloudProviderId() == null) {
                return Mono.just(mapToWithProviderName(config, null));
            }

            return cloudProviderService.findById(config.getCloudProviderId())
                    .map(provider -> mapToWithProviderName(config, provider.getProvider()));
        });
    }

    @Override
    public Mono<SignatureConfigurationResponse> getCompleteConfigurationById(String id, String organizationId) {
        UUID uuid;
        try {
            uuid = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            log.error("Invalid UUID format: {}", id, e);
            return Mono.error(new IllegalArgumentException("Invalid UUID format: " + id));
        }

        return loadAndValidateEntity(uuid, organizationId)
                .flatMap(this::mapToSignatureConfigurationResponse);
    }

    @Override
    public Mono<Void> updateSignatureConfiguration(
            String id,
            String organizationId,
            CompleteSignatureConfiguration newConfig,
            String rationale,
            String userEmail) {

        UUID configId = UUID.fromString(id);

        // 1) Load and validate the existing entity
        return loadAndValidateEntity(configId, organizationId)
                .flatMap(existing ->
                        // 2) Asynchronously get the old snapshot DTO
                        mapToSignatureConfigurationResponse(existing)
                                .flatMap(oldSnapshot -> {
                                    // 3) Merge non-secret DTO fields into a copy
                                    SignatureConfiguration merged = mergeEntityWithDto(existing, newConfig);

                                    // 4) Patch Vault if secrets changed, updating merged.vaultHashedSecretValues
                                    return patchSecretsIfNeeded(merged, newConfig)
                                            .flatMap(fullyMerged ->
                                                    // 5) Compute the diff between original and fully merged
                                                    Mono.just(diffEntities(existing, fullyMerged))
                                                            .flatMap(changes ->
                                                                    // 6) Persist the fully merged entity
                                                                    repository.save(fullyMerged)
                                                                            // 7) Audit using the oldSnapshot Mono and new snapshot DTO
                                                                            .flatMap(saved ->
                                                                                    mapToSignatureConfigurationResponse(saved)
                                                                                            .flatMap(newSnapshot ->
                                                                                                    signatureConfigurationAuditService.saveAudit(
                                                                                                            oldSnapshot,
                                                                                                            changes,
                                                                                                            rationale,
                                                                                                            userEmail
                                                                                                    )
                                                                                            )
                                                                            )
                                                            )
                                            );
                                })
                )
                .then();
    }


    /**
     * Copies the existing entity, then overrides any non-null DTO fields.
     * Secrets are not stored here; they are applied in patchSecretsIfNeeded().
     */
    private SignatureConfiguration mergeEntityWithDto(
            SignatureConfiguration existing,
            CompleteSignatureConfiguration dto) {

        // Copy everything from the existing entity
        SignatureConfiguration copy = SignatureConfiguration.builder()
                .id(existing.getId())
                .organizationIdentifier(existing.getOrganizationIdentifier())
                .secretRelativePath(existing.getSecretRelativePath())
                .vaultHashedSecretValues(existing.getVaultHashedSecretValues())
                .enableRemoteSignature(existing.isEnableRemoteSignature())
                .signatureMode(existing.getSignatureMode())
                .cloudProviderId(existing.getCloudProviderId())
                .clientId(existing.getClientId())
                .credentialId(existing.getCredentialId())
                .credentialName(existing.getCredentialName())
                .newTransaction(false)
                .build();

        // Override only DTO fields that are non-null
        if (dto.enableRemoteSignature() != null) {
            copy.setEnableRemoteSignature(dto.enableRemoteSignature());
        }
        if (dto.signatureMode() != null) {
            copy.setSignatureMode(dto.signatureMode());
        }
        if (dto.cloudProviderId() != null) {
            copy.setCloudProviderId(dto.cloudProviderId());
        }
        if (dto.clientId() != null) {
            copy.setClientId(dto.clientId());
        }
        if (dto.credentialId() != null) {
            copy.setCredentialId(dto.credentialId());
        }
        if (dto.credentialName() != null) {
            copy.setCredentialName(dto.credentialName());
        }

        return copy;
    }

    /**
     * Reads the JSON map of old hashes from the entity.
     */
    private Map<String,String> readExistingHashes(SignatureConfiguration entity) {
        if (entity.getVaultHashedSecretValues() == null) {
            return Collections.emptyMap();
        }
        try {
            return objectMapper.readValue(
                    entity.getVaultHashedSecretValues(),
                    new TypeReference<Map<String,String>>() {});
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Error parsing existing hashes", e);
        }
    }

    /**
     * Compares S256 hashes of secrets in newConfig against the existing
     * mergedEntity.vaultHashedSecretValues. If any differ, patches Vault
     * and updates mergedEntity.vaultHashedSecretValues. Returns the mergedEntity.
     */
    private Mono<SignatureConfiguration> patchSecretsIfNeeded(
            SignatureConfiguration mergedEntity,
            CompleteSignatureConfiguration newConfig) {

        // 1) Load old hashes
        Map<String,String> existingHashes = readExistingHashes(mergedEntity);

        // 2) Prepare toPatch and updatedHashes
        Map<String,String> toPatch       = new HashMap<>();
        Map<String,String> updatedHashes = new HashMap<>(existingHashes);

        // 2a) clientSecret
        if (newConfig.clientSecret() != null) {
            String newHash = hashS256(newConfig.clientSecret());
            if (!newHash.equals(existingHashes.get(CLIENT_SECRET))) {
                toPatch.put(CLIENT_SECRET, newConfig.clientSecret());
                updatedHashes.put(CLIENT_SECRET, newHash);
            }
        }
        // 2b) credentialPassword
        if (newConfig.credentialPassword() != null) {
            String newHash = hashS256(newConfig.credentialPassword());
            if (!newHash.equals(existingHashes.get(CREDENTIAL_PASSWORD))) {
                toPatch.put(CREDENTIAL_PASSWORD, newConfig.credentialPassword());
                updatedHashes.put(CREDENTIAL_PASSWORD, newHash);
            }
        }
        // 2c) TOTP secret
        if (newConfig.secret() != null) {
            String newHash = hashS256(newConfig.secret());
            if (!newHash.equals(existingHashes.get(SECRET))) {
                toPatch.put(SECRET, newConfig.secret());
                updatedHashes.put(SECRET, newHash);
            }
        }

        // 3) If nothing changed, return the merged entity untouched
        if (toPatch.isEmpty()) {
            return Mono.just(mergedEntity);
        }

        // 4) Serialize and set new JSON of hashes
        try {
            mergedEntity.setVaultHashedSecretValues(
                    objectMapper.writeValueAsString(updatedHashes)
            );
        } catch (JsonProcessingException e) {
            return Mono.error(new IllegalStateException(
                    "Failed to serialize updated hashes", e));
        }

        // 5) Patch Vault and return the merged entity
        return vaultService
                .patchSecrets(mergedEntity.getSecretRelativePath(), toPatch)
                .thenReturn(mergedEntity);
    }

    /**
     * Builds a map of all fields to compare, allowing null values.
     */
    private Map<String,Object> toComparableMap(SignatureConfiguration e) {
        Map<String,Object> m = new HashMap<>();
        m.put("enableRemoteSignature",    e.isEnableRemoteSignature());
        m.put("signatureMode",            e.getSignatureMode());
        m.put("cloudProviderId",          e.getCloudProviderId());
        m.put("clientId",                 e.getClientId());
        m.put("credentialId",             e.getCredentialId());
        m.put("credentialName",           e.getCredentialName());
        m.put("vaultHashedSecretValues",  e.getVaultHashedSecretValues());
        return m;
    }

    private ChangeSet diffEntities(
            SignatureConfiguration oldEntity,
            SignatureConfiguration newEntity) {

        Map<String,Object> oldMap = toComparableMap(oldEntity);
        Map<String,Object> newMap = toComparableMap(newEntity);

        Map<String,Object> olds = new HashMap<>();
        Map<String,Object> news = new HashMap<>();

        for (Map.Entry<String,Object> entry : oldMap.entrySet()) {
            String key = entry.getKey();
            Object o = entry.getValue();

            Object n = newMap.get(key);

            if (!Objects.equals(o, n)) {
                olds.put(key, o);
                news.put(key, n);
            }
        }

        return new ChangeSet(olds, news);
    }

    private SignatureConfigWithProviderName mapToWithProviderName(SignatureConfiguration config, String providerName) {
        return new SignatureConfigWithProviderName(
                config.getId(),
                config.getOrganizationIdentifier(),
                config.isEnableRemoteSignature(),
                config.getSignatureMode(),
                providerName,
                config.getClientId(),
                config.getCredentialId(),
                config.getCredentialName()
        );
    }


    @Override
    public Mono<Void> deleteSignatureConfiguration(String id, String organizationId, String rationale, String userEmail) {

        UUID uuid = UUID.fromString(id);

        return loadAndValidateEntity(uuid, organizationId)
                .flatMap(this::mapToSignatureConfigurationResponse)
                        .flatMap(existing -> vaultService.deleteSecret(existing.secretRelativePath())
                                .then(repository.deleteById(uuid))
                                .then(signatureConfigurationAuditService.saveDeletionAudit(existing,  rationale, userEmail))
                        );
    }

    private Mono<SignatureConfigurationResponse> mapToSignatureConfigurationResponse(SignatureConfiguration config) {
        return Mono.just(
                SignatureConfigurationResponse.builder()
                .id(config.getId())
                .organizationIdentifier(config.getOrganizationIdentifier())
                .enableRemoteSignature(config.isEnableRemoteSignature())
                .signatureMode(config.getSignatureMode())
                .cloudProviderId(config.getCloudProviderId())
                .clientId(config.getClientId())
                .credentialId(config.getCredentialId())
                .credentialName(config.getCredentialName())
                .secretRelativePath(config.getSecretRelativePath())
                .vaultHashedSecretValues(config.getVaultHashedSecretValues())
                .build()
        );
    }

    /**
     * Loads the entity by UUID and checks that it belongs to the given organization.
     * Returns the entity (not a DTO) for further updates.
     */
    private Mono<SignatureConfiguration> loadAndValidateEntity(
            UUID id,
            String organizationId) {
        return repository.findById(id)
                .switchIfEmpty(Mono.error(new NoSuchEntityException(
                        "Signature configuration not found with ID: " + id)))
                .flatMap(entity -> {
                    if (!organizationId.equals(entity.getOrganizationIdentifier())) {
                        return Mono.error(new OrganizationIdentifierMismatchException(
                                "Organization identifier mismatch"));
                    }
                    return Mono.just(entity);
                });
    }


    private String hashS256(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 Algorithm not supported", e);
        }
    }
}