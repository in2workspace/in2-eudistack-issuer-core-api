package es.in2.issuer.backend.backoffice.domain.service;

import reactor.core.publisher.Mono;

import java.util.Map;

public interface VaultService {
    Mono<Void> saveSecrets(String secretRelativePath, Map<String, String> secrets);
    Mono<Map<String,Object>> getSecrets(String secretRelativePath);
    Mono<Void> deleteSecret(String secretRelativePath);
    Mono<Void> patchSecrets(String secretRelativePath, Map<String, String> partialUpdate);
}
