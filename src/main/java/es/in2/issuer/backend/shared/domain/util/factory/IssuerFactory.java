package es.in2.issuer.backend.shared.domain.util.factory;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.service.impl.RemoteSignatureServiceImpl;
import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig;
import es.in2.issuer.backend.shared.infrastructure.config.RemoteSignatureConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Date;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.DID_ELSI;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_SERVICE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_TYPE_SERVER;

@Component
@RequiredArgsConstructor
@Slf4j
public class IssuerFactory {

    private final RemoteSignatureConfig      remoteSignatureConfig;
    private final DefaultSignerConfig        defaultSignerConfig;
    private final RemoteSignatureServiceImpl remoteSignatureServiceImpl;

    /**
     * Detailed issuer creation without post-recover side-effects.
     * - Server mode: local issuer
     * - Remote mode: remote flow, retries, errors are propagated
     */
    public Mono<DetailedIssuer> createDetailedIssuer() {
        log.debug("🔐: createDetailedIssuer");
        return isServerMode()
                ? Mono.just(buildLocalDetailedIssuer())
                : createRemoteDetailedIssuerNoNotifyOnError();
    }

    /**
     * Simple issuer creation without post-recover side-effects.
     * - Server mode: local issuer
     * - Remote mode: remote flow, retries, errors are propagated
     */
    public Mono<SimpleIssuer> createSimpleIssuer() {
        log.debug("🔐: createSimpleIssuer");
        return isServerMode()
                ? Mono.just(buildLocalSimpleIssuer())
                : createRemoteDetailedIssuerNoNotifyOnError()
                .map(detailed -> SimpleIssuer.builder()
                        .id(detailed.getId())
                        .build());
    }

    /**
     * Detailed issuer creation with post-recover side-effects on error:
     * - If remote flow fails after retries, it executes handlePostRecoverError(procedureId, email)
     *   and completes empty.
     */
    public Mono<DetailedIssuer> createDetailedIssuerAndNotifyOnError(String procedureId, String email) {
        log.debug("🔐: createDetailedIssuerAndNotifyOnError");
        return isServerMode()
                ? Mono.just(buildLocalDetailedIssuer())
                : createRemoteDetailedIssuerNotifyOnError(procedureId, email);
    }

    /**
     * Simple issuer creation with post-recover side-effects on error:
     * - If remote flow fails after retries, it executes handlePostRecoverError(procedureId, email)
     *   and completes empty.
     */
    public Mono<SimpleIssuer> createSimpleIssuerAndNotifyOnError(String procedureId, String email) {
        log.debug("🔐: createSimpleIssuerAndNotifyOnError");
        return isServerMode()
                ? Mono.just(buildLocalSimpleIssuer())
                : createRemoteDetailedIssuerNotifyOnError(procedureId, email)
                .map(detailed -> SimpleIssuer.builder()
                        .id(detailed.getId())
                        .build());
    }

    private boolean isServerMode() {
        return SIGNATURE_REMOTE_TYPE_SERVER.equals(remoteSignatureConfig.getRemoteSignatureType());
    }

    private DetailedIssuer buildLocalDetailedIssuer() {
        return DetailedIssuer.builder()
                .id(DID_ELSI + defaultSignerConfig.getOrganizationIdentifier())
                .organizationIdentifier(defaultSignerConfig.getOrganizationIdentifier())
                .organization(defaultSignerConfig.getOrganization())
                .country(defaultSignerConfig.getCountry())
                .commonName(defaultSignerConfig.getCommonName())
                .serialNumber(defaultSignerConfig.getSerialNumber())
                .build();
    }

    private SimpleIssuer buildLocalSimpleIssuer() {
        return SimpleIssuer.builder()
                .id(DID_ELSI + defaultSignerConfig.getOrganizationIdentifier())
                .build();
    }

    /**
     * Remote flow used by the "no notify on error" methods:
     * - retries recoverable errors
     * - propagates the error downstream if it still fails
     */
    private Mono<DetailedIssuer> createRemoteDetailedIssuerNoNotifyOnError() {
        log.debug("🔐: createRemoteDetailedIssuerNoNotifyOnError");
        return remoteIssuerCoreFlow()
                .retryWhen(buildRetrySpec())
                .doOnError(err ->
                        log.error("Error during remote issuer creation at {}: {}", new Date(), err.getMessage())
                );
    }

    /**
     * Remote flow used by the "notify on error" methods:
     * - retries recoverable errors
     * - if it still fails, executes handlePostRecoverError(procedureId, email) and completes empty
     */
    private Mono<DetailedIssuer> createRemoteDetailedIssuerNotifyOnError(String procedureId, String email) {
        log.debug("🔐: createRemoteDetailedIssuerNotifyOnError");
        return remoteIssuerCoreFlow()
                .retryWhen(buildRetrySpec())
                .onErrorResume(err -> {
                    log.error("Error during remote issuer creation at {}: {}", new Date(), err.getMessage());
                    return remoteSignatureServiceImpl.handlePostRecoverError(procedureId, email)
                            .then(Mono.empty());
                });
    }

    /**
     * Core remote signature flow: validate -> token -> certInfo -> extract issuer
     */
    private Mono<DetailedIssuer> remoteIssuerCoreFlow() {
        return Mono.defer(() ->
                remoteSignatureServiceImpl.validateCredentials()
                        .flatMap(valid -> {
                            if (Boolean.FALSE.equals(valid)) {
                                log.error("Credentials mismatch. Signature process aborted.");
                                return Mono.error(new RemoteSignatureException("Credentials mismatch."));
                            }
                            return remoteSignatureServiceImpl.requestAccessToken(null, SIGNATURE_REMOTE_SCOPE_SERVICE)
                                    .flatMap(token -> remoteSignatureServiceImpl.requestCertificateInfo(
                                            token,
                                            remoteSignatureConfig.getRemoteSignatureCredentialId()
                                    ))
                                    .flatMap(remoteSignatureServiceImpl::extractIssuerFromCertificateInfo);
                        })
        );
    }

    private Retry buildRetrySpec() {
        return Retry.backoff(3, Duration.ofSeconds(1))
                .maxBackoff(Duration.ofSeconds(5))
                .jitter(0.5)
                .filter(remoteSignatureServiceImpl::isRecoverableError)
                .doBeforeRetry(rs -> log.info("Retry #{} for remote signature", rs.totalRetries() + 1));
    }
}
