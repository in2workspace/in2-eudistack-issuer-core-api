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

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;

@Component
@RequiredArgsConstructor
@Slf4j
public class IssuerFactory {

    private final RemoteSignatureConfig remoteSignatureConfig;
    private final DefaultSignerConfig    defaultSignerConfig;
    private final RemoteSignatureServiceImpl remoteSignatureServiceImpl;

    public Mono<DetailedIssuer> createDetailedIssuer(String procedureId, String credentialType) {
        log.debug("createDetailedIssuer called with procedureId={} credentialType={}", procedureId, credentialType);
        return isServerMode()
                ? Mono.just(buildLocalDetailedIssuer())
                : createRemoteDetailedIssuer(procedureId, credentialType)
                .doOnNext(issuer -> log.info("Remote DetailedIssuer returned: {}", issuer));
    }

    public Mono<SimpleIssuer> createSimpleIssuer(String procedureId, String credentialType) {
        log.debug("createSimpleIssuer called with procedureId={} credentialType={}", procedureId, credentialType);
        return isServerMode()
                ? Mono.just(buildLocalSimpleIssuer())
                : createRemoteDetailedIssuer(procedureId, credentialType)
                .doOnNext(di -> log.info("Remote DetailedIssuer for Simple conversion: {}", di))
                .map(detailed -> SimpleIssuer.builder()
                        .id(detailed.getId())
                        .build());
    }

    private boolean isServerMode() {
        return SIGNATURE_REMOTE_TYPE_SERVER.equals(remoteSignatureConfig.getRemoteSignatureType());
    }

    private DetailedIssuer buildLocalDetailedIssuer() {
        log.debug("Building local DetailedIssuer for organization {}", defaultSignerConfig.getOrganizationIdentifier());
        return DetailedIssuer.builder()
                .id(DID_ELSI + defaultSignerConfig.getOrganizationIdentifier())
                .organizationIdentifier(defaultSignerConfig.getOrganizationIdentifier())
                .organization(defaultSignerConfig.getOrganization())
                .country(defaultSignerConfig.getCountry())
                .commonName(defaultSignerConfig.getCommonName())
                .emailAddress(defaultSignerConfig.getEmail())
                .serialNumber(defaultSignerConfig.getSerialNumber())
                .build();
    }

    private SimpleIssuer buildLocalSimpleIssuer() {
        log.debug("Building local SimpleIssuer for organization {}", defaultSignerConfig.getOrganizationIdentifier());
        return SimpleIssuer.builder()
                .id(DID_ELSI + defaultSignerConfig.getOrganizationIdentifier())
                .build();
    }

    private Mono<DetailedIssuer> createRemoteDetailedIssuer(String procedureId, String credentialType) {
        log.debug("Creating remote DetailedIssuer, validating credentials...");
        return Mono.defer(() ->
                        remoteSignatureServiceImpl.validateCredentials()
                                .flatMap(valid -> {
                                    if (!valid) {
                                        log.error("Credentials mismatch. Signature process aborted.");
                                        return Mono.error(new RemoteSignatureException("Credentials mismatch."));
                                    }
                                    log.debug("Credentials valid, fetching mail for credentialType={}", credentialType);
                                    return getMail(procedureId, credentialType)
                                            .flatMap(mail -> {
                                                log.debug("Obtained mail: {}. Requesting access token...", mail);
                                                return remoteSignatureServiceImpl
                                                        .requestAccessToken(null, SIGNATURE_REMOTE_SCOPE_SERVICE)
                                                        .flatMap(token -> {
                                                            log.debug("Access token obtained, requesting certificate info...");
                                                            return remoteSignatureServiceImpl.requestCertificateInfo(
                                                                    token,
                                                                    remoteSignatureConfig.getRemoteSignatureCredentialId()
                                                            );
                                                        })
                                                        .flatMap(certInfo -> {
                                                            log.debug("Certificate info received, extracting issuer with mail={}...", mail);
                                                            return remoteSignatureServiceImpl.extractIssuerFromCertificateInfo(certInfo, mail);
                                                        });
                                            });
                                })
                )
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1))
                        .maxBackoff(Duration.ofSeconds(5))
                        .jitter(0.5)
                        .filter(remoteSignatureServiceImpl::isRecoverableError)
                        .doBeforeRetry(rs -> log.info("Retry #{} for remote signature", rs.totalRetries() + 1))
                )
                .onErrorResume(err -> {
                    log.error("Error during remote issuer creation at {}: {}", new Date(), err.getMessage());
                    return remoteSignatureServiceImpl.handlePostRecoverError(procedureId)
                            .then(Mono.empty());
                });
    }

    private Mono<String> getMail(String procedureId, String credentialType) {
        return switch (credentialType) {
            case LEAR_CREDENTIAL_EMPLOYEE -> remoteSignatureServiceImpl.getMandatorMail(procedureId)
                    .doOnNext(mail -> log.debug("Mandator mail for LEAR_CREDENTIAL_EMPLOYEE: {}", mail));
            case LABEL_CREDENTIAL -> remoteSignatureServiceImpl.getMailForVerifiableCertification(procedureId)
                    .doOnNext(mail -> log.debug("Mail for LABEL_CREDENTIAL: {}", mail));
            default -> {
                log.error("Unsupported credentialType: {}", credentialType);
                yield Mono.error(new RemoteSignatureException("Unsupported credentialType: " + credentialType));
            }
        };
    }
}
