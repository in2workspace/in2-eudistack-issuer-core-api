package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriRequest;
import es.in2.issuer.backend.shared.domain.service.CredentialDeliveryService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
@Service
public class CredentialDeliveryServiceImpl implements CredentialDeliveryService {

    private final WebClientConfig webClient;
    private final EmailService emailService;
    private final AppConfig appConfig;

    @Override
    public Mono<Void> sendVcToResponseUri(String responseUri, String encodedVc, String credId, String email, String bearerToken) {
        ResponseUriRequest responseUriRequest = ResponseUriRequest.builder()
                .encodedVc(encodedVc)
                .build();
        log.info("[RESPONSE-URI] Starting request to: {} for credId: {} email: {}", responseUri, credId, email);
        log.debug("Sending the VC: {} to response_uri: {} to email {}", encodedVc, responseUri, email);

        return webClient.commonWebClient()
                .patch()
                .uri(responseUri)
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken)
                .bodyValue(responseUriRequest)
                .exchangeToMono(response -> {
                    log.info("[RESPONSE-URI] Received response: {} from {}", response.statusCode(), responseUri);
                    if (response.statusCode().is2xxSuccessful()) {
                        if (HttpStatus.ACCEPTED.equals(response.statusCode())) {
                            log.info("[RESPONSE-URI] SUCCESS: Received 202 ACCEPTED from response_uri. Extracting HTML and sending specific mail for missing documents");
                            return response.bodyToMono(String.class)
                                    .flatMap(htmlResponseBody ->
                                            emailService.sendResponseUriAcceptedWithHtml(email, credId, htmlResponseBody))
                                    .then();
                        }
                        log.info("[RESPONSE-URI] SUCCESS: Received {} from response_uri for credId: {}", response.statusCode(), credId);
                        return Mono.empty();
                    } else {
                        log.error("[RESPONSE-URI] FAILURE: Non-2xx status code received: {} from {} for credId: {}. Sending failure email...", 
                                response.statusCode(), responseUri, credId);
                        return emailService.sendResponseUriFailed(email, credId, appConfig.getKnowledgeBaseUploadCertificationGuideUrl())
                                .then()
                                .flatMap(unused -> Mono.error(new RuntimeException(
                                    "Failed to upload credential to response URI: " + response.statusCode()
                                )));
                    }
                })
                .onErrorResume(WebClientRequestException.class, ex -> {
                    log.error("[RESPONSE-URI] NETWORK ERROR: Failed to connect to {} for credId: {}: {}", 
                            responseUri, credId, ex.getMessage(), ex);
                    return emailService.sendResponseUriFailed(email, credId, appConfig.getKnowledgeBaseUploadCertificationGuideUrl())
                            .onErrorResume(emailError -> {
                                log.error("Failed to send failure email after network error", emailError);
                                return Mono.empty();
                            })
                            .then(Mono.error(ex));
                });
    }
}
