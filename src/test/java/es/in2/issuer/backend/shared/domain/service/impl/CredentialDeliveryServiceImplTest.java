package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.WebClientConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.net.URI;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialDeliveryServiceImplTest {

    private WebClientConfig webClientConfig;
    private ExchangeFunction exchangeFunction;
    private EmailService emailService;
    private AppConfig appConfig;
    private CredentialDeliveryServiceImpl service;
    private WebClient webClient;

    private static final String RESPONSE_URI = "http://example.com/endpoint";
    private static final String ENC_VC = "encoded-vc";
    private static final String PRODUCT_ID = "prod-123";
    private static final String COMPANY_EMAIL = "foo@bar.com";
    private static final String BEARER = "token-xyz";
    private static final String GUIDE_URL = "http://kb.guide";

    @BeforeEach
    void setup() {
        webClientConfig = mock(WebClientConfig.class);
        exchangeFunction = mock(ExchangeFunction.class);
        emailService = mock(EmailService.class);
        appConfig = mock(AppConfig.class);

        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);

        webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.commonWebClient()).thenReturn(webClient);

        service = new CredentialDeliveryServiceImpl(webClientConfig, emailService, appConfig);
    }

    @Test
    void whenAccepted202_thenSendResponseUriAcceptedWithHtml() {

        ClientResponse clientResponse = mock(ClientResponse.class);
        when(clientResponse.statusCode()).thenReturn(HttpStatus.ACCEPTED);
        when(clientResponse.bodyToMono(String.class))
                .thenReturn(Mono.just("<html>missing docs</html>"));

        when(clientResponse.releaseBody()).thenReturn(Mono.empty());

        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        when(emailService.sendResponseUriAcceptedWithHtml(
                COMPANY_EMAIL, PRODUCT_ID, "<html>missing docs</html>"
        )).thenReturn(Mono.empty());

        StepVerifier.create(
                        service.sendVcToResponseUri(RESPONSE_URI, ENC_VC, PRODUCT_ID, COMPANY_EMAIL, BEARER)
                )
                .verifyComplete();

        verify(emailService, times(1))
                .sendResponseUriAcceptedWithHtml(COMPANY_EMAIL, PRODUCT_ID, "<html>missing docs</html>");
        verify(emailService, never()).sendResponseUriFailed(any(), any(), any());
    }


    @Test
    void whenOk200_thenNoEmailSent() {
        ClientResponse clientResponse = ClientResponse
                .create(HttpStatus.OK)
                .build();

        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        StepVerifier.create(
                        service.sendVcToResponseUri(RESPONSE_URI, ENC_VC, PRODUCT_ID, COMPANY_EMAIL, BEARER)
                )
                .verifyComplete();

        verify(emailService, never()).sendResponseUriAcceptedWithHtml(any(), any(), any());
        verify(emailService, never()).sendResponseUriFailed(any(), any(), any());
    }

    @Test
    void whenErrorStatus_thenSendResponseUriFailed() {
        ClientResponse clientResponse = mock(ClientResponse.class);
        when(clientResponse.statusCode()).thenReturn(HttpStatus.BAD_REQUEST);
        when(clientResponse.releaseBody()).thenReturn(Mono.empty());
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        when(emailService.sendResponseUriFailed(
                COMPANY_EMAIL, PRODUCT_ID, GUIDE_URL
        )).thenReturn(Mono.empty());

        StepVerifier.create(
                        service.sendVcToResponseUri(RESPONSE_URI, ENC_VC, PRODUCT_ID, COMPANY_EMAIL, BEARER)
                )
                .verifyComplete();

        verify(emailService, times(1))
                .sendResponseUriFailed(COMPANY_EMAIL, PRODUCT_ID, GUIDE_URL);
        verify(emailService, never()).sendResponseUriAcceptedWithHtml(any(), any(), any());
    }

    @Test
    void whenNetworkError_thenSendResponseUriFailed() {
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.error(
                        new WebClientRequestException(
                                new IOException("network error"),
                                HttpMethod.PATCH,
                                URI.create(RESPONSE_URI),
                                new HttpHeaders()
                        )
                ));

        when(emailService.sendResponseUriFailed(
                COMPANY_EMAIL, PRODUCT_ID, GUIDE_URL
        )).thenReturn(Mono.empty());

        StepVerifier.create(
                        service.sendVcToResponseUri(RESPONSE_URI, ENC_VC, PRODUCT_ID, COMPANY_EMAIL, BEARER)
                )
                .verifyComplete();

        verify(emailService, times(1))
                .sendResponseUriFailed(COMPANY_EMAIL, PRODUCT_ID, GUIDE_URL);
        verify(emailService, never()).sendResponseUriAcceptedWithHtml(any(), any(), any());
    }
}
