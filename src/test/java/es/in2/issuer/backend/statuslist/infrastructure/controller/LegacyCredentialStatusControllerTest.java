package es.in2.issuer.backend.statuslist.infrastructure.controller;

import es.in2.issuer.backend.statuslist.domain.service.LegacyCredentialStatusQuery;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;


class LegacyCredentialStatusControllerTest {

    private LegacyCredentialStatusQuery legacyQuery;
    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        legacyQuery = mock(LegacyCredentialStatusQuery.class);

        LegacyCredentialStatusController controller = new LegacyCredentialStatusController(legacyQuery);

        webTestClient = WebTestClient
                .bindToController(controller)
                .configureClient()
                .baseUrl("/backoffice/v1/credentials/status")
                .build();
    }

    @Test
    void getCredentialsByListId_shouldReturnOkAndContainNonces() {
        int listId = 7;

        when(legacyQuery.getNoncesByListId(anyString(), eq(listId)))
                .thenReturn(Flux.just("nonce-1", "nonce-2"));

        webTestClient.get()
                .uri("/{listId}", listId)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .consumeWith(result -> {
                    String body = result.getResponseBody();
                    assertNotNull(body);

                    // Minimal assertion without coupling to DTO field names
                    org.assertj.core.api.Assertions.assertThat(body)
                            .contains("nonce-1")
                            .contains("nonce-2");
                });

        ArgumentCaptor<String> processIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(legacyQuery, times(1)).getNoncesByListId(processIdCaptor.capture(), eq(listId));
        verifyNoMoreInteractions(legacyQuery);

        String capturedProcessId = processIdCaptor.getValue();
        assertNotNull(capturedProcessId);
        assertEquals(36, capturedProcessId.length());
    }

    @Test
    void getCredentialsByListId_shouldReturnEmptyArray_whenNoNonces() {
        int listId = 99;

        when(legacyQuery.getNoncesByListId(anyString(), eq(listId)))
                .thenReturn(Flux.empty());

        webTestClient.get()
                .uri("/{listId}", listId)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .consumeWith(result -> {
                    String body = result.getResponseBody();
                    assertNotNull(body);
                    org.assertj.core.api.Assertions.assertThat(body).isEqualTo("[]");
                });

        verify(legacyQuery, times(1)).getNoncesByListId(anyString(), eq(listId));
        verifyNoMoreInteractions(legacyQuery);
    }
}

