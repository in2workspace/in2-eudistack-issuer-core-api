package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListCredentialSerializationException;
import es.in2.issuer.backend.statuslist.domain.spi.CredentialPayloadSigner;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;
import static java.util.Collections.emptyMap;

@RequiredArgsConstructor
@Component
public class StatusListSigner implements CredentialPayloadSigner {

    private final RemoteSignatureService remoteSignatureService;
    private final ObjectMapper objectMapper;

    public Mono<String> sign(Map<String, Object> payload, String token, Long listId) {
        requireNonNullParam(payload, "payload");
        requireNonNullParam(token, "token");

        return toSignatureRequest(payload)
                .flatMap(req -> remoteSignatureService.signSystemCredential(req, token))
                .onErrorMap(ex -> new RemoteSignatureException("Remote signature failed; list ID: " + listId, ex))
                .map(signedData -> extractJwt(signedData, listId));
    }

    private Mono<SignatureRequest> toSignatureRequest(Map<String, Object> payload) {
        return Mono.fromCallable(() -> {
            String json = objectMapper.writeValueAsString(payload);

            SignatureConfiguration config = SignatureConfiguration.builder()
                    .type(SignatureType.JADES)
                    .parameters(emptyMap())
                    .build();

            return SignatureRequest.builder()
                    .configuration(config)
                    .data(json)
                    .build();
        }).onErrorMap(JsonProcessingException.class, StatusListCredentialSerializationException::new);
    }

    private String extractJwt(SignedData signedData, Long listId) {
        if (signedData == null || signedData.data() == null || signedData.data().isBlank()) {
            throw new RemoteSignatureException("Remote signer returned empty SignedData; list ID: " + listId);
        }
        return signedData.data();
    }
}
