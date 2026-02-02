package es.in2.issuer.backend.statusList.domain.spi;

import reactor.core.publisher.Mono;

import java.util.Map;

public interface CredentialPayloadSigner {
    Mono<String> sign(
            Map<String, Object> payload,
            String token,
            Long referenceId
    );
}
