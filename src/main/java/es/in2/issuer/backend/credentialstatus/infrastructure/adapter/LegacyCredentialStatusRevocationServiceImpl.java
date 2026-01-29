package es.in2.issuer.backend.credentialstatus.infrastructure.adapter;

import es.in2.issuer.backend.credentialstatus.domain.model.entities.LegacyStatusListIndex;
import es.in2.issuer.backend.credentialstatus.domain.service.LegacyCredentialStatusRevocationService;
import es.in2.issuer.backend.credentialstatus.infrastructure.repository.LegacyCredentialStatusRepository;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static java.util.Objects.requireNonNull;

@Slf4j
@Service
@RequiredArgsConstructor
public class LegacyCredentialStatusRevocationServiceImpl implements LegacyCredentialStatusRevocationService {

    private final LegacyCredentialStatusRepository legacyCredentialStatusRepository;

    @Override
    public Mono<Void> revoke(int listId, CredentialStatus credentialStatus) {
        log.info("LegacyCredentialStatusRevocationServiceImpl.revoke");
        requireNonNull(credentialStatus, "credentialStatus cannot be null");

        String nonce = credentialStatus.statusListIndex();
        if (nonce == null || nonce.isBlank()) {
            return Mono.error(new IllegalArgumentException("credentialStatus.statusListIndex (nonce) cannot be null/blank"));
        }

        LegacyStatusListIndex entity = new LegacyStatusListIndex();
        entity.setListId(listId);
        entity.setNonce(nonce);

        return legacyCredentialStatusRepository.save(entity).then();
    }
}

