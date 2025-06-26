package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.repository.CredentialStatusRepository;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusServiceImpl implements CredentialStatusService {

    private final CredentialStatusRepository credentialStatusRepository;

    @Override
    public Flux<String> getCredentialsStatus() {
        return credentialStatusRepository.findAll()
                .map(statusListIndex -> statusListIndex.getId().toString());
    }
}
