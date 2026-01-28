package es.in2.issuer.backend.statusList.domain.service;

import es.in2.issuer.backend.statusList.infrastructure.repository.StatusList;

public interface StatusListRevocationService {
    StatusList applyRevocation(StatusList current, int index);
}
