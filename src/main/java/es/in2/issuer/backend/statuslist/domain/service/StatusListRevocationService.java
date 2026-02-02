package es.in2.issuer.backend.statuslist.domain.service;

import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusList;

public interface StatusListRevocationService {
    StatusList applyRevocation(StatusList current, int index);
}
