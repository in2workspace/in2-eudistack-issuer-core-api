package es.in2.issuer.backend.statuslist.domain.service.impl;

import es.in2.issuer.backend.statuslist.domain.service.StatusListRevocationService;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusList;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@RequiredArgsConstructor
@Service
public class BitstringStatusListRevocationService
        implements StatusListRevocationService {

    private final BitstringEncoder encoder = new BitstringEncoder();

    @Override
    public StatusList applyRevocation(StatusList currentStatusList, int idx) {
        requireNonNullParam(currentStatusList, "current");
        requireNonNullParam(idx, "idx");

        String updatedEncoded =
                encoder.setBit(currentStatusList.encodedList(), idx, true);

        return new StatusList(
                currentStatusList.id(),
                currentStatusList.purpose(),
                updatedEncoded,
                currentStatusList.signedCredential(),
                currentStatusList.createdAt(),
                currentStatusList.updatedAt()
        );
    }
}
