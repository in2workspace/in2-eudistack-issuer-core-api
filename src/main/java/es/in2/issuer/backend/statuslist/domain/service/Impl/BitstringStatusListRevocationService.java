package es.in2.issuer.backend.statuslist.domain.service.Impl;

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
    public StatusList applyRevocation(StatusList current, int idx) {
        requireNonNullParam(current, "current");
        requireNonNullParam(idx, "idx");

        String updatedEncoded =
                encoder.setBit(current.encodedList(), idx, true);

        return new StatusList(
                current.id(),
                current.purpose(),
                updatedEncoded,
                current.signedCredential(),
                current.createdAt(),
                current.updatedAt()
        );
    }
}
