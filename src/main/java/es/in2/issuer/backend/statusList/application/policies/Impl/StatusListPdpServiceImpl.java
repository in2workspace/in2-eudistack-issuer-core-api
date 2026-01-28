package es.in2.issuer.backend.statusList.application.policies.Impl;


import es.in2.issuer.backend.shared.application.workflow.policies.PdpCommonService;
import es.in2.issuer.backend.shared.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.statusList.application.policies.StatusListPdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private final PdpCommonService pdpCommonService;

    @Override
    public Mono<Void> validateRevokeCredential(String processId, String token, CredentialProcedure procedure) {
        return Mono.defer(() ->
                validateStatus(procedure.getCredentialStatus())
                        .doFirst(() -> log.info("Process ID: {} - Validating 'revoke' action...", processId))
                        .then(pdpCommonService.parseAndValidateRole(token, LEAR))
                        .flatMap(pdpCommonService::extractUserOrganizationIdentifier)
                        .flatMap(userOrg ->
                                pdpCommonService.ensureSameOrgOrSysAdmin(
                                        userOrg,
                                        procedure.getOrganizationIdentifier()
                                )
                        )
        );
    }

    private Mono<Void> validateStatus(CredentialStatusEnum credentialStatus) {
        if (credentialStatus == VALID) {
            return Mono.empty();
        }

        return Mono.error(new InvalidStatusException(
                "Invalid status: " + credentialStatus
        ));
    }
}
