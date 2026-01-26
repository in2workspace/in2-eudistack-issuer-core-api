package es.in2.issuer.backend.backoffice.application.workflow.policies.impl;

import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.application.workflow.policies.PdpCommonService;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureInvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR;

@Service
@Slf4j
@RequiredArgsConstructor
public class BackofficePdpServiceImpl implements BackofficePdpService {

    private final PdpCommonService pdpCommonService;
    private final CredentialProcedureRepository credentialProcedureRepository;

    @Override
    public Mono<Void> validateSignCredential(String processId, String token, CredentialProcedure procedure) {
        log.info("Validating 'sign' action for processId={} and credentialProcedureId={}",
                processId, procedure.getProcedureId());

        return validatePendSignatureStatus(procedure.getCredentialStatus())
                .then(pdpCommonService.parseAndValidateRole(token, LEAR))
                .flatMap(pdpCommonService::extractUserOrganizationIdentifier)
                .flatMap(userOrg ->
                        pdpCommonService.ensureSameOrgOrSysAdmin(
                                userOrg,
                                procedure.getOrganizationIdentifier()
                        )
                );
    }

    //todo make it admit procedure instead of procedure id
    @Override
    public Mono<Void> validateSendReminder(String processId, String token, String credentialProcedureId) {
        log.info("Validating 'send reminder' action for processId={} and credentialProcedureId={}",
                processId, credentialProcedureId);

        return pdpCommonService.parseAndValidateRole(token, LEAR)
                .flatMap(pdpCommonService::extractUserOrganizationIdentifier)
                .flatMap(userOrg -> {
                    if (pdpCommonService.isSysAdmin(userOrg)) {
                        log.info("User belongs to admin organization. Skipping DB lookup.");
                        return Mono.empty();
                    }

                    return credentialProcedureRepository.findById(UUID.fromString(credentialProcedureId))
                            .flatMap(procedure ->
                                    pdpCommonService.ensureSameOrgOrSysAdmin(
                                            userOrg,
                                            procedure.getOrganizationIdentifier()
                                    )
                            );
                });
    }

    private Mono<Void> validatePendSignatureStatus(CredentialStatusEnum credentialStatus) {
        if (credentialStatus == CredentialStatusEnum.PEND_SIGNATURE) {
            return Mono.empty();
        }

        // If you already have a specific exception, prefer it; otherwise reuse UnauthorizedRoleException.
        return Mono.error(new CredentialProcedureInvalidStatusException(
                "Access denied: Credential procedure is not in PEND_SIGNATURE status"
        ));
    }
}