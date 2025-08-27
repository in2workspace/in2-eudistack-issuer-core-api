package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigAudit;
import es.in2.issuer.backend.backoffice.domain.service.SignatureConfigurationAuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/ops/v1/signatures/configs/audit") //TODO: deberia ser backoffice? obsoleta?
@RequiredArgsConstructor
public class SignatureConfigurationSignatureAuditController {

    private final SignatureConfigurationAuditService auditService;

    @GetMapping
    public Flux<SignatureConfigAudit> getAllAudits(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return auditService.getAllAudits();
    }

    @GetMapping(params = "organizationIdentifier")
    public Flux<SignatureConfigAudit> getAuditsByOrganization(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestParam String organizationIdentifier
    ) {
        return auditService.getAuditsByOrganization(organizationIdentifier);
    }

}