package es.in2.issuer.backend.shared.domain.model.dto.credential;

import java.util.List;

public interface W3CVerifiableCredential {
    List<String> context();
    String id();
    List<String> type();
    String description();
    Issuer issuer();
    String validFrom();
    String validUntil();
    CredentialStatusObject credentialStatus();
}
