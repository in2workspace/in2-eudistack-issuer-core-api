package es.in2.issuer.backend.shared.domain.model;

import es.in2.issuer.backend.shared.domain.util.Constants;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public enum CredentialConfigurationsSupported {
    LEAR_CREDENTIAL_EMPLOYEE(Constants.LEAR_CREDENTIAL_EMPLOYEE),
    LEAR_CREDENTIAL_MACHINE(Constants.LEAR_CREDENTIAL_MACHINE),
    VERIFIABLE_CERTIFICATION(Constants.VERIFIABLE_CERTIFICATION);

    private final String text;

    @Override
    public String toString() {
        return text;
    }
}