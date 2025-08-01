package es.in2.issuer.backend.shared.domain.model.enums;

import lombok.Getter;

@Getter
public enum CredentialType {
    LEAR_CREDENTIAL_EMPLOYEE("LEARCredentialEmployee"),
    LEAR_CREDENTIAL_MACHINE("LEARCredentialMachine"),
    LABEL_CREDENTIAL("gx:LabelCredential");

    private final String typeId;

    CredentialType(String typeId) {
        this.typeId = typeId;
    }

}
