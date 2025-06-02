package es.in2.issuer.backend.shared.objectmother;

import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;

public final class PreAuthorizedCodeResponseMother {

    private PreAuthorizedCodeResponseMother() {
    }

    public static PreAuthorizedCodeResponse dummy() {
        return new PreAuthorizedCodeResponse(
                "preAuthorizedCode",
                "pin"
        );
    }

    public static PreAuthorizedCodeResponse withPreAuthorizedCodeAndPin(String preAuthorizedCode, String pin) {
        return new PreAuthorizedCodeResponse(
                preAuthorizedCode,
                pin
        );
    }
}
