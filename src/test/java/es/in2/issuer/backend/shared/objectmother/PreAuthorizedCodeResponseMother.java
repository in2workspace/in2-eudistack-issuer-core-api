package es.in2.issuer.backend.shared.objectmother;

import es.in2.issuer.backend.shared.domain.model.dto.Grants;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.*;

//public final class PreAuthorizedCodeResponseMother {
//
//    private PreAuthorizedCodeResponseMother() {
//    }
//
//    public static PreAuthorizedCodeResponse dummy() {
//        return new PreAuthorizedCodeResponse(
//                new Grants("preAuthorizedCode",
//                        new Grants.TxCode(5, "inputMode", "description")),
//                "pin"
//        );
//    }
//
//    public static PreAuthorizedCodeResponse withPreAuthorizedCodeAndPin(String preAuthorizedCode, String pin) {
//        return new PreAuthorizedCodeResponse(
//                new Grants(preAuthorizedCode,
//                        new Grants.TxCode(TX_CODE_SIZE, TX_INPUT_MODE, TX_CODE_DESCRIPTION)),
//                pin
//        );
//    }
//}
