package es.in2.issuer.backend.oidc4vci.domain.model;

import lombok.Builder;
import org.springframework.web.bind.annotation.BindParam;

@Builder
public record TokenRequest(
        @BindParam("grant_type") String grantType,
        @BindParam("pre-authorized_code") String preAuthorizedCode,
        @BindParam("tx_code") String txCode,
        @BindParam("refresh_token") String refreshToken){
}
