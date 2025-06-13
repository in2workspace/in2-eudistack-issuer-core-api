package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import es.in2.issuer.backend.shared.domain.model.dto.Grants;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_CREDENTIAL_OFFER_PATH;
import static es.in2.issuer.backend.shared.domain.util.HttpUtils.ensureUrlHasProtocol;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferServiceImpl implements CredentialOfferService {

    private final AppConfig appConfig;

    @Override
    public Mono<CredentialOffer> buildCustomCredentialOffer(String credentialType, String preAuthorizedCode) {
        return Mono.just(
                CredentialOffer.builder()
                        .credentialIssuer(appConfig.getIssuerBackendUrl())
                        .credentialConfigurationIds(List.of(LEAR_CREDENTIAL_EMPLOYEE))
                        .grants(Map.of(GRANT_TYPE, buildGrants(preAuthorizedCode)))
                        .build()
        );
    }

    @Override
    public Mono<String> createCredentialOfferUriResponse(String nonce) {
        String url = ensureUrlHasProtocol(appConfig.getIssuerBackendUrl() + OID4VCI_CREDENTIAL_OFFER_PATH + "/" + nonce);
        String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8);
        String credentialOfferPrefix = "openid-credential-offer://?credential_offer_uri=";
        return Mono.just(credentialOfferPrefix + encodedUrl);
    }

    private Grants buildGrants(String preAuthorizedCode) {
        Grants.TxCode grantTxCode = new Grants.TxCode(TX_CODE_SIZE, TX_INPUT_MODE, TX_CODE_DESCRIPTION);
        return Grants.builder()
                .preAuthorizedCode(preAuthorizedCode)
                .txCode(grantTxCode)
                .build();
    }
}
