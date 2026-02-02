package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndTxCode;
import es.in2.issuer.backend.shared.domain.model.dto.Grants;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;

import java.security.SecureRandom;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_CODE_SIZE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_INPUT_MODE;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class PreAuthorizedCodeServiceImpl implements PreAuthorizedCodeService {
    private final SecureRandom random;
    private final CacheStore<CredentialProcedureIdAndTxCode> credentialProcedureIdAndTxCodeByPreAuthorizedCodeCacheStore;
    private final TranslationService translationService;

    @Override
    public Mono<PreAuthorizedCodeResponse> generatePreAuthorizedCode(String processId, Mono<String> credentialProcedureIdMono) {
        return generateCodes()
                .doFirst(() -> log.debug("ProcessId: {} AuthServer: Generating PreAuthorizedCode response", processId))
                .flatMap(tuple -> storeInCache(processId, credentialProcedureIdMono, tuple))
                .doOnSuccess(preAuthorizedCodeResponse ->
                        log.debug(
                                "ProcessId: {} AuthServer: Generated PreAuthorizedCode response successfully",
                                processId));
    }

    private @NotNull Mono<Tuple2<String, String>> generateCodes() {
        return Mono.zip(generatePreAuthorizedCode(), generateTxCode());
    }

    private @NotNull Mono<PreAuthorizedCodeResponse> storeInCache(String processId, Mono<String> credentialProcedureIdMono, Tuple2<String, String> codes) {
        String preAuthorizedCode = codes.getT1();
        String txCode = codes.getT2();

        return credentialProcedureIdMono
                .flatMap(credentialProcedureId ->
                        credentialProcedureIdAndTxCodeByPreAuthorizedCodeCacheStore
                                .add(preAuthorizedCode, new CredentialProcedureIdAndTxCode(credentialProcedureId, txCode))
                                .doOnSuccess(preAuthorizedCodeSaved ->
                                        log.debug(
                                                "ProcessId: {} AuthServer: Saved TxCode and CredentialId by " +
                                                        "PreAuthorizedCode in cache",
                                                processId))
                                .flatMap(preAuthorizedCodeSaved -> buildPreAuthorizedCodeResponse(
                                        preAuthorizedCodeSaved,
                                        txCode)));
    }

    private Mono<String> generatePreAuthorizedCode() {
        return generateCustomNonce();
    }

    private Mono<String> generateTxCode() {
        double minValue = Math.pow(10, (double) TX_CODE_SIZE - 1);
        double maxValue = Math.pow(10, TX_CODE_SIZE) - 1;
        int i = random.nextInt((int) (maxValue - minValue + 1)) + (int) minValue;
        return Mono.just(String.valueOf(i));
    }

    private Mono<PreAuthorizedCodeResponse> buildPreAuthorizedCodeResponse(String preAuthorizedCode, String txCode) {
        Grants.TxCode grantTxCode = Grants.TxCode.builder()
                .length(TX_CODE_SIZE)
                .inputMode(TX_INPUT_MODE)
                .build();
        Grants grants = new Grants(preAuthorizedCode, grantTxCode);
        return Mono.just(new PreAuthorizedCodeResponse(grants, txCode));
    }
}
