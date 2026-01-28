package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SUPPORTED_PROOF_ALG;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SUPPORTED_PROOF_TYP;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;



@ExtendWith(MockitoExtension.class)
class ProofValidationServiceImplTest {

    @Mock
    private JWTService jwtService;

    @InjectMocks
    private ProofValidationServiceImpl service;


    @BeforeEach
    void setUp() {
        service = new ProofValidationServiceImpl(jwtService);
    }

    @Test
    void isProofValid_valid_returnsTrue() {
        String expectedAudience = "aud";
        long now = Instant.now().getEpochSecond();

        String jwt = buildValidProofJwt(expectedAudience, now, now + 300);

        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.just(true));

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), expectedAudience))
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void isProofValid_signatureInvalid_returnsFalse() {
        String aud = "aud";
        long now = Instant.now().getEpochSecond();

        String jwt = buildJwtRaw(
                """
                {"alg":"%s","typ":"%s","kid":"did:key:zDummy"}
                """.formatted(SUPPORTED_PROOF_ALG, SUPPORTED_PROOF_TYP),
                """
                {"aud":"%s","iat":%d,"exp":%d}
                """.formatted(aud, now - 10, now + 600)
        );

        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.just(false));

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), aud))
                .expectNext(false)
                .verifyComplete();
    }


    @Test
    void isProofValid_headerMissingAlgOrTyp_mapsToProofValidationException() {
        // Missing typ
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"kid\":\"did:key:zDummy\"}",
                "{\"aud\":\"aud\",\"iat\":" + Instant.now().getEpochSecond() + "}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_headerUnsupportedTyp_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"WRONG\",\"kid\":\"did:key:zDummy\"}",
                "{\"aud\":\"aud\",\"iat\":" + Instant.now().getEpochSecond() + "}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_headerAlgNone_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"none\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}",
                "{\"aud\":\"aud\",\"iat\":" + Instant.now().getEpochSecond() + "}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }


    @Test
    void isProofValid_headerKidJwkX5cMustBeExactlyOne_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\","
                        + "\"kid\":\"did:key:zDummy\","
                        + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x\",\"y\":\"y\"}}",
                "{\"aud\":\"aud\",\"iat\":" + Instant.now().getEpochSecond() + "}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_headerJwkWithPrivateMaterial_mapsToProofValidationException() {
        // jwk with "d" => private key material => invalid
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\","
                        + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x\",\"y\":\"y\",\"d\":\"PRIVATE\"}}",
                "{\"aud\":\"aud\",\"iat\":" + Instant.now().getEpochSecond() + "}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadAudMissing_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}",
                "{\"iat\":" + Instant.now().getEpochSecond() + "}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadAudMismatch_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}",
                "{\"aud\":\"OTHER\",\"iat\":" + Instant.now().getEpochSecond() + "}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadAudAsList_matchesExpected_returnsTrue() {
        String expectedAudience = "aud";
        long now = Instant.now().getEpochSecond();

        String jwt = buildAudListProofJwt(expectedAudience, now);

        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.just(true));

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), expectedAudience))
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void isProofValid_payloadIatMissing_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}",
                "{\"aud\":\"aud\"}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadIatNotNumeric_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}",
                "{\"aud\":\"aud\",\"iat\":\"nope\"}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadIatTooOld_mapsToProofValidationException() {
        long iat = Instant.now().minusSeconds(301).getEpochSecond();
        String jwt = buildValidProofJwt("aud", iat, null);

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadIatTooFuture_mapsToProofValidationException() {
        long iat = Instant.now().plusSeconds(61).getEpochSecond();
        String jwt = buildValidProofJwt("aud", iat, null);

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadExpExpired_mapsToProofValidationException() {
        long now = Instant.now().getEpochSecond();
        long exp = now - 1;

        String jwt = buildValidProofJwt("aud", now, exp);

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_payloadExpNotNumeric_mapsToProofValidationException() {
        String jwt = buildJwtRaw(
                "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}",
                "{\"aud\":\"aud\",\"iat\":" + Instant.now().getEpochSecond() + ",\"exp\":\"bad\"}"
        );

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), "aud"))
                .expectError(ProofValidationException.class)
                .verify();
    }

    @Test
    void isProofValid_whenJwtServiceThrows_mapsToProofValidationException() {
        String expectedAudience = "aud";
        long now = Instant.now().getEpochSecond();

        String jwt = buildValidProofJwt(expectedAudience, now, now + 300);

        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class)))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), expectedAudience))
                .expectError(ProofValidationException.class)
                .verify();
    }
    @Test
    void isProofValid_withJwk_whenJwtServiceThrows_callsJwkVerifier_andMapsToProofValidationException() throws Exception {
        String expectedAudience = "aud";
        long now = Instant.now().getEpochSecond();

        String jwt = buildNimbusSignedJwtWithPublicEcJwk(expectedAudience, now);

        when(jwtService.validateJwtSignatureWithJwkReactive(anyString(), anyMap()))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), expectedAudience))
                .expectError(ProofValidationException.class)
                .verify();

        verify(jwtService).validateJwtSignatureWithJwkReactive(anyString(), anyMap());
        verify(jwtService, never()).validateJwtSignatureReactive(any(SignedJWT.class));
    }

    @Test
    void isProofValid_withJwk_usesValidateJwtSignatureWithJwkReactive_returnsTrue() throws Exception {
        String expectedAudience = "aud";
        long now = Instant.now().getEpochSecond();

        String jwt = buildNimbusSignedJwtWithPublicEcJwk(expectedAudience, now);

        when(jwtService.validateJwtSignatureWithJwkReactive(anyString(), anyMap()))
                .thenReturn(Mono.just(true));

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), expectedAudience))
                .expectNext(true)
                .verifyComplete();

        verify(jwtService).validateJwtSignatureWithJwkReactive(anyString(), anyMap());
        verify(jwtService, never()).validateJwtSignatureReactive(any(SignedJWT.class));
    }
    @Test
    void isProofValid_withJwk_signatureInvalid_returnsFalse() throws Exception {
        String expectedAudience = "aud";
        long now = Instant.now().getEpochSecond();

        String jwt = buildNimbusSignedJwtWithPublicEcJwk(expectedAudience, now);

        when(jwtService.validateJwtSignatureWithJwkReactive(anyString(), anyMap()))
                .thenReturn(Mono.just(false));

        StepVerifier.create(service.isProofValid(jwt, Set.of(SUPPORTED_PROOF_ALG), expectedAudience))
                .expectNext(false)
                .verifyComplete();

        verify(jwtService).validateJwtSignatureWithJwkReactive(anyString(), anyMap());
        verify(jwtService, never()).validateJwtSignatureReactive(any(SignedJWT.class));
    }





    // ---------------- helpers ----------------

    private static String buildValidProofJwt(String expectedAudience, long iat, Long exp) {
        String header = "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}";
        String payload = "{\"aud\":\"" + expectedAudience + "\",\"iat\":" + iat + (exp != null ? ",\"exp\":" + exp : "") + "}";
        return buildJwtRaw(header, payload);
    }

    private static String buildAudListProofJwt(String expectedAudience, long iat) {
        String header = "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP + "\",\"kid\":\"did:key:zDummy\"}";
        String payload = "{\"aud\":[\"x\",\"" + expectedAudience + "\"],\"iat\":" + iat + "}";
        return buildJwtRaw(header, payload);
    }

    private static String buildJwtRaw(String headerJson, String payloadJson) {
        String h = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String p = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String s = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("signature".getBytes(StandardCharsets.UTF_8));
        return h + "." + p + "." + s;
    }

    private static String buildNimbusSignedJwtWithPublicEcJwk(String expectedAudience, long nowEpochSec) throws Exception {
        // Keypair real P-256
        ECKey ecKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        // Header con jwk público (sin material privado)
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(SUPPORTED_PROOF_TYP))
                .jwk(ecKey.toPublicJWK())
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(expectedAudience)
                .issueTime(new Date((nowEpochSec - 1) * 1000))
                .expirationTime(new Date((nowEpochSec + 300) * 1000))
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);

        jwt.sign(new ECDSASigner(ecKey));

        return jwt.serialize();
    }
}