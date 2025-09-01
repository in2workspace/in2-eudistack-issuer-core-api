package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTClaimMissingException;
import es.in2.issuer.backend.shared.domain.exception.JWTCreationException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.infrastructure.crypto.CryptoComponent;
import io.github.novacrypto.base58.Base58;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.DID_KEY;

@Slf4j
@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

    private final ObjectMapper objectMapper;
    private final CryptoComponent cryptoComponent;

    @Override
    public String generateJWT(String payload) {
        try {
            // Get ECKey
            ECKey ecJWK = cryptoComponent.getECKey();
            // Set Header
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(cryptoComponent.getECKey().getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();
            // Set Payload
            JWTClaimsSet claimsSet = convertPayloadToJWTClaimsSet(payload);
            // Create JWT for ES256 algorithm
            SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
            // Sign with a private EC key
            JWSSigner signer = new ECDSASigner(ecJWK);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new JWTCreationException("Error creating JWT");
        }
    }

    private JWTClaimsSet convertPayloadToJWTClaimsSet(String payload) {
        try {
            JsonNode jsonNode = objectMapper.readTree(payload);
            Map<String, Object> claimsMap = objectMapper.convertValue(jsonNode, new TypeReference<>() {
            });
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            for (Map.Entry<String, Object> entry : claimsMap.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
            return builder.build();
        } catch (JsonProcessingException e) {
            log.error("Error while parsing the JWT payload", e);
            throw new JWTCreationException("Error while parsing the JWT payload");
        }

    }
    @Override
    public Mono<Boolean> validateJwtSignatureReactive(JWSObject jwsObject) {
        String kid = jwsObject.getHeader().getKeyID();
        log.debug("validateJwtSignatureReactive - kid: {}", kid);
        String encodedPublicKey = extractEncodedPublicKey(kid);
        log.debug("validateJwtSignatureReactive - encodedPublicKey: {}", encodedPublicKey);
        return decodePublicKeyIntoBytes(encodedPublicKey)
                .flatMap(publicKeyBytes -> validateJwtSignature(jwsObject.getParsedString(), publicKeyBytes));
    }


    public String extractEncodedPublicKey(String kid) {
        String prefix = DID_KEY;
        String encodedPublicKey;

        if (kid.contains("#")) {
            encodedPublicKey = kid.substring(kid.indexOf("#") + 1);
        } else if (kid.contains(prefix)) {
            encodedPublicKey = kid.substring(kid.indexOf(prefix) + prefix.length());
        } else {
            log.error("❌ 'kid' format not correct");
            throw new IllegalArgumentException("'kid' format not correct");
        }

        return encodedPublicKey;
    }


    private Mono<Boolean> validateJwtSignature(String jwtString, byte[] publicKeyBytes) {
        return Mono.fromCallable(() -> {
            try {
                log.debug("validateJwtSignature");
                // Set the curve as secp256r1
                ECCurve curve = new SecP256R1Curve();
                BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));

                // Recover the Y coordinate from the X coordinate and the curve
                BigInteger y = curve.decodePoint(publicKeyBytes).getYCoord().toBigInteger();

                ECPoint point = new ECPoint(x, y);

                // Fetch the ECParameterSpec for secp256r1
                ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
                ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

                // Create a KeyFactory and generate the public key
                KeyFactory kf = KeyFactory.getInstance("EC");
                ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
                PublicKey publicKey = kf.generatePublic(pubKeySpec);

                // Parse the JWT and create a verifier
                SignedJWT signedJWT = SignedJWT.parse(jwtString);
                ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);

                // Verify the signature
                return signedJWT.verify(verifier);
            } catch (Exception e) {
                return false; // In case of any exception, return false
            }
        });
    }

    private Mono<byte[]> decodePublicKeyIntoBytes(String publicKey) {
        return Mono.fromCallable(() -> {
            // Remove the prefix "z" to get the multibase encoded string
            if (!publicKey.startsWith("z")) {
                throw new IllegalArgumentException("Invalid Public Key.");
            }
            String multibaseEncoded = publicKey.substring(1);

            // Multibase decode (Base58) the encoded part to get the bytes
            byte[] decodedBytes = Base58.base58Decode(multibaseEncoded);

            // Multicodec prefix is fixed for "0x1200" for the secp256r1 curve
            int prefixLength = 2;

            // Extract public key bytes after the multicodec prefix
            byte[] publicKeyBytes = new byte[decodedBytes.length - prefixLength];
            System.arraycopy(decodedBytes, prefixLength, publicKeyBytes, 0, publicKeyBytes.length);

            return publicKeyBytes;
        });
    }

    @Override
    public SignedJWT parseJWT(String jwt) {
        try {
            return SignedJWT.parse(jwt);
        } catch (ParseException e) {
            log.error("Error when parsing JWTs: {}", e.getMessage());
            throw new JWTParsingException("Error when parsing JWTs");
        }
    }

    @Override
    public Payload getPayloadFromSignedJWT(SignedJWT signedJWT) {
        return signedJWT.getPayload();
    }

    @Override
    public String getClaimFromPayload(Payload payload, String claimName) {
        Object claimValue = payload.toJSONObject().get(claimName);
        if (claimValue == null) {
            throw new JWTClaimMissingException(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName));
        }
        try {
            return objectMapper.writeValueAsString(claimValue);
        } catch (JsonProcessingException e) {
            throw new JWTClaimMissingException(String.format("Failed to serialize '%s' claim to JSON: %s", claimName, e.getMessage()));
        }
    }

    @Override
    public Long getExpirationFromToken(String token) {
        Payload payload = getPayloadFromSignedJWT(parseJWT(token));
        Object claimValue = payload.toJSONObject().get("exp");
        if (claimValue == null) {
            throw new JWTClaimMissingException("The 'exp' claim is missing in the JWT payload.");
        }
        if (claimValue instanceof Number number) {
            return number.longValue();
        } else {
            throw new JWTClaimMissingException("The 'exp' claim is not a valid number in the JWT payload.");
        }
    }
}
