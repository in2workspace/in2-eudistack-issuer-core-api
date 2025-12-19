package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.model.entities.BitstringStatusListCredential;
import es.in2.issuer.backend.backoffice.domain.model.entities.StatusCredentialList;
import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import es.in2.issuer.backend.backoffice.domain.repository.CredentialStatusRepository;
import es.in2.issuer.backend.backoffice.domain.repository.StatusCredentialListRepository;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.RemoteSignatureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.zip.GZIPOutputStream;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusServiceImpl implements CredentialStatusService {

    private final CredentialStatusRepository credentialStatusRepository;
    private final StatusCredentialListRepository statusCredentialListRepository;
    private final RemoteSignatureService remoteSignatureService;
    private final ObjectMapper objectMapper;
    private static final int MIN_BITSTRING_BYTES = 16 * 1024; //cal?

    // contrasentit que es faci "byListId" havent-hi un sol índex, però canviar-ho seria feina innecessària
    // Flux tenia sentit abans, però ara que es retorna la vc list no cal
    @Override
    public Flux<String> getCredentialsByListId(int listId) {
        // for old credentials with PlainList credential status
        if(listId == 1){
            return getOldCredentialsListByListId(listId);
        }else{
            return Flux.just("dummy");
//            return getNewCredentialsListByListId(listId);
        }
    }

    @Override
    public Mono<Void> revokeCredential(int listId, CredentialStatus credentialStatus) {
        if(listId == 1){
            return revokeOldCredential(listId, credentialStatus);
        }else{
            // todo revokeNewCredential()
            return Mono.empty();
        }
    }

    private Flux<String> getNewCredentialsListByListId(int listId) {

        return statusCredentialListRepository.findByListId(listId)
                .switchIfEmpty(Mono.error(new IllegalStateException("Status list not found for listId: " + listId)))
                .flatMap(this::buildBitstringStatusListCredentialJson)
                .flatMap(credentialJson -> {
                    SignatureRequest signatureRequest = new SignatureRequest(new SignatureConfiguration(SignatureType.JADES, Collections.emptyMap()), credentialJson);
                    return remoteSignatureService.executeSigningFlow(signatureRequest, "");
                })
                .map(SignedData::data)
                .flux();
    }

    private Flux<String> getOldCredentialsListByListId(int listId){
        return credentialStatusRepository.findByListId(listId)
                .map(StatusListIndex::getNonce);
    }

    private Mono<Void> revokeOldCredential(int listId, CredentialStatus credentialStatus){
        StatusListIndex statusListIndex = new StatusListIndex();
        String nonce = credentialStatus.statusListIndex();
        statusListIndex.setNonce(nonce);
        statusListIndex.setListId(listId);
        return credentialStatusRepository.save(statusListIndex)
                .then();
    }

    // bitstring BitstringStatusListCredential
    // todo: revisar tota aquesta part, assegurar que no hi ha codi duplicat
    private Mono<String> buildBitstringStatusListCredentialJson(StatusCredentialList statusList) {
        BitstringStatusListCredential vc = mapToBitstringStatusListCredential(statusList);
        try {
            String json = objectMapper.writeValueAsString(vc);
            return Mono.just(json);
        } catch (JsonProcessingException e) {
            log.error("Error serializing BitstringStatusListCredential to JSON for listId {}", statusList.getListId(), e);
            return Mono.error(e);
        }
    }

    private BitstringStatusListCredential mapToBitstringStatusListCredential(StatusCredentialList statusList) {
        String encodedList = encodeBitstring(statusList.getBitstring(), statusList.getSizeBits());

        BitstringStatusListCredential.CredentialSubject credentialSubject =
                BitstringStatusListCredential.CredentialSubject.builder()
                        .id(statusList.getListId() + "#list")
                        .type("BitstringStatusList")
                        .statusPurpose(statusList.getStatusPurpose())
                        .encodedList(encodedList)
                        .build();

        OffsetDateTime validFrom = statusList.getValidFrom();
        OffsetDateTime validUntil = statusList.getValidUntil();

        return BitstringStatusListCredential.builder()
                .id(statusList.getListId())
                .type(List.of("VerifiableCredential", "BitstringStatusListCredential"))
                .issuer(statusList.getIssuer())
                .validFrom(validFrom)
                .validUntil(validUntil)
                .credentialSubject(credentialSubject)
                .build();
    }

    private String encodeBitstring(byte[] rawBitstring, Integer sizeBits) {
        byte[] normalizedBitstring = normalizeBitstringSize(rawBitstring, sizeBits);
        byte[] compressed = gzip(normalizedBitstring);
        String base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(compressed);
        return "u" + base64Url;
    }

    private byte[] normalizeBitstringSize(byte[] rawBitstring, Integer sizeBits) {
        if (rawBitstring == null) {
            int minBytes = Math.max(MIN_BITSTRING_BYTES, bitsToBytes(sizeBits));
            return new byte[minBytes];
        }

        int requiredBytes = Math.max(MIN_BITSTRING_BYTES, bitsToBytes(sizeBits));
        if (rawBitstring.length >= requiredBytes) {
            return rawBitstring;
        }

        byte[] padded = new byte[requiredBytes];
        System.arraycopy(rawBitstring, 0, padded, 0, rawBitstring.length);
        return padded;
    }

    private int bitsToBytes(Integer sizeBits) {
        if (sizeBits == null || sizeBits <= 0) {
            return MIN_BITSTRING_BYTES;
        }
        int bytes = sizeBits / 8;
        if (sizeBits % 8 != 0) {
            bytes += 1;
        }
        return bytes;
    }

    private byte[] gzip(byte[] data) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzipOut = new GZIPOutputStream(baos)) {
            gzipOut.write(data);
            gzipOut.finish();
            return baos.toByteArray();
        } catch (IOException e) {
            log.error("Error compressing bitstring with GZIP", e);
            throw new IllegalStateException("Error compressing bitstring", e);
        }
    }


}
