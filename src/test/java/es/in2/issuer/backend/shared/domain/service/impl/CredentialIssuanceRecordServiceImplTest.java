package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedDataCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialIssuanceRecord;
import es.in2.issuer.backend.shared.domain.repository.CredentialIssuanceRepository;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.shared.objectmother.LEARCredentialEmployeeMother;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceRecordServiceImplTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CacheStore<String> cacheStoreForTransactionCode;

    @Mock
    private CredentialIssuanceRepository credentialIssuanceRepository;

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private CredentialIssuanceRecordServiceImpl credentialIssuanceRecordService;

    @Test
    void create_withCorrectData_returnsExpectedActivationCode() throws JsonProcessingException {
        String expectedActivationCode = "12345";
        String processId = "processId";

        PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest =
                PreSubmittedDataCredentialRequest
                        .builder()
                        .payload(JsonNodeFactory.instance.objectNode())
                        .build();
        String token = "token";
        LEARCredentialEmployee learCredentialEmployee =
                LEARCredentialEmployeeMother.withIdAndMandatorOrganizationIdentifierAndMandateeEmail();
        CredentialIssuanceRecord savedRecord = new CredentialIssuanceRecord();
        savedRecord.setId(UUID.randomUUID());

        when(accessTokenService.getOrganizationId(token))
                .thenReturn(Mono.just("organizationId"));
        when(objectMapper.treeToValue(nullable(JsonNode.class), eq(LEARCredentialEmployee.class)))
                .thenReturn(learCredentialEmployee);
        when(credentialIssuanceRepository.save(any()))
                .thenReturn(Mono.just(savedRecord));
        when(cacheStoreForTransactionCode.add(anyString(), anyString()))
                .thenReturn(Mono.just(expectedActivationCode));

        var result = credentialIssuanceRecordService.create(processId, preSubmittedDataCredentialRequest, token);

        StepVerifier
                .create(result)
                .assertNext(activationCode ->
                        assertThat(expectedActivationCode).isEqualTo(activationCode))
                .verifyComplete();
    }

    @Test
    void create_withInvalidPayload_ReturnsJsonProcessingException() throws JsonProcessingException {
        String processId = "processId";

        PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest =
                PreSubmittedDataCredentialRequest
                        .builder()
                        .payload(JsonNodeFactory.instance.objectNode())
                        .build();
        String token = "token";

        CredentialIssuanceRecord savedRecord = new CredentialIssuanceRecord();
        savedRecord.setId(UUID.randomUUID());

        when(accessTokenService.getOrganizationId(token))
                .thenReturn(Mono.just("organizationId"));

        when(objectMapper.treeToValue(nullable(JsonNode.class), eq(LEARCredentialEmployee.class)))
                .thenThrow(new JsonParseException(""));

        var result = credentialIssuanceRecordService.create(processId, preSubmittedDataCredentialRequest, token);

        StepVerifier
                .create(result)
                .expectError(ParseErrorException.class)
                .verify();
    }
}