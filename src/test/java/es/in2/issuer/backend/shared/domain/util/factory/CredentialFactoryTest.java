package es.in2.issuer.backend.shared.domain.util.factory;

import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialFactoryTest {

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @InjectMocks
    private CredentialFactory credentialFactory;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

//    @Test
//    void testMapCredentialIntoACredentialProcedureRequest_Success() {
//        //Arrange
//        String processId = "processId";
//        JsonNode jsonNode = mock(JsonNode.class);
//        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
//                .operationMode("S")
//                .schema("LEARCredentialEmployee")
//                .payload(jsonNode)
//                .build();
//
//        CredentialProcedureCreationRequest credentialProcedureCreationRequest = mock(CredentialProcedureCreationRequest.class);
//
//        when(learCredentialEmployeeFactory.mapAndBuildLEARCredentialEmployee(jsonNode, preSubmittedCredentialDataRequest.operationMode()))
//                .thenReturn(Mono.just(credentialProcedureCreationRequest));
//
//        //Act & Assert
//        StepVerifier.create(credentialFactory.mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialDataRequest))
//                .expectNext(credentialProcedureCreationRequest)
//                .verifyComplete();
//
//        verify(learCredentialEmployeeFactory).mapAndBuildLEARCredentialEmployee(jsonNode, preSubmittedCredentialDataRequest.operationMode());
//    }

//    @Test
//    void testMapCredentialIntoACredentialProcedureRequest_Failure() {
//        //Arrange
//        String processId = "processId";
//        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
//                .schema("UNSUPPORTED_CREDENTIAL")
//                .build();
//
//        //Act & Assert
//        StepVerifier.create(credentialFactory.mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialDataRequest))
//                .expectError(CredentialTypeUnsupportedException.class)
//                .verify();
//
//        verify(learCredentialEmployeeFactory, never()).mapAndBuildLEARCredentialEmployee(any(), any());
//    }

    @Test
    void testMapCredentialIntoACredentialProcedureRequest_Failure() {
        //Arrange
        String processId = "processId";
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
                .schema("UNSUPPORTED_CREDENTIAL")
                .build();

        //Act & Assert
        StepVerifier.create(credentialFactory.mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialDataRequest, ""))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();

        verify(learCredentialEmployeeFactory, never()).mapAndBuildLEARCredentialEmployee(any(), any(), any());
    }

    @Test
    void testBindCryptographicCredentialSubjectId_Success() {
        //Arrange
        String processId = "processId";
        String credentialType = "LEARCredentialEmployee";
        String credential = "credential";
        String mandateeId = "mandateeId";
        String result = "result";

        when(learCredentialEmployeeFactory.bindCryptographicCredentialSubjectId(credential, mandateeId))
                .thenReturn(Mono.just(result));

        //Act & Assert
        StepVerifier.create(credentialFactory.bindCryptographicCredentialSubjectId(processId, credentialType, credential, mandateeId))
                .expectNext(result)
                .verifyComplete();

        verify(learCredentialEmployeeFactory).bindCryptographicCredentialSubjectId(credential, mandateeId);
    }

    @Test
    void testBindCryptographicCredentialSubjectId_Failure() {
        //Arrange
        String processId = "processId";
        String credentialType = "UNSUPPORTED_CREDENTIAL";
        String credential = "credential";
        String mandateeId = "mandateeId";

        //Act & Assert
        StepVerifier.create(credentialFactory.bindCryptographicCredentialSubjectId(processId, credentialType, credential, mandateeId))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();

        verify(learCredentialEmployeeFactory, never()).bindCryptographicCredentialSubjectId(anyString(), anyString());
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_Success() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String boundCredential = "boundCredential";
        String format = "format";
        String authServerNonce = "nonce";

        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId))
                .thenReturn(Mono.just(boundCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, boundCredential, format))
                .thenReturn(Mono.empty());
        when(deferredCredentialMetadataService.updateDeferredCredentialByAuthServerNonce(authServerNonce, format))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, LEAR_CREDENTIAL_EMPLOYEE, format, authServerNonce))
                .verifyComplete();

        verify(learCredentialEmployeeFactory).mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId);
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, boundCredential, format);
        verify(deferredCredentialMetadataService).updateDeferredCredentialByAuthServerNonce(authServerNonce, format);
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_UnsupportedCredentialType_Error() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String credentialType = "unsupportedType";
        String format = "format";
        String authServerNonce = "nonce";

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, credentialType, format, authServerNonce))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();

        verify(learCredentialEmployeeFactory, never()).mapCredentialAndBindIssuerInToTheCredential(any(), any());
        verify(credentialProcedureService, never()).updateDecodedCredentialByProcedureId(any(), any(), any());
        verify(deferredCredentialMetadataService, never()).updateDeferredCredentialMetadataByAuthServerNonce(any());
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_BindIssuer_Error() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String format = "format";
        String authServerNonce = "nonce";

        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId))
                .thenReturn(Mono.error(new RuntimeException("Binding error")));

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, LEAR_CREDENTIAL_EMPLOYEE, format, authServerNonce))
                .expectError(RuntimeException.class)
                .verify();

        verify(learCredentialEmployeeFactory).mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId);
        verify(credentialProcedureService, never()).updateDecodedCredentialByProcedureId(any(), any(), any());
        verify(deferredCredentialMetadataService, never()).updateDeferredCredentialMetadataByAuthServerNonce(any());
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_UpdateDB_Error() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String boundCredential = "boundCredential";
        String format = "format";
        String authServerNonce = "nonce";

        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId))
                .thenReturn(Mono.just(boundCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, boundCredential, format))
                .thenReturn(Mono.error(new RuntimeException("DB Update error")));

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, LEAR_CREDENTIAL_EMPLOYEE, format, authServerNonce))
                .expectError(RuntimeException.class)
                .verify();

        verify(learCredentialEmployeeFactory).mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId);
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, boundCredential, format);
        verify(deferredCredentialMetadataService).updateDeferredCredentialByAuthServerNonce(authServerNonce, format);
    }




}