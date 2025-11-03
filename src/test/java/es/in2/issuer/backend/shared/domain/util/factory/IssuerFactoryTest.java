package es.in2.issuer.backend.shared.domain.util.factory;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.service.impl.RemoteSignatureServiceImpl;
import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig;
import es.in2.issuer.backend.shared.infrastructure.config.RemoteSignatureConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuerFactoryTest {

    @Mock private RemoteSignatureConfig remoteSignatureConfig;
    @Mock private DefaultSignerConfig defaultSignerConfig;
    @Mock private RemoteSignatureServiceImpl remoteSignatureServiceImpl;
    @InjectMocks private IssuerFactory issuerFactory;

    private final String procedureId = "proc-123";

    @BeforeEach
    void setUp() {
        // Default: not SERVER -> remote branch is used when explicitly set to CLOUD in tests
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn("OTHER");
    }

    @Test
    void createDetailedIssuer_LocalServerSide_ReturnsFromDefaultConfig() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_SERVER);
        when(defaultSignerConfig.getOrganizationIdentifier()).thenReturn("ORG-ID");
        when(defaultSignerConfig.getOrganization()).thenReturn("MyOrg");
        when(defaultSignerConfig.getCountry()).thenReturn("ES");
        when(defaultSignerConfig.getCommonName()).thenReturn("CN");
        when(defaultSignerConfig.getSerialNumber()).thenReturn("SN123");

        StepVerifier.create(issuerFactory.createDetailedIssuer(procedureId, "x@y.z"))
                .assertNext(issuer -> {
                    assertEquals(DID_ELSI + "ORG-ID", issuer.id());
                    assertEquals("ORG-ID", issuer.organizationIdentifier());
                    assertEquals("MyOrg", issuer.organization());
                    assertEquals("ES", issuer.country());
                    assertEquals("CN", issuer.commonName());
                    assertEquals("SN123", issuer.serialNumber());
                })
                .verifyComplete();
    }


    @Test
    void createSimpleIssuer_LocalServerSide_ReturnsFromDefaultConfig() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_SERVER);
        when(defaultSignerConfig.getOrganizationIdentifier()).thenReturn("ORG-ID");

        StepVerifier.create(issuerFactory.createSimpleIssuer(procedureId, "someone@mail"))
                .assertNext(simple -> assertEquals(DID_ELSI + "ORG-ID", simple.getId()))
                .verifyComplete();
    }

    @Test
    void createDetailedIssuer_Remote_CredentialsMismatch_CompletesSilently() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureServiceImpl.validateCredentials()).thenReturn(Mono.just(false));
        when(remoteSignatureServiceImpl.isRecoverableError(any())).thenReturn(false);
        when(remoteSignatureServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuer(procedureId, ""))
                .verifyComplete();

        verify(remoteSignatureServiceImpl).validateCredentials();
        verify(remoteSignatureServiceImpl).isRecoverableError(any());
        verify(remoteSignatureServiceImpl).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(remoteSignatureServiceImpl);
    }


    @Test
    void createDetailedIssuerRemote_SuccessPath() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureServiceImpl.validateCredentials()).thenReturn(Mono.just(true));
        when(remoteSignatureServiceImpl.requestAccessToken(isNull(), eq(SIGNATURE_REMOTE_SCOPE_SERVICE)))
                .thenReturn(Mono.just("token"));
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-id");
        when(remoteSignatureServiceImpl.requestCertificateInfo("token", "cred-id"))
                .thenReturn(Mono.just("cert-info"));

        DetailedIssuer expected = DetailedIssuer.builder()
                .id("id1")
                .organizationIdentifier("org1")
                .organization("o")
                .country("ES")
                .commonName("CN")
                .serialNumber("SN")
                .build();

        // New signature: extractIssuerFromCertificateInfo(certInfo)
        when(remoteSignatureServiceImpl.extractIssuerFromCertificateInfo("cert-info"))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(issuerFactory.createDetailedIssuer(procedureId, "user@mail"))
                .expectNext(expected)
                .verifyComplete();

        verify(remoteSignatureServiceImpl).validateCredentials();
        verify(remoteSignatureServiceImpl).requestAccessToken(null, SIGNATURE_REMOTE_SCOPE_SERVICE);
        verify(remoteSignatureServiceImpl).requestCertificateInfo("token", "cred-id");
        verify(remoteSignatureServiceImpl).extractIssuerFromCertificateInfo("cert-info");
        verifyNoMoreInteractions(remoteSignatureServiceImpl);
    }

    @Test
    void createSimpleIssuerRemote_SuccessPath() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureServiceImpl.validateCredentials()).thenReturn(Mono.just(true));
        when(remoteSignatureServiceImpl.requestAccessToken(isNull(), eq(SIGNATURE_REMOTE_SCOPE_SERVICE)))
                .thenReturn(Mono.just("token"));
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-id");
        when(remoteSignatureServiceImpl.requestCertificateInfo("token", "cred-id"))
                .thenReturn(Mono.just("cert-info"));

        DetailedIssuer detailed = DetailedIssuer.builder().id("issuer-id").build();
        when(remoteSignatureServiceImpl.extractIssuerFromCertificateInfo("cert-info"))
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer(procedureId, "user@mail"))
                .assertNext(simple -> assertEquals("issuer-id", simple.getId()))
                .verifyComplete();
    }

    @Test
    void createDetailedIssuerRemote_GenericMidFlowError_CompletesAfterPostRecover() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureServiceImpl.validateCredentials()).thenReturn(Mono.just(true));
        // Fail after validate -> will be caught by onErrorResume
        when(remoteSignatureServiceImpl.requestAccessToken(any(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("boom")));
        when(remoteSignatureServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuer(procedureId, ""))
                .verifyComplete();

        verify(remoteSignatureServiceImpl).handlePostRecoverError(procedureId, "");
    }

    @Test
    void createDetailedIssuerRemote_ValidateCredentialsRecoverable_ThenHandlePostRecoverCompletes() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureServiceImpl.validateCredentials())
                .thenReturn(Mono.error(new IOException("timeout1")))
                .thenReturn(Mono.error(new IOException("timeout2")))
                .thenReturn(Mono.error(new IOException("timeout3")))
                .thenReturn(Mono.error(new IOException("timeout4")));
        when(remoteSignatureServiceImpl.isRecoverableError(any())).thenReturn(true);
        when(remoteSignatureServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuer(procedureId, ""))
                .verifyComplete();

        verify(remoteSignatureServiceImpl, times(4)).validateCredentials();
        verify(remoteSignatureServiceImpl).handlePostRecoverError(procedureId, "");
    }

    @Test
    void createDetailedIssuerRemote_ValidateCredentialsRecoverable_ThenHandlePostRecoverFails() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureServiceImpl.validateCredentials())
                .thenReturn(Mono.error(new IOException("timeout1")));
        when(remoteSignatureServiceImpl.isRecoverableError(any())).thenReturn(true);
        RuntimeException postEx = new RuntimeException("post-recover failed");
        when(remoteSignatureServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.error(postEx));

        StepVerifier.create(issuerFactory.createDetailedIssuer(procedureId, ""))
                .expectErrorSatisfies(ex -> assertEquals(postEx, ex))
                .verify();

        verify(remoteSignatureServiceImpl).handlePostRecoverError(procedureId, "");
    }
}
