package es.in2.issuer.backend.statuslist.infrastructure.adapter;


import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.statuslist.domain.exception.*;
import es.in2.issuer.backend.statuslist.domain.factory.BitstringStatusListCredentialFactory;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.service.impl.BitstringStatusListRevocationService;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusList;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BitstringStatusListProviderTest {

    @Mock
    private AppConfig appConfig;

    @Mock
    private StatusListRepository statusListRepository;

    @Mock
    private StatusListIndexRepository statusListIndexRepository;

    @Mock
    private BitstringStatusListCredentialFactory statusListBuilder;

    @Mock
    private BitstringStatusListRevocationService revocationService;

    @Mock
    private BitstringStatusListIndexReservation statusListIndexReservationService;

    @Mock
    private StatusListSigner statusListSigner;

    @Mock
    private IssuerFactory issuerFactory;

    @InjectMocks
    private BitstringStatusListProvider bitstringStatusListProvider;

    private static final Long TEST_LIST_ID = 1L;
    private static final String TEST_SIGNED_CREDENTIAL = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_PROCEDURE_ID = "550e8400-e29b-41d4-a716-446655440000";
    private static final String TEST_TOKEN = "test-token";
    private static final String TEST_ISSUER_URL = "https://issuer.example.com";
    private static final String TEST_ISSUER_DID = "did:example:issuer";
    private static final int TEST_IDX = 5;

    @BeforeEach
    void setUp() {
        lenient().when(appConfig.getIssuerBackendUrl()).thenReturn(TEST_ISSUER_URL);
    }

    // ========== Tests for getSignedStatusListCredential ==========

    @Test
    void getSignedStatusListCredential_shouldReturnSignedCredential_whenListExistsWithSignedCredential() {
        // Arrange
        StatusList statusList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(statusList));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID))
                .expectNext(TEST_SIGNED_CREDENTIAL)
                .verifyComplete();

        verify(statusListRepository).findById(TEST_LIST_ID);
    }

    @Test
    void getSignedStatusListCredential_shouldThrowStatusListNotFoundException_whenListDoesNotExist() {
        // Arrange
        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID))
                .expectError(StatusListNotFoundException.class)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
    }




    @Test
    void getSignedStatusListCredential_shouldThrowException_whenListIdIsNull() {
        // Act & Assert
        assertThatThrownBy(() -> bitstringStatusListProvider.getSignedStatusListCredential(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("listId");

        verifyNoInteractions(statusListRepository);
    }

    // ========== Tests for allocateEntry ==========

    @Test
    void allocateEntry_shouldReturnExistingEntry_whenProcedureAlreadyAllocated() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        StatusListIndex existingIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                10,
                procedureUuid,
                Instant.now()
        );

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("10")
                .statusListCredential(expectedListUrl)
                .build();

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.just(existingIndex));

        when(statusListBuilder.buildStatusListEntry(expectedListUrl, 10, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexRepository).findByProcedureId(procedureUuid);
        verify(statusListBuilder).buildStatusListEntry(expectedListUrl, 10, purpose);
    }

    @Test
    void allocateEntry_shouldAllocateNewEntry_whenNoPreviousAllocation() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        StatusList existingList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        StatusListIndex reservedIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                5,
                procedureUuid,
                Instant.now()
        );

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("5")
                .statusListCredential(expectedListUrl)
                .build();

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurpose("revocation"))
                .thenReturn(Mono.just(existingList));

        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(100L));

        when(statusListIndexReservationService.reserve(TEST_LIST_ID, TEST_PROCEDURE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(expectedListUrl, 5, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexRepository).findByProcedureId(procedureUuid);
        verify(statusListRepository).findLatestByPurpose("revocation");
        verify(statusListIndexRepository).countByStatusListId(TEST_LIST_ID);
        verify(statusListIndexReservationService).reserve(TEST_LIST_ID, TEST_PROCEDURE_ID);
        verify(statusListBuilder).buildStatusListEntry(expectedListUrl, 5, purpose);
    }

    @Test
    void allocateEntry_shouldThrowException_whenPurposeIsNull() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(null, TEST_PROCEDURE_ID, TEST_TOKEN)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("purpose");

        verifyNoInteractions(statusListIndexRepository);
    }

    @Test
    void allocateEntry_shouldThrowException_whenProcedureIdIsNull() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(StatusPurpose.REVOCATION, null, TEST_TOKEN)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("procedureId");

        verifyNoInteractions(statusListIndexRepository);
    }


    @Test
    void allocateEntry_shouldThrowException_whenTokenIsNull() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(StatusPurpose.REVOCATION, TEST_PROCEDURE_ID, null)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("token");

        verifyNoInteractions(statusListIndexRepository);
    }


    @Test
    void allocateEntry_shouldThrowException_whenProcedureIdIsInvalidUUID() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(StatusPurpose.REVOCATION, "invalid-uuid", TEST_TOKEN)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(IllegalArgumentException.class);
    }


    @Test
    void allocateEntry_shouldCreateNewList_whenExistingListIsNearCapacity() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        Long newListId = 2L;

        StatusList existingList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        StatusList newListSaved = new StatusList(
                newListId,
                "revocation",
                "newEncodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        StatusListIndex reservedIndex = new StatusListIndex(
                1L,
                newListId,
                0,
                procedureUuid,
                Instant.now()
        );

        String newListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + newListId;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("0")
                .statusListCredential(newListUrl)
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurpose("revocation"))
                .thenReturn(Mono.just(existingList));

        // Simular que la llista està a prop de la capacitat (>90%)
        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(115000L)); // Més del 90% de 131072

        // Mock per crear la nova llista - s'anomena dues vegades durant el flux
        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(newListSaved));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(newListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(newListId)))
                .thenReturn(Mono.just("newSignedJwt"));

        when(statusListRepository.updateSignedCredential(newListId, "newSignedJwt"))
                .thenReturn(Mono.just(1));

        when(statusListIndexReservationService.reserve(newListId, TEST_PROCEDURE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(newListUrl, 0, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexRepository).findByProcedureId(procedureUuid);
        verify(statusListRepository).findLatestByPurpose("revocation");
        verify(statusListIndexRepository).countByStatusListId(TEST_LIST_ID);
        verify(statusListRepository, atLeastOnce()).save(any(StatusList.class));
        verify(issuerFactory, atLeastOnce()).createSimpleIssuer();
        verify(statusListSigner, atLeastOnce()).sign(anyMap(), eq(TEST_TOKEN), eq(newListId));
        verify(statusListRepository, atLeastOnce()).updateSignedCredential(eq(newListId), anyString());
        verify(statusListIndexReservationService).reserve(newListId, TEST_PROCEDURE_ID);
    }

    @Test
    void allocateEntry_shouldAllocateNewEntry_whenNoListExists() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        StatusList newList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        StatusListIndex reservedIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                0,
                procedureUuid,
                Instant.now()
        );

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("0")
                .statusListCredential(expectedListUrl)
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurpose("revocation"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(newList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID)))
                .thenReturn(Mono.just("signedJwt"));

        when(statusListRepository.updateSignedCredential(TEST_LIST_ID, "signedJwt"))
                .thenReturn(Mono.just(1));

        // Aquest mock és necessari perquè després de crear la llista, es fa un count
        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(0L));

        when(statusListIndexReservationService.reserve(TEST_LIST_ID, TEST_PROCEDURE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(expectedListUrl, 0, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListRepository).findLatestByPurpose("revocation");
        verify(statusListRepository, atLeastOnce()).save(any(StatusList.class));
        verify(issuerFactory, atLeastOnce()).createSimpleIssuer();
        verify(statusListSigner, atLeastOnce()).sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID));
        verify(statusListIndexRepository).countByStatusListId(TEST_LIST_ID);
        verify(statusListIndexReservationService).reserve(TEST_LIST_ID, TEST_PROCEDURE_ID);
    }

    @Test
    void allocateEntry_shouldRollbackDeleteAndPropagateError_whenSigningFailsDuringCreateNewList() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurpose("revocation"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        RuntimeException signError = new RuntimeException("sign failed");
        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID)))
                .thenReturn(Mono.error(signError));

        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectErrorMatches(e -> e == signError)
                .verify();

        verify(statusListRepository).deleteById(TEST_LIST_ID);
    }

    @Test
    void allocateEntry_shouldPropagateOriginalError_whenRollbackDeleteAlsoFails() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurpose("revocation"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        RuntimeException signError = new RuntimeException("sign failed");
        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID)))
                .thenReturn(Mono.error(signError));

        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.error(new RuntimeException("delete failed")));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectErrorMatches(e -> e == signError)
                .verify();

        verify(statusListRepository).deleteById(TEST_LIST_ID);
    }

    @Test
    void allocateEntry_shouldRollbackAndThrowStatusListSigningPersistenceException_whenUpdateSignedCredentialIsZero() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurpose("revocation"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID)))
                .thenReturn(Mono.just("jwt"));

        when(statusListRepository.updateSignedCredential(TEST_LIST_ID, "jwt"))
                .thenReturn(Mono.just(0));

        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectError(StatusListSigningPersistenceException.class)
                .verify();

        verify(statusListRepository).deleteById(TEST_LIST_ID);
    }

    @Test
    void allocateEntry_shouldCreateNewListAndRetryReserve_whenIndexReservationExhausted() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusList existingList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        Long newListId = 2L;
        StatusList newListSaved = new StatusList(
                newListId,
                "revocation",
                "newEncodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        StatusListIndex reservedIndex = new StatusListIndex(
                1L,
                newListId,
                7,
                procedureUuid,
                Instant.now()
        );

        String newListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + newListId;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("7")
                .statusListCredential(newListUrl)
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurpose("revocation"))
                .thenReturn(Mono.just(existingList));

        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(0L));

        // First reserve fails with exhausted
        when(statusListIndexReservationService.reserve(TEST_LIST_ID, TEST_PROCEDURE_ID))
                .thenReturn(Mono.error(new IndexReservationExhaustedException("", new Exception())));

        // Create new list
        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(newListSaved));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(newListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(newListId)))
                .thenReturn(Mono.just("newJwt"));

        when(statusListRepository.updateSignedCredential(newListId, "newJwt"))
                .thenReturn(Mono.just(1));

        // Second reserve succeeds on the new list
        when(statusListIndexReservationService.reserve(newListId, TEST_PROCEDURE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(newListUrl, 7, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexReservationService).reserve(TEST_LIST_ID, TEST_PROCEDURE_ID);
        verify(statusListIndexReservationService).reserve(newListId, TEST_PROCEDURE_ID);
    }

    @Test
    void getSignedStatusListCredential_shouldPropagateError_whenRepositoryFails() {
        // Arrange
        RuntimeException repoError = new RuntimeException("db down");

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.error(repoError));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID))
                .expectErrorMatches(e -> e == repoError)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
        verifyNoMoreInteractions(statusListRepository);
    }

    @ParameterizedTest(name = "should throw when signed credential is missing: \"{0}\"")
    @NullSource
    @ValueSource(strings = {"", "   "})
    void getSignedStatusListCredential_shouldThrowException_whenSignedCredentialIsMissing(String signedCredential) {
        // Arrange
        StatusList statusList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "encodedList",
                signedCredential,
                Instant.now(),
                Instant.now()
        );

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(statusList));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID))
                .expectError(SignedStatusListCredentialNotAvailableException.class)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
    }



    @Test
    void revoke_shouldComplete_whenRevocationSucceeds() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");

        StatusList currentRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                new BitstringEncoder().createEmptyEncodedList(131072),
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        StatusList updatedRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "updatedEncodedList",
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();

        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(currentRow));

        when(revocationService.applyRevocation(currentRow, TEST_IDX))
                .thenReturn(updatedRow);

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(listUrl, TEST_ISSUER_DID, "revocation", "updatedEncodedList"))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID)))
                .thenReturn(Mono.just("jwt"));

        when(statusListRepository.updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        )).thenReturn(Mono.just(1));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_PROCEDURE_ID, TEST_TOKEN))
                .verifyComplete();

        verify(statusListIndexRepository).findByProcedureId(procedureUuid);
        verify(statusListRepository).findById(TEST_LIST_ID);
        verify(revocationService).applyRevocation(currentRow, TEST_IDX);
        verify(statusListRepository).updateSignedAndEncodedIfUnchanged(eq(TEST_LIST_ID), anyString(), anyString(), eq(updatedAt));
    }

    @Test
    void revoke_shouldThrowStatusListIndexNotFoundException_whenNoIndexExists() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectError(StatusListIndexNotFoundException.class)
                .verify();

        verify(statusListIndexRepository).findByProcedureId(procedureUuid);
        verifyNoInteractions(statusListRepository);
    }

    @Test
    void revoke_shouldThrowStatusListNotFoundException_whenStatusListDoesNotExist() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectError(StatusListNotFoundException.class)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
        verifyNoInteractions(revocationService);
    }

    @Test
    void revoke_shouldCompleteWithoutUpdating_whenAlreadyRevoked() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        // Build an encodedList where TEST_IDX is already revoked (bit=1)
        BitstringEncoder enc = new BitstringEncoder();
        String empty = enc.createEmptyEncodedList(131072);

        StatusList baseRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                empty,
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        // Use the real revocation logic once to produce a list with the bit set,
        // then feed that to the provider so resolveRevocationCandidate sees it as already revoked.
        BitstringStatusListRevocationService realRevocation = new BitstringStatusListRevocationService();
        StatusList revokedRow = realRevocation.applyRevocation(baseRow, TEST_IDX);

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(revokedRow));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_PROCEDURE_ID, TEST_TOKEN))
                .verifyComplete();

        verify(statusListIndexRepository).findByProcedureId(procedureUuid);
        verify(statusListRepository).findById(TEST_LIST_ID);

        verifyNoInteractions(statusListSigner);
        verify(statusListRepository, never()).updateSignedAndEncodedIfUnchanged(anyLong(), anyString(), anyString(), any());
        verify(revocationService, never()).applyRevocation(any(), anyInt());
    }

    @Test
    void revoke_shouldRetryAndSucceed_whenOptimisticUpdateHappens() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");

        StatusList currentRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                new BitstringEncoder().createEmptyEncodedList(131072),
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        StatusList updatedRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "updatedEncodedList",
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        // Will be called at least twice because of retry
        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(currentRow), Mono.just(currentRow));

        when(revocationService.applyRevocation(currentRow, TEST_IDX))
                .thenReturn(updatedRow);

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(listUrl, TEST_ISSUER_DID, "revocation", "updatedEncodedList"))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID)))
                .thenReturn(Mono.just("jwt"));

        // First attempt: 0 rows updated -> OptimisticUpdateException
        // Second attempt: 1 row updated -> success
        when(statusListRepository.updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        )).thenReturn(Mono.just(0), Mono.just(1));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_PROCEDURE_ID, TEST_TOKEN))
                .verifyComplete();

        verify(statusListRepository, times(2)).updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        );
    }

    @Test
    void revoke_shouldThrowException_whenProcedureIdIsInvalidUUID() {
        Mono<Void> mono = monoFromCall(() ->
                bitstringStatusListProvider.revoke("invalid-uuid", TEST_TOKEN)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid UUID string");

        verifyNoInteractions(statusListIndexRepository);
        verifyNoInteractions(statusListRepository);
    }


    @Test
    void revoke_shouldFailAfterMaxRetries_whenOptimisticUpdateNeverSucceeds() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_PROCEDURE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");

        StatusList currentRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                new BitstringEncoder().createEmptyEncodedList(131072),
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        StatusList updatedRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "updatedEncodedList",
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByProcedureId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        // Will be called once per attempt
        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(currentRow));

        when(revocationService.applyRevocation(currentRow, TEST_IDX))
                .thenReturn(updatedRow);

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(listUrl, TEST_ISSUER_DID, "revocation", "updatedEncodedList"))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID)))
                .thenReturn(Mono.just("jwt"));

        // Always fails -> triggers OptimisticUpdateException every attempt
        when(statusListRepository.updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        )).thenReturn(Mono.just(0));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_PROCEDURE_ID, TEST_TOKEN))
                .expectErrorMatches(e ->
                        e.getClass().getName().contains("RetryExhaustedException")
                                && e.getCause() instanceof OptimisticUpdateException
                )
                .verify();


        // maxAttempts=5 -> 5 invocations
        verify(statusListRepository, times(5)).updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        );
    }

    private static <T> Mono<T> monoFromCall(Supplier<Mono<T>> call) {
        try {
            return call.get();
        } catch (Throwable t) {
            return Mono.error(t);
        }
    }

}