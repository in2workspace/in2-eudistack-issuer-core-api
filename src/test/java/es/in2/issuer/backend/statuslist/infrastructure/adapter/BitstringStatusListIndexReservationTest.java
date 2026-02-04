package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import es.in2.issuer.backend.statuslist.domain.exception.IndexReservationExhaustedException;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListIndexAllocator;
import es.in2.issuer.backend.statuslist.domain.spi.UniqueViolationClassifier;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BitstringStatusListIndexReservationTest {

    @Mock
    private StatusListIndexRepository statusListIndexRepository;

    @Mock
    private StatusListIndexAllocator indexAllocator;

    @Mock
    private UniqueViolationClassifier uniqueViolationClassifier;

    private BitstringStatusListIndexReservation service;

    @BeforeEach
    void setUp() {
        service = new BitstringStatusListIndexReservation(
                statusListIndexRepository,
                indexAllocator,
                uniqueViolationClassifier
        );
    }

    @Test
    void reserve_success_first_try() {
        long statusListId = 10L;
        UUID procedureUuid = UUID.randomUUID();
        String procedureId = procedureUuid.toString();

        when(indexAllocator.proposeIndex(anyInt())).thenReturn(123);

        StatusListIndex saved = new StatusListIndex(
                1L,
                statusListId,
                123,
                procedureUuid,
                Instant.now()
        );

        when(statusListIndexRepository.save(any(StatusListIndex.class))).thenReturn(Mono.just(saved));

        StepVerifier.create(service.reserve(statusListId, procedureId))
                .assertNext(result -> {
                    assertEquals(1L, result.id());
                    assertEquals(statusListId, result.statusListId());
                    assertEquals(123, result.idx());
                    assertEquals(procedureUuid, result.procedureId());
                    assertNotNull(result.createdAt());
                })
                .verifyComplete();

        verify(indexAllocator, times(1)).proposeIndex(anyInt());
        verify(statusListIndexRepository, times(1)).save(any(StatusListIndex.class));
        verifyNoInteractions(uniqueViolationClassifier);
    }

    @Test
    void reserve_retries_on_idx_collision_then_success() {
        long statusListId = 99L;
        UUID procedureUuid = UUID.randomUUID();
        String procedureId = procedureUuid.toString();

        // Provide indexes for each attempt (not strictly required, but helps to see multiple calls).
        when(indexAllocator.proposeIndex(anyInt()))
                .thenReturn(1, 2, 3);

        RuntimeException duplicateIdx = new RuntimeException("duplicate idx");

        // Retry filter + exhausted wrap are driven by classifier returning IDX.
        when(uniqueViolationClassifier.classify(any(Throwable.class)))
                .thenReturn(UniqueViolationClassifier.Kind.IDX);

        StatusListIndex saved = new StatusListIndex(
                77L,
                statusListId,
                3,
                procedureUuid,
                Instant.now()
        );

        AtomicInteger saveCalls = new AtomicInteger(0);
        when(statusListIndexRepository.save(any(StatusListIndex.class))).thenAnswer(inv -> {
            int n = saveCalls.incrementAndGet();
            if (n <= 2) {
                return Mono.error(duplicateIdx);
            }
            return Mono.just(saved);
        });

        StepVerifier.withVirtualTime(() -> service.reserve(statusListId, procedureId))
                // Backoff is small (5ms..100ms), this is more than enough.
                .thenAwait(Duration.ofSeconds(1))
                .assertNext(result -> {
                    assertEquals(77L, result.id());
                    assertEquals(statusListId, result.statusListId());
                    assertEquals(procedureUuid, result.procedureId());
                })
                .verifyComplete();

        verify(statusListIndexRepository, times(3)).save(any(StatusListIndex.class));
        verify(indexAllocator, times(3)).proposeIndex(anyInt());
        verify(uniqueViolationClassifier, atLeast(1)).classify(any(Throwable.class));
    }

    @Test
    void reserve_when_procedure_unique_violation_returns_existing_reservation() {
        long statusListId = 5L;
        UUID procedureUuid = UUID.randomUUID();
        String procedureId = procedureUuid.toString();

        when(indexAllocator.proposeIndex(anyInt())).thenReturn(42);

        RuntimeException duplicateProcedure = new RuntimeException("duplicate procedure");

        when(uniqueViolationClassifier.classify(any(Throwable.class)))
                .thenReturn(UniqueViolationClassifier.Kind.PROCEDURE_ID);

        StatusListIndex existing = new StatusListIndex(
                999L,
                statusListId,
                888,
                procedureUuid,
                Instant.now()
        );

        when(statusListIndexRepository.save(any(StatusListIndex.class))).thenReturn(Mono.error(duplicateProcedure));
        when(statusListIndexRepository.findByProcedureId(procedureUuid)).thenReturn(Mono.just(existing));

        StepVerifier.create(service.reserve(statusListId, procedureId))
                .assertNext(result -> {
                    assertEquals(999L, result.id());
                    assertEquals(statusListId, result.statusListId());
                    assertEquals(888, result.idx());
                    assertEquals(procedureUuid, result.procedureId());
                })
                .verifyComplete();

        verify(statusListIndexRepository, times(1)).save(any(StatusListIndex.class));
        verify(statusListIndexRepository, times(1)).findByProcedureId(procedureUuid);
        // No retry should happen because onErrorResume returns a value.
        verify(indexAllocator, times(1)).proposeIndex(anyInt());
    }

    @Test
    void reserve_when_procedure_unique_violation_and_not_found_propagates_original_error() {
        long statusListId = 6L;
        UUID procedureUuid = UUID.randomUUID();
        String procedureId = procedureUuid.toString();

        when(indexAllocator.proposeIndex(anyInt())).thenReturn(7);

        RuntimeException duplicateProcedure = new RuntimeException("duplicate procedure");

        when(uniqueViolationClassifier.classify(any(Throwable.class)))
                .thenReturn(UniqueViolationClassifier.Kind.PROCEDURE_ID);

        when(statusListIndexRepository.save(any(StatusListIndex.class))).thenReturn(Mono.error(duplicateProcedure));
        when(statusListIndexRepository.findByProcedureId(procedureUuid)).thenReturn(Mono.empty());

        StepVerifier.create(service.reserve(statusListId, procedureId))
                .expectErrorSatisfies(t -> assertSame(duplicateProcedure, t))
                .verify();

        verify(statusListIndexRepository, times(1)).save(any(StatusListIndex.class));
        verify(statusListIndexRepository, times(1)).findByProcedureId(procedureUuid);
        verify(indexAllocator, times(1)).proposeIndex(anyInt());
    }

    @Test
    void reserve_fail_fast_on_not_unique_and_does_not_wrap() {
        long statusListId = 77L;
        UUID procedureUuid = UUID.randomUUID();
        String procedureId = procedureUuid.toString();

        when(indexAllocator.proposeIndex(anyInt())).thenReturn(11);

        RuntimeException notUnique = new RuntimeException("some other constraint");
        when(uniqueViolationClassifier.classify(any(Throwable.class)))
                .thenReturn(UniqueViolationClassifier.Kind.NOT_UNIQUE);

        when(statusListIndexRepository.save(any(StatusListIndex.class))).thenReturn(Mono.error(notUnique));

        StepVerifier.create(service.reserve(statusListId, procedureId))
                .expectErrorSatisfies(t -> assertSame(notUnique, t))
                .verify();

        // Should not retry because filter only retries on IDX or UNKNOWN.
        verify(statusListIndexRepository, times(1)).save(any(StatusListIndex.class));
        verify(indexAllocator, times(1)).proposeIndex(anyInt());
        verify(uniqueViolationClassifier, atLeast(1)).classify(any(Throwable.class));
    }

    @Test
    void reserve_exhausts_retries_and_wraps_as_IndexReservationExhaustedException_for_idx_or_unknown() {
        long statusListId = 123L;
        UUID procedureUuid = UUID.randomUUID();
        String procedureId = procedureUuid.toString();

        when(indexAllocator.proposeIndex(anyInt())).thenReturn(1);

        RuntimeException duplicateIdx = new RuntimeException("duplicate idx");
        when(statusListIndexRepository.save(any(StatusListIndex.class))).thenReturn(Mono.error(duplicateIdx));

        when(uniqueViolationClassifier.classify(any(Throwable.class)))
                .thenReturn(UniqueViolationClassifier.Kind.IDX);

        StepVerifier.withVirtualTime(() -> service.reserve(statusListId, procedureId))
                .thenAwait(Duration.ofSeconds(10))
                .expectErrorSatisfies(t -> {
                    assertTrue(t instanceof IndexReservationExhaustedException);

                    Throwable c1 = t.getCause();
                    assertNotNull(c1);

                    // RetryExhaustedException is package-private, so check by class name.
                    assertEquals("RetryExhaustedException", c1.getClass().getSimpleName());
                    assertTrue(c1.getMessage() != null && c1.getMessage().contains("Retries exhausted"));

                    // Original failure is nested as the cause of the retry-exhausted error.
                    Throwable c2 = c1.getCause();
                    assertSame(duplicateIdx, c2);
                })
                .verify();

        verify(statusListIndexRepository, times(30)).save(any(StatusListIndex.class));
        verify(indexAllocator, times(30)).proposeIndex(anyInt());
        verify(uniqueViolationClassifier, atLeast(1)).classify(any(Throwable.class));
    }


    @Test
    void reserve_null_params_error_and_no_side_effects() {
        String someProcedureId = UUID.randomUUID().toString();

        NullPointerException ex1 = assertThrows(
                NullPointerException.class,
                () -> service.reserve(null, someProcedureId)
        );
        assertTrue(ex1.getMessage().contains("statusListId"));

        NullPointerException ex2 = assertThrows(
                NullPointerException.class,
                () -> service.reserve(1L, null)
        );
        assertTrue(ex2.getMessage().contains("procedureId"));

        verifyNoInteractions(statusListIndexRepository, indexAllocator, uniqueViolationClassifier);
    }


    @Test
    void reserve_sends_correct_row_to_repository_save() {
        long statusListId = 333L;
        UUID procedureUuid = UUID.randomUUID();
        String procedureId = procedureUuid.toString();

        when(indexAllocator.proposeIndex(anyInt())).thenReturn(55);

        StatusListIndex saved = new StatusListIndex(
                10L,
                statusListId,
                55,
                procedureUuid,
                Instant.now()
        );
        when(statusListIndexRepository.save(any(StatusListIndex.class))).thenReturn(Mono.just(saved));

        ArgumentCaptor<StatusListIndex> captor = ArgumentCaptor.forClass(StatusListIndex.class);

        StepVerifier.create(service.reserve(statusListId, procedureId))
                .expectNextCount(1)
                .verifyComplete();

        verify(statusListIndexRepository).save(captor.capture());
        StatusListIndex toSave = captor.getValue();

        assertNull(toSave.id());
        assertEquals(statusListId, toSave.statusListId());
        assertEquals(55, toSave.idx());
        assertEquals(procedureUuid, toSave.procedureId());
        assertNotNull(toSave.createdAt());
    }
}
