package es.in2.issuer.backend.statuslist.domain.spi;

/**
 * Strategy for proposing candidate indices within a Status List.
 * This component does not perform any persistence or availability checks.
 */
public interface StatusListIndexAllocator {

    /**
     * Proposes a candidate index in the range [0, capacity).
     */
    int proposeIndex(int capacity);
}
