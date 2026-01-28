package es.in2.issuer.backend.statusList.infrastructure.adapter;

import es.in2.issuer.backend.statusList.domain.spi.StatusListIndexAllocator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class RandomIndexAllocator implements StatusListIndexAllocator {

    private final SecureRandom random = new SecureRandom();

    @Override
    public int proposeIndex(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be > 0");
        }
        return random.nextInt(capacity);
    }
}

