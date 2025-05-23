package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class SecureRandomConfigTest {

    @InjectMocks
    private SecureRandomConfig secureRandomConfig;

    @Test
    void testSecureRandomConstruction() {
        SecureRandom secureRandom =  secureRandomConfig.secureRandom();
        assertThat(secureRandom).isInstanceOf(SecureRandom.class);
    }

}