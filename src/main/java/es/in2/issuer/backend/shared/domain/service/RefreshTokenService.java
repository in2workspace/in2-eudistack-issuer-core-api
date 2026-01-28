package es.in2.issuer.backend.shared.domain.service;

import java.time.Instant;

public interface RefreshTokenService {
    String generateRefreshToken();
    long generateRefreshTokenExpirationTime(Instant issueTime);
}
