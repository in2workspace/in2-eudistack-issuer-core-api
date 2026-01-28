package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

import static es.in2.issuer.backend.shared.domain.util.Constants.REFRESH_TOKEN_EXPIRATION;
import static es.in2.issuer.backend.shared.domain.util.Constants.REFRESH_TOKEN_EXPIRATION_TIME_UNIT;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    @Override
    public String generateRefreshToken() {
        RefreshToken refreshToken = new RefreshToken();
        log.debug("Generated refresh token");
        return refreshToken.getValue();
    }

    @Override
    public long generateRefreshTokenExpirationTime(Instant issueTime) {
        return issueTime.plus(
                        REFRESH_TOKEN_EXPIRATION,
                        REFRESH_TOKEN_EXPIRATION_TIME_UNIT.toChronoUnit())
                .getEpochSecond();
    }
}