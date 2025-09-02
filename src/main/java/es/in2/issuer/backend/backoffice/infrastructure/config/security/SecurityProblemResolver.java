package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Map;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.AUTHENTICATION_FAILED;

@Slf4j
@Component
public class SecurityProblemResolver {

    private static final ProblemSpec DEFAULT_AUTH_SPEC =
            new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(), "Unauthorized",
                    HttpStatus.UNAUTHORIZED, AUTHENTICATION_FAILED);

    private static final ProblemSpec DEFAULT_ACCESS_SPEC =
            new ProblemSpec(SecurityErrorTypes.DEFAULT_ACCESS.getCode(), "Forbidden",
                    HttpStatus.FORBIDDEN, "Access denied");

    private final Map<Class<? extends Throwable>, ProblemSpec> map = Map.ofEntries(
            // 401
            Map.entry(BadCredentialsException.class,
                    new ProblemSpec(SecurityErrorTypes.INVALID_TOKEN.getCode(),
                            "Invalid token", HttpStatus.UNAUTHORIZED, "Invalid token")),

            Map.entry(AuthenticationServiceException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(),
                            "Authentication service error", HttpStatus.UNAUTHORIZED, AUTHENTICATION_FAILED)),

            Map.entry(InsufficientAuthenticationException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(),
                            "Insufficient authentication", HttpStatus.UNAUTHORIZED, "Additional authentication required")),

            Map.entry(UsernameNotFoundException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(),
                            "User not found", HttpStatus.UNAUTHORIZED, AUTHENTICATION_FAILED)),

            Map.entry(DisabledException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(),
                            "User disabled", HttpStatus.UNAUTHORIZED, AUTHENTICATION_FAILED)),
            Map.entry(LockedException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(),
                            "User locked", HttpStatus.UNAUTHORIZED, AUTHENTICATION_FAILED)),
            Map.entry(AccountExpiredException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(),
                            "Account expired", HttpStatus.UNAUTHORIZED, AUTHENTICATION_FAILED)),
            Map.entry(CredentialsExpiredException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(),
                            "Credentials expired", HttpStatus.UNAUTHORIZED, AUTHENTICATION_FAILED)),
            // 403
            Map.entry(AccessDeniedException.class,
                    new ProblemSpec(SecurityErrorTypes.DEFAULT_ACCESS.getCode(),
                            "Forbidden", HttpStatus.FORBIDDEN, "Access denied"))
    );

    public ProblemSpec resolve(Throwable ex, boolean isAuthenticationPhase) {
        log.debug("SecurityProblemResolver.resolve - inside");
        log.debug("Exception: ", ex);

        Class<?> c = ex.getClass();
        while (c != null && c != Object.class) {
            ProblemSpec spec = map.get(c);
            if (spec != null) return spec;
            c = c.getSuperclass();
        }
        return isAuthenticationPhase ? DEFAULT_AUTH_SPEC : DEFAULT_ACCESS_SPEC;
    }

    public record ProblemSpec(String type, String title, HttpStatus status, String fallbackDetail) {}
}

