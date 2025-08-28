package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.backoffice.infrastructure.config.security.exception.ParseAuthenticationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class SecurityProblemResolver {

    private static final ProblemSpec DEFAULT_AUTH_SPEC =
            new ProblemSpec(SecurityErrorTypes.DEFAULT_AUTH.getCode(), "Unauthorized", HttpStatus.UNAUTHORIZED, "Authentication failed");

    private static final ProblemSpec DEFAULT_ACCESS_SPEC =
            new ProblemSpec(SecurityErrorTypes.DEFAULT_ACCESS.getCode(), "Forbidden", HttpStatus.FORBIDDEN, "Access denied");

    private final Map<Class<? extends Throwable>, ProblemSpec> map = Map.ofEntries(
            // 401a
            Map.entry(
                    ParseAuthenticationException.class,
                    new ProblemSpec(
                            SecurityErrorTypes.INVALID_TOKEN.getCode(),
                            "Invalid token",
                            HttpStatus.UNAUTHORIZED,
                            "Invalid token"
                    )
            )
            // 403 todo
    );

    public ProblemSpec resolve(Throwable ex, boolean isAuthPhase) {
        Class<?> c = ex.getClass();
        while (c != null && c != Object.class) {
            ProblemSpec spec = map.get(c);
            if (spec != null) return spec;
            c = c.getSuperclass();
        }
        return isAuthPhase ? DEFAULT_AUTH_SPEC : DEFAULT_ACCESS_SPEC;
    }

    public record ProblemSpec(String type, String title, HttpStatus status, String fallbackDetail) {}
}
