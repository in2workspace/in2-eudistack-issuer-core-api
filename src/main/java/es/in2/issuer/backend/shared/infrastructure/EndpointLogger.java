package es.in2.issuer.backend.shared.infrastructure;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;

@Slf4j
@Component
public class EndpointLogger {

    private final RequestMappingHandlerMapping handlerMapping;

    public EndpointLogger(
            @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping
    ) {
        this.handlerMapping = handlerMapping;
    }

    @PostConstruct
    void logEndpoints() {
        handlerMapping.getHandlerMethods().forEach((info, method) -> {
            log.info(
                    "Mapped endpoint: {} {} -> {}#{}",
                    info.getMethodsCondition(),
                    info.getPatternsCondition(),
                    method.getBeanType().getSimpleName(),
                    method.getMethod().getName()
            );
        });
    }
}

