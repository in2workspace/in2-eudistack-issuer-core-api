package es.in2.issuer.backend.shared.infrastructure;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;

@Slf4j
@Component
public class MappingStartupLogger
        implements ApplicationListener<ApplicationReadyEvent> {

    private final RequestMappingHandlerMapping handlerMapping;

    public MappingStartupLogger(
            @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping
    ) {
        this.handlerMapping = handlerMapping;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        handlerMapping.getHandlerMethods().forEach((info, method) -> {
            log.info(
                    "Endpoint ready: {} {} -> {}#{}",
                    info.getMethodsCondition(),
                    info.getPatternsCondition(),
                    method.getBeanType().getSimpleName(),
                    method.getMethod().getName()
            );
        });
    }
}

