package es.in2.issuer.backend.shared.infrastructure.controller.error;

import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Component
public class ErrorResponseFactory {
    public Mono<GlobalErrorMessage> handleWith(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return Mono.fromSupplier(() -> buildError(type, title, status, detail, ex, request));
    }

    public GlobalErrorMessage handleWithNow(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return buildError(type, title, status, detail, ex, request);
    }

    private String resolveDetail(Exception ex, String fallback) {
        String msg = ex.getMessage();
        return (msg == null || msg.isBlank()) ? fallback : msg;
    }

    private GlobalErrorMessage buildError(
            String type, String title, HttpStatus httpStatus, String detail,
            Exception ex, ServerHttpRequest request
    ) {
        String instance = UUID.randomUUID().toString();
        RequestPath path = request.getPath();
        log.error("instance={} path={} status={} ex={} detail={}",
                instance, path.value(), httpStatus.value(), ex.getClass().getName(), detail);
        return new GlobalErrorMessage(type, title, httpStatus.value(), detail, instance);
    }
}
