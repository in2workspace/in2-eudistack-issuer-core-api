package es.in2.issuer.backend.backoffice.domain.model.dtos;

public record GlobalErrorMessage(String type,
                                 String title,
                                 int status,
                                 String detail,
                                 String instance) {
}
