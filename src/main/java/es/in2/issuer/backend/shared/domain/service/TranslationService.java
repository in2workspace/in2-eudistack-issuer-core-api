package es.in2.issuer.backend.shared.domain.service;

public interface TranslationService {
    public String getLocale();
    public String translate(String code, Object... args);
}
