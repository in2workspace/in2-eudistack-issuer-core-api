package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;

public interface TranslationService {
    public String getLocale();
    public String translate(String code, Object... args);
}
