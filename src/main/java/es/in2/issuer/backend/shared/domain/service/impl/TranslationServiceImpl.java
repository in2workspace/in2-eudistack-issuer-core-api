package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.service.TranslationService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class TranslationServiceImpl implements TranslationService {

    private final AppConfig appConfig;

    private static final List<String> SUPPORTED_LANGS = List.of("en", "es");

    @Override
    public String getLocale() {
        String locale = appConfig.getDefaultLang();
        log.info("Default lang from config: {}", locale);

        if (locale == null || locale.isBlank()) {
            log.warn("No default language configured. Using fallback: 'en'");
            return "en";
        }

        locale = locale.trim().toLowerCase();

        if (!SUPPORTED_LANGS.contains(locale)) {
            log.warn("Unsupported language '{}'. Falling back to 'en'", locale);
            return "en";
        }
        log.info("Using locale: {}", locale);
        return locale;
    }
}
