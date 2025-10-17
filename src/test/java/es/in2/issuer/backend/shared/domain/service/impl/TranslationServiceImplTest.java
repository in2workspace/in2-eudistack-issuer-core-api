package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class TranslationServiceImplTest {

    @Mock
    private AppConfig appConfig;

    @Mock
    private MessageSource messageSource;

    private TranslationServiceImpl service;

    @Captor
    private ArgumentCaptor<Object[]> argsCaptor;

    @Captor
    private ArgumentCaptor<Locale> localeCaptor;

    @BeforeEach
    void setUp() {
        service = new TranslationServiceImpl(appConfig, messageSource);
    }

    @ParameterizedTest(name = "getLocale() with config=''{0}'' -> ''{1}''")
    @CsvSource({
            "en,en",
            "es,es",
            "' EN ',en",
            "Es,es",
            "FR,en",
            "'',en",
            "'   ',en",
            "NULL,en"
    })
    @DisplayName("getLocale() resolves locale with trimming, case-insensitivity and fallback")
    void getLocale_resolvesAndFallsBack(String configured, String expected) {
        // Arrange
        when(appConfig.getDefaultLang()).thenReturn(configured);

        // Act
        String actual = service.getLocale();

        // Assert
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("translate() returns localized message from MessageSource with correct args and locale")
    void translate_returnsMessage_andUsesLocaleAndArgs() {
        // Arrange
        when(appConfig.getDefaultLang()).thenReturn("es");
        // Use a lenient stub on messageSource so we can verify captors afterwards
        when(messageSource.getMessage(eq("greeting"), any(), any()))
                .thenReturn("Hola, Roger");

        // Act
        String result = service.translate("greeting", "Roger");

        // Assert
        assertThat(result).isEqualTo("Hola, Roger");

        // Verify that MessageSource was called with the expected code, args, and locale
        verify(messageSource).getMessage(eq("greeting"), argsCaptor.capture(), localeCaptor.capture());

        // Check args were propagated as-is
        Object[] passedArgs = argsCaptor.getValue();
        assertThat(passedArgs).isNotNull();
        assertThat(passedArgs).hasSize(1);
        assertThat(passedArgs[0]).isEqualTo("Roger");

        // Check locale derived from getLocale() is Spanish
        Locale passedLocale = localeCaptor.getValue();
        assertThat(passedLocale).isNotNull();
        assertThat(passedLocale.getLanguage()).isEqualTo("es");
    }

    @Test
    @DisplayName("translate() falls back to code when message is missing")
    void translate_fallsBackToCodeOnMissingMessage() {
        // Arrange
        when(appConfig.getDefaultLang()).thenReturn("en");
        when(messageSource.getMessage(eq("missing.key"), any(), any()))
                .thenThrow(new NoSuchMessageException("missing.key"));

        // Act
        String result = service.translate("missing.key", 123);

        // Assert
        assertThat(result).isEqualTo("missing.key");

        // Also verify locale used was English
        verify(messageSource).getMessage(eq("missing.key"), any(), localeCaptor.capture());
        assertThat(localeCaptor.getValue().getLanguage()).isEqualTo("en");
    }
}
