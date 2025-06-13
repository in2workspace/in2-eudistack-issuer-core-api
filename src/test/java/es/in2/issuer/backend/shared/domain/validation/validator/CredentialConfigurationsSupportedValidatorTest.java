package es.in2.issuer.backend.shared.domain.validation.validator;

import es.in2.issuer.backend.shared.domain.model.CredentialConfigurationsSupported;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CredentialConfigurationsSupportedValidatorTest {

    @Mock
    private ConstraintValidatorContext constraintValidatorContext;

    @InjectMocks
    private CredentialConfigurationsSupportedValidator credentialConfigurationsSupportedValidator;

    @Test
    void isValid_WithValidCredentialValue_ReturnsTrue() {
        String validValue = CredentialConfigurationsSupported.values()[0].toString();

        var result = credentialConfigurationsSupportedValidator.isValid(validValue, constraintValidatorContext);

        assertThat(result).isTrue();
    }

    @Test
    void isValid_WithInvalidCredentialValue_ReturnsFalse() {
        String invalidValue = "invalid_value";

        var result = credentialConfigurationsSupportedValidator.isValid(invalidValue, constraintValidatorContext);

        assertThat(result).isFalse();
    }

    @ParameterizedTest
    @EnumSource(CredentialConfigurationsSupported.class)
    void isValid_WithAllEnumValues_ReturnsTrue(CredentialConfigurationsSupported credentialConfiguration) {
        String value = credentialConfiguration.toString();

        boolean isValid = credentialConfigurationsSupportedValidator.isValid(value, constraintValidatorContext);

        assertThat(isValid).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isValid_WithNullOrEmptyValue_ReturnsFalse(String nullOrEmptyValue) {
        boolean isValid = credentialConfigurationsSupportedValidator.isValid(nullOrEmptyValue, constraintValidatorContext);

        assertThat(isValid).isFalse();
    }

    @Test
    void isValid_WithCaseInsensitiveMatch_ReturnsFalse() {
        String validValue = CredentialConfigurationsSupported.values()[0].toString().toLowerCase();

        var result = credentialConfigurationsSupportedValidator.isValid(validValue, constraintValidatorContext);

        assertThat(result).isFalse();
    }
}