package es.in2.issuer.backend.shared.domain.validation.validator;

import es.in2.issuer.backend.shared.domain.model.CredentialConfigurationsSupported;
import es.in2.issuer.backend.shared.domain.validation.constraint.CredentialConfigurationsSupportedConstraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class CredentialConfigurationsSupportedValidator implements
        ConstraintValidator<CredentialConfigurationsSupportedConstraint, String> {

    private static final Set<String> VALID_TEXT_VALUES = Arrays.stream(CredentialConfigurationsSupported.values())
            .map(CredentialConfigurationsSupported::toString)
            .collect(Collectors.toUnmodifiableSet());

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value != null && VALID_TEXT_VALUES.contains(value);
    }
}