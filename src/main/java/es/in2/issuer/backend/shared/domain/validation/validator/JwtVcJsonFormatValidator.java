package es.in2.issuer.backend.shared.domain.validation.validator;

import es.in2.issuer.backend.shared.domain.validation.constraint.JwtVcJsonFormatConstraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;

public class JwtVcJsonFormatValidator implements
        ConstraintValidator<JwtVcJsonFormatConstraint, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value != null && value.equals(JWT_VC_JSON);
    }
}