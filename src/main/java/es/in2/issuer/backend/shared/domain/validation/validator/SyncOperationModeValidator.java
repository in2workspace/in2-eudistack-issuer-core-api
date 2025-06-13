package es.in2.issuer.backend.shared.domain.validation.validator;

import es.in2.issuer.backend.shared.domain.validation.constraint.SyncOperationModeConstraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SYNC;

public class SyncOperationModeValidator implements
        ConstraintValidator<SyncOperationModeConstraint, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value != null && value.equals(SYNC);
    }
}