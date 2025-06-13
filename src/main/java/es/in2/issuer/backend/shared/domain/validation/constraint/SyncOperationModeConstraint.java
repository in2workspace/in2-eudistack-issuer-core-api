package es.in2.issuer.backend.shared.domain.validation.constraint;


import es.in2.issuer.backend.shared.domain.validation.validator.SyncOperationModeValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE})
@Retention(RUNTIME)
@Documented
@Constraint(validatedBy = SyncOperationModeValidator.class)
public @interface SyncOperationModeConstraint {
    String message() default "Operation mode must be SYNC";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
