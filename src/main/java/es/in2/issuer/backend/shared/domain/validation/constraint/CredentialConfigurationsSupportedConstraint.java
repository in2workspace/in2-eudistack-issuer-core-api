package es.in2.issuer.backend.shared.domain.validation.constraint;


import es.in2.issuer.backend.shared.domain.validation.validator.CredentialConfigurationsSupportedValidator;
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
@Constraint(validatedBy = CredentialConfigurationsSupportedValidator.class)
public @interface CredentialConfigurationsSupportedConstraint {
    String message() default "Schema must be one of the supported credential configurations";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
