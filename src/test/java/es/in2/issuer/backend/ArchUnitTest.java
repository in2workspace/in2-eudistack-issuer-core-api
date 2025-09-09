package es.in2.issuer.backend;


import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.GeneralCodingRules;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static org.assertj.core.api.Assertions.assertThat;

@AnalyzeClasses(packages = "es.in2.issuer.backend")
class ArchUnitTest {
    private static final String BASE_PACKAGE = "es.in2.issuer.backend";
    private static final Set<String> CONSTANTS_CLASSES =
            Set.of(
                    BASE_PACKAGE + ".shared.domain.util.Constants",
                    BASE_PACKAGE + ".shared.infrastructure.config.SwaggerConfig");

//todo
//    @ArchTest
//    static final ArchRule packageDependenciesAreRespected = layeredArchitecture()
//            .consideringOnlyDependenciesInLayers()
//            // Define layers
//            .layer("Backoffice").definedBy(BASE_PACKAGE + ".backoffice..")
//            .layer("OIDC4VCI").definedBy(BASE_PACKAGE + ".oidc4vci..")
//            .layer("OIDC4VCI-Workflow").definedBy(BASE_PACKAGE + ".oidc4vci.application.workflow..")
//            .layer("Shared").definedBy(BASE_PACKAGE + ".shared..")
//            // Add constraints
//            .whereLayer("Backoffice").mayOnlyAccessLayers("OIDC4VCI-Workflow", "Shared")
//            .whereLayer("OIDC4VCI").mayOnlyAccessLayers("Shared")
//            .whereLayer("Shared").mayNotAccessAnyLayer();

    @ArchTest
    static final ArchRule implementationsShouldBeInSameLayerAsInterfaces =
            classes()
                    .that().areNotInterfaces()
                    .and().resideInAPackage(BASE_PACKAGE + "..")
                    .and().haveNameMatching(".*(?i)(service|workflow).*")
                    .should(new ArchCondition<>("reside in the same layer as the interfaces they implement") {
                        @Override
                        public void check(JavaClass clazz, ConditionEvents events) {
                            String implLayer = getLayerForPackage(clazz.getPackageName());

                            for (JavaType javaType : clazz.getInterfaces()) {
                                JavaClass implementedInterface = javaType.toErasure();
                                String interfaceLayer = getLayerForPackage(implementedInterface.getPackageName());

                                if (implLayer != null && interfaceLayer != null && !implLayer.equals(interfaceLayer)) {
                                    String message = String.format(
                                            "Class %s (layer: %s) implements %s (layer: %s)",
                                            clazz.getName(), implLayer, implementedInterface.getName(), interfaceLayer
                                    );
                                    events.add(SimpleConditionEvent.violated(clazz, message));
                                }
                            }
                        }
                    });

    private static String getLayerForPackage(String packageName) {
        if (packageName.startsWith(BASE_PACKAGE + ".backoffice")) return "Backoffice";
        if (packageName.startsWith(BASE_PACKAGE + ".oidc4vci.application.workflow")) return "OIDC4VCI-Workflow";
        if (packageName.startsWith(BASE_PACKAGE + ".oidc4vci")) return "OIDC4VCI";
        if (packageName.startsWith(BASE_PACKAGE + ".shared")) return "Shared";
        return null;
    }

    @ArchTest
    static final ArchRule testClassesShouldResideInTheSamePackageAsImplementation =
            GeneralCodingRules.testClassesShouldResideInTheSamePackageAsImplementation();

    @Test
    void classesInSharedMustBeUsedBySharedOrByBothBackofficeAndOidc4vci() {
        var classes = new ClassFileImporter().importPackages(BASE_PACKAGE);

        Set<JavaClass> sharedClasses = classes.stream()
                .filter(javaClass -> javaClass.getPackageName().contains(".shared"))
                .collect(Collectors.toSet());

        Set<JavaClass> sharedClassesToCheck = sharedClasses
                .stream()
                .filter(javaClass -> !CONSTANTS_CLASSES.contains(javaClass.getName()))
                .filter(this::isNotTestClass)
                .collect(Collectors.toSet());

        Set<JavaClass> backofficeClasses = filterClassesByPackage(classes, ".backoffice");
        Set<JavaClass> oidcClasses = filterClassesByPackage(classes, ".oidc4vci");


        for (JavaClass sharedClass : sharedClassesToCheck) {
            boolean usedByBackoffice = backofficeClasses.stream().anyMatch(user -> usesClass(user, sharedClass));
            boolean usedByOidc4vci = oidcClasses.stream().anyMatch(user -> usesClass(user, sharedClass));
            boolean usedByShared = sharedClasses.stream().anyMatch(user -> usesClass(user, sharedClass));

            boolean isShared = ((usedByBackoffice && usedByOidc4vci) || usedByShared);
            assertThat(isShared)
                    .withFailMessage("The class " + sharedClass.getName() +
                            " is not used by both packages nor shared.")
                    .isTrue();
        }
    }

    private Set<JavaClass> filterClassesByPackage(JavaClasses classes, String packageName) {
        return classes.stream()
                .filter(javaClass -> javaClass.getPackageName().contains(packageName))
                .collect(Collectors.toSet());
    }

    private boolean usesClass(JavaClass javaClass, JavaClass sharedClass) {
        return javaClass.getDirectDependenciesFromSelf().stream()
                .anyMatch(dependency -> dependency.getTargetClass().equals(sharedClass));
    }

    private boolean isNotTestClass(JavaClass javaClass) {
        return !javaClass.getSimpleName().endsWith("Test")
                && !javaClass.getSimpleName().endsWith("IT");
    }
}