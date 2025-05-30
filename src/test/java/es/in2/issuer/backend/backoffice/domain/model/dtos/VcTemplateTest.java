package es.in2.issuer.backend.backoffice.domain.model.dtos;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VcTemplateTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        Boolean expectedMutable = true;
        String expectedName = "Template";
        String expectedTemplate = "Template content";

        // Act
        VcTemplate vcTemplate = new VcTemplate(expectedMutable, expectedName, expectedTemplate);

        // Assert
        assertEquals(expectedMutable, vcTemplate.mutable());
        assertEquals(expectedName, vcTemplate.name());
        assertEquals(expectedTemplate, vcTemplate.template());
    }

    @Test
    void testSetters() {
        // Arrange
        Boolean newMutable = false;
        String newName = "New Template";
        String newTemplate = "New Template content";

        // Act
        VcTemplate vcTemplate = VcTemplate.builder()
                .mutable(newMutable)
                .name(newName)
                .template(newTemplate)
                .build();

        // Assert
        assertEquals(newMutable, vcTemplate.mutable());
        assertEquals(newName, vcTemplate.name());
        assertEquals(newTemplate, vcTemplate.template());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        Boolean expectedMutable = true;
        String expectedName = "Template";
        String expectedTemplate = "Template content";

        VcTemplate vcTemplate1 = new VcTemplate(expectedMutable, expectedName, expectedTemplate);
        VcTemplate vcTemplate2 = new VcTemplate(expectedMutable, expectedName, expectedTemplate);

        // Assert
        assertEquals(vcTemplate1, vcTemplate2);
        assertEquals(vcTemplate1.hashCode(), vcTemplate2.hashCode());
    }
}