package io.sypt.core.keystore;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KSMResourceLoaderTest {

    private KSMResourceLoader loader;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        loader = new KSMResourceLoader();
    }

    @Test
    void shouldLoadResourceFromFileSystem() throws IOException {
        Path tempFile = tempDir.resolve("test-file.txt");
        Files.writeString(tempFile, "Contenu Système");
        String absolutePath = tempFile.toAbsolutePath().toString();

        try (InputStream is = loader.getResource(absolutePath)) {
            // Then
        	Assertions.assertThat(is).isNotNull();
        	Assertions.assertThat(new String(is.readAllBytes())).isEqualTo("Contenu Système");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "classpath:test-resource.txt", "test-resource.txt", "classpath:/test-resource.txt" })
    void shouldLoadResourceFromClasspathWithPrefix(String path) throws IOException {
        // When
        try (InputStream is = loader.getResource(path)) {
            // Then
        	Assertions.assertThat(is).isNotNull();
        }
    }

    @Test
    void shouldThrowExceptionWhenResourceNotFound() {
        // Given
        String unknownPath = "non-existent-file.txt";

        // When / Then
        Assertions.assertThatThrownBy(() -> loader.getResource(unknownPath))
            .isInstanceOf(FileNotFoundException.class)
            .hasMessageContaining("Ressource introuvable");
    }
}