package com.github.rafaritter44.security.vigenere.cryptanalysis.io;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Paths.get;
import static java.util.Optional.empty;
import static java.util.Optional.of;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Optional;

public class FileManager {
	
	public Optional<String> read(final String file) {
		if (file == null || file.isEmpty()) {
			return empty();
		}
		try (final InputStream inputStream = new FileInputStream(new File(file))) {
			final ByteArrayOutputStream result = new ByteArrayOutputStream();
			final byte[] buffer = new byte[1024];
			int length;
			while ((length = inputStream.read(buffer)) != -1) {
				result.write(buffer, 0, length);
			}
			return of(result.toString(UTF_8.name()).trim());
		} catch (final FileNotFoundException e) {
			return empty();
		} catch (final IOException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}
	
	public void write(final String file, final String text) {
		try {
			Files.write(get(file), text.getBytes(UTF_8));
		} catch (final IOException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}
	
}
