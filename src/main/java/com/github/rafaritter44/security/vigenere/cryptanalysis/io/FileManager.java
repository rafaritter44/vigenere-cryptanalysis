package com.github.rafaritter44.security.vigenere.cryptanalysis.io;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class FileManager {
	
	public String read(final String file) {
		final InputStream inputStream = FileManager.class.getResourceAsStream(file);
		final ByteArrayOutputStream result = new ByteArrayOutputStream();
		final byte[] buffer = new byte[1024];
		int length;
		try {
			while ((length = inputStream.read(buffer)) != -1) {
				result.write(buffer, 0, length);
			}
			return result.toString(UTF_8.name());
		} catch (final IOException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}
	
}
