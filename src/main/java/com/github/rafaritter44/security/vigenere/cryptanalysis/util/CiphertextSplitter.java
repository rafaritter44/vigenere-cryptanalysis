package com.github.rafaritter44.security.vigenere.cryptanalysis.util;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CiphertextSplitter {
	
	private Map<String, List<String>> cache = new ConcurrentHashMap<>();
	
	public List<String> splitCiphertext(final String ciphertext, final int keyLength) {
		if (ciphertext == null || keyLength < 1) {
			return emptyList();
		}
		final String cacheKey = ciphertext + keyLength;
		final List<String> cached = cache.get(cacheKey);
		if (cached != null) {
			return cached;
		}
		final List<StringBuilder> splitCiphertextBuilder = new ArrayList<>();
		for (int i = 0; i < keyLength; i++) {
			splitCiphertextBuilder.add(new StringBuilder());
		}
		final int ciphertextLength = ciphertext.length();
		for (int letterIndex = 0; letterIndex < ciphertextLength; letterIndex++) {
			final char letter = ciphertext.charAt(letterIndex);
			final int splitCiphertextIndex = letterIndex % keyLength;
			splitCiphertextBuilder.get(splitCiphertextIndex).append(letter);
		}
		final List<String> splitCiphertext = splitCiphertextBuilder
				.parallelStream()
				.map(StringBuilder::toString)
				.collect(toList());
		cache.put(cacheKey, splitCiphertext);
		return splitCiphertext;
	}
	
}
