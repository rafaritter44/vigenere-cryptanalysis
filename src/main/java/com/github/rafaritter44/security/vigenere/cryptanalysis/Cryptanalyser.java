package com.github.rafaritter44.security.vigenere.cryptanalysis;

import static java.util.Collections.emptyList;
import static java.util.Optional.empty;
import static java.util.stream.Collector.of;
import static java.util.stream.Collectors.toList;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

import com.github.rafaritter44.security.vigenere.cryptanalysis.key.FrequencyAnalyzer;
import com.github.rafaritter44.security.vigenere.cryptanalysis.key.length.KeyLengthFinder;
import com.github.rafaritter44.security.vigenere.cryptanalysis.util.CiphertextSplitter;

public class Cryptanalyser {
	
	private final KeyLengthFinder keyLengthFinder;
	private final FrequencyAnalyzer frequencyAnalyzer;
	private final CiphertextSplitter ciphertextSplitter;
	private final VigenereSquare vigenereSquare;
	
	private String ciphertext;
	private List<Integer> keyLengths;
	private Map<Integer, List<Iterator<Character>>> keys;
	private String key;
	private String plaintext;
	
	public Cryptanalyser(
			final KeyLengthFinder keyLengthFinder,
			final FrequencyAnalyzer frequencyAnalyzer,
			final CiphertextSplitter ciphertextSplitter,
			final VigenereSquare vigenereSquare) {
		this.keyLengthFinder = keyLengthFinder;
		this.frequencyAnalyzer = frequencyAnalyzer;
		this.ciphertextSplitter = ciphertextSplitter;
		this.vigenereSquare = vigenereSquare;
		this.keys = new HashMap<>();
	}
	
	public void findKeyLengths() {
		if (ciphertext != null) {
			keyLengths = keyLengthFinder.findKeyLengths(ciphertext);
		}
	}
	
	public List<Integer> getKeyLengths() {
		if (keyLengths == null) {
			return emptyList();
		}
		return keyLengths;
	}
	
	public void findKeys(final int keyLengthIndex) {
		if (ciphertext == null || keyLengths == null || keyLengthIndex < 0 || keyLengthIndex >= keyLengths.size()) {
			return;
		}
		final List<String> splitCiphertext = ciphertextSplitter.splitCiphertext(ciphertext, keyLengths.get(keyLengthIndex));
		final List<Iterator<Character>> key = splitCiphertext
				.parallelStream()
				.map(frequencyAnalyzer::findKeys)
				.map(List::iterator)
				.collect(toList());
		keys.put(keyLengths.get(keyLengthIndex), key);
	}
	
	public Optional<String> decrypt(final int keyLengthIndex) {
		if (ciphertext == null || keyLengths == null || keyLengthIndex < 0 || keyLengthIndex >= keyLengths.size()) {
			return empty();
		}
		final int keyLength = keyLengths.get(keyLengthIndex);
		if (keys.get(keyLength) == null) {
			return empty();
		}
		final boolean keyPresent = keys
				.get(keyLength)
				.parallelStream()
				.allMatch(Iterator::hasNext);
		if (!keyPresent) {
			return empty();
		}
		key = keys
				.get(keyLength)
				.parallelStream()
				.map(Iterator::next)
				.collect(of(StringBuilder::new, StringBuilder::append, StringBuilder::append, StringBuilder::toString));
		plaintext = IntStream
				.range(0, ciphertext.length())
				.parallel()
				.mapToObj(i -> vigenereSquare.decrypt(key.charAt(i % keyLength), ciphertext.charAt(i)))
				.collect(of(StringBuilder::new, StringBuilder::append, StringBuilder::append, StringBuilder::toString));
		return Optional.of(plaintext);
	}
	
	public Optional<String> decrypt(final int keyLengthIndex, final int keyLetterIndex) {
		if (ciphertext == null || keyLengths == null || keyLengthIndex < 0 || keyLengthIndex >= keyLengths.size() ||
				this.key == null || this.plaintext == null) {
			return empty();
		}
		final int keyLength = keyLengths.get(keyLengthIndex);
		if (keys.get(keyLength) == null) {
			return empty();
		}
		final List<Iterator<Character>> key = keys.get(keyLength);
		if (keyLetterIndex < 0 || keyLetterIndex >= key.size() || !key.get(keyLetterIndex).hasNext()) {
			return empty();
		}
		final char newKeyLetter = key.get(keyLetterIndex).next();
		final char[] keyLetters = this.key.toCharArray();
		keyLetters[keyLetterIndex] = newKeyLetter;
		this.key = String.valueOf(keyLetters);
		final int ciphertextLength = ciphertext.length();
		final char[] plaintextLetters = plaintext.toCharArray();
		for (int i = keyLetterIndex; i < ciphertextLength; i += keyLength) {
			plaintextLetters[i] = vigenereSquare.decrypt(newKeyLetter, ciphertext.charAt(i));
		}
		plaintext = String.valueOf(plaintextLetters);
		return Optional.of(plaintext);
	}

	public void setCiphertext(final String ciphertext) {
		this.ciphertext = ciphertext;
	}
	
	public String getKey() {
		return key;
	}
	
}
