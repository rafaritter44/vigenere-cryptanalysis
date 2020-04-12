package com.github.rafaritter44.security.vigenere.cryptanalysis;

import static java.util.Collections.emptyList;
import static java.util.Optional.empty;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.github.rafaritter44.security.vigenere.cryptanalysis.decrypt.FrequencyAnalyzer;
import com.github.rafaritter44.security.vigenere.cryptanalysis.keylength.KeyLengthFinder;
import com.github.rafaritter44.security.vigenere.cryptanalysis.util.CiphertextSplitter;

public class Cryptanalyser {
	
	private final KeyLengthFinder keyLengthFinder;
	private final FrequencyAnalyzer frequencyAnalyzer;
	private final CiphertextSplitter ciphertextSplitter;
	
	private String ciphertext;
	private List<Integer> keyLengths;
	
	public Cryptanalyser(
			final KeyLengthFinder keyLengthFinder,
			final FrequencyAnalyzer frequencyAnalyzer,
			final CiphertextSplitter ciphertextSplitter) {
		this.keyLengthFinder = keyLengthFinder;
		this.frequencyAnalyzer = frequencyAnalyzer;
		this.ciphertextSplitter = ciphertextSplitter;
	}
	
	public Optional<String> decrypt(final int keyLengthIndex) {
		if (ciphertext == null || keyLengths == null || keyLengthIndex < 0 || keyLengthIndex >= keyLengths.size()) {
			return empty();
		}
		final ArrayList<String> splitCiphertext = ciphertextSplitter.splitCiphertext(ciphertext, keyLengths.get(keyLengthIndex));
		final List<String> splitPlaintext = splitCiphertext
				.parallelStream()
				.map(frequencyAnalyzer::decrypt)
				.collect(toList());
		return ofNullable(ciphertextSplitter.mergeSplitPlaintext(splitPlaintext));
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
	
	public void setCiphertext(final String ciphertext) {
		this.ciphertext = ciphertext;
	}
	
}
