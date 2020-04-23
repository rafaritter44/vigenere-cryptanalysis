package com.github.rafaritter44.security.vigenere.cryptanalysis.key;

import static java.util.Collections.emptyList;
import static java.util.Map.Entry.comparingByValue;
import static java.util.function.Function.identity;
import static java.util.stream.Collector.of;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.rafaritter44.security.vigenere.cryptanalysis.VigenereSquare;

public class FrequencyAnalyzer {
	
	private final VigenereSquare vigenereSquare;
	private final Map<Character, Double> plaintextLetterFrequencies;
	private final String alphabet;
	
	public FrequencyAnalyzer(
			final VigenereSquare vigenereSquare,
			final Map<Character, Double> plaintextLetterFrequencies,
			final String alphabet) {
		this.vigenereSquare = vigenereSquare;
		this.plaintextLetterFrequencies = plaintextLetterFrequencies;
		this.alphabet = alphabet;
	}
	
	public List<Character> findKeys(final String ciphertext) {
		if (ciphertext == null || ciphertext.isEmpty()) {
			return emptyList();
		}
		final double ciphertextLength = (double) ciphertext.length();
		final Map<Character, Double> chiSquares = new HashMap<>();
		String ciphertextUnderAnalysis = ciphertext; 
		for (int i = 1; i < alphabet.length(); i++) {
			final Map<Character, Double> encryptedLetterFrequencies = ciphertextUnderAnalysis
					.chars()
					.parallel()
					.mapToObj(letter -> (char) letter)
					.collect(toMap(identity(), letter -> 1D, Double::sum))
					.entrySet()
					.parallelStream()
					.map(kv -> {
						kv.setValue(kv.getValue() / ciphertextLength);
						return kv;
					})
					.collect(toMap(Entry::getKey, Entry::getValue));
			double chiSquare = 0D;
			for (int j = 0; j < alphabet.length(); j++) {
				final char letter = alphabet.charAt(j);
				final double observedFrequency = encryptedLetterFrequencies.getOrDefault(letter, 0D);
				final double expectedFrequency = plaintextLetterFrequencies.get(letter) * ciphertextLength;
				chiSquare += Math.pow(observedFrequency - expectedFrequency, 2D) / expectedFrequency;
			}
			chiSquares.put(alphabet.charAt(i - 1), chiSquare);
			final char alphabetLetter = alphabet.charAt(i);
			ciphertextUnderAnalysis = ciphertext
					.chars()
					.parallel()
					.mapToObj(encryptedLetter -> (char) encryptedLetter)
					.map(encryptedLetter -> vigenereSquare.decrypt(alphabetLetter, encryptedLetter))
					.collect(of(StringBuilder::new, StringBuilder::append, StringBuilder::append, StringBuilder::toString));
		}
		return chiSquares
				.entrySet()
				.parallelStream()
				.sorted(comparingByValue())
				.map(Entry::getKey)
				.collect(toList());
	}
	
}
