package com.github.rafaritter44.security.vigenere.cryptanalysis.decrypt;

import static java.util.Map.Entry.comparingByValue;
import static java.util.function.Function.identity;
import static java.util.stream.Collector.of;
import static java.util.stream.Collectors.toConcurrentMap;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

public class FrequencyAnalyzer {
	
	private final Map<Character, Double> letterFrequencies;
	
	public FrequencyAnalyzer(final Map<Character, Double> letterFrequencies) {
		this.letterFrequencies = letterFrequencies
				.entrySet()
				.parallelStream()
				.sorted(comparingByValue())
				.collect(toConcurrentMap(Entry::getKey, Entry::getValue));
	}
	
	public String decrypt(final String ciphertext) {
		if (ciphertext == null || ciphertext.isEmpty()) {
			return "";
		}
		final double ciphertextLength = (double) ciphertext.length();
		final Map<Character, Double> letterFrequencies = ciphertext
				.chars()
				.parallel()
				.mapToObj(letter -> (char) letter)
				.collect(toConcurrentMap(identity(), letter -> 1D, Double::sum))
				.entrySet()
				.parallelStream()
				.map(kv -> {
					kv.setValue(kv.getValue() / ciphertextLength);
					return kv;
				})
				.sorted(comparingByValue())
				.collect(toConcurrentMap(Entry::getKey, Entry::getValue));
		if (letterFrequencies.size() != this.letterFrequencies.size()) {
			throw new DifferentAlphabetSizesException(letterFrequencies.size(), this.letterFrequencies.size());
		}
		final Map<Character, Character> ciphertextToPlaintext = new ConcurrentHashMap<>();
		final Iterator<Character> encryptedLetters = letterFrequencies.keySet().iterator();
		for (final Character plaintextLetter : this.letterFrequencies.keySet()) {
			ciphertextToPlaintext.put(encryptedLetters.next(), plaintextLetter);
		}
		return ciphertext
				.chars()
				.parallel()
				.mapToObj(letter -> (char) letter)
				.map(ciphertextToPlaintext::get)
				.collect(of(StringBuffer::new, StringBuffer::append, StringBuffer::append, StringBuffer::toString));
	}
	
}
