package com.github.rafaritter44.security.vigenere.cryptanalysis.decrypt;

import static java.util.Map.Entry.comparingByValue;
import static java.util.function.Function.identity;
import static java.util.stream.Collector.of;
import static java.util.stream.Collectors.toMap;

import java.util.Iterator;
import java.util.LinkedHashMap;
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
				.collect(toMap(Entry::getKey, Entry::getValue, (a,b) -> a, LinkedHashMap::new));
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
				.collect(toMap(identity(), letter -> 1D, Double::sum))
				.entrySet()
				.parallelStream()
				.map(kv -> {
					kv.setValue(kv.getValue() / ciphertextLength);
					return kv;
				})
				.sorted(comparingByValue())
				.collect(toMap(Entry::getKey, Entry::getValue, (a,b) -> a, LinkedHashMap::new));
		if (letterFrequencies.size() > this.letterFrequencies.size()) {
			throw new IllegalArgumentException("The ciphertext alphabet is larger than that of the actual language");
		}
		final Map<Character, Character> ciphertextToPlaintext = new ConcurrentHashMap<>();
		final Iterator<Character> plaintextLetters = this.letterFrequencies.keySet().iterator();
		for (final Character encryptedLetter : letterFrequencies.keySet()) {
			ciphertextToPlaintext.put(encryptedLetter, plaintextLetters.next());
		}
		return ciphertext
				.chars()
				.parallel()
				.mapToObj(letter -> (char) letter)
				.map(ciphertextToPlaintext::get)
				.collect(of(StringBuffer::new, StringBuffer::append, StringBuffer::append, StringBuffer::toString));
	}
	
}
