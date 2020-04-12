package com.github.rafaritter44.security.vigenere.cryptanalysis;

import static java.lang.Math.abs;
import static java.util.Comparator.comparing;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toConcurrentMap;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.IntStream;

public class CoincidenceCounter implements KeyLengthFinder {
	
	private final double actualCoincidenceIndex;
	private final int maxKeyLength;
	
	public CoincidenceCounter(final double actualCoincidenceIndex, final int maxKeyLength) {
		this.actualCoincidenceIndex = actualCoincidenceIndex;
		this.maxKeyLength = maxKeyLength;
	}
	
	@Override
	public List<Integer> findKeyLength(final String ciphertext) {
		return IntStream
				.rangeClosed(1, maxKeyLength)
				.parallel()
				.boxed()
				.collect(toConcurrentMap(identity(), keyLength -> calculateCoincidenceIndex(ciphertext, keyLength)))
				.entrySet()
				.parallelStream()
				.sorted(comparing(index -> abs(actualCoincidenceIndex - index.getValue())))
				.map(Entry::getKey)
				.collect(toList());
	}
	
	private double calculateCoincidenceIndex(final String ciphertext, final int keyLength) {
		final ArrayList<String> splitCiphertext = new ArrayList<>();
		for (int i = 0; i < keyLength; i++) {
			splitCiphertext.add("");
		}
		final int cipertextLength = ciphertext.length();
		for (int letterIndex = 0; letterIndex < cipertextLength; letterIndex++) {
			final char letter = ciphertext.charAt(letterIndex);
			final int splitCiphertextIndex = letterIndex % keyLength;
			splitCiphertext.set(splitCiphertextIndex, splitCiphertext.get(splitCiphertextIndex) + letter);
		}
		return splitCiphertext
				.parallelStream()
				.mapToDouble(chunk -> {
					final Map<Character, Integer> letterFrequencies = chunk
						.chars()
						.parallel()
						.mapToObj(letter -> (char) letter)
						.collect(toConcurrentMap(identity(), letter -> 1, Integer::sum));
					return calculateCoincidenceIndex(letterFrequencies, chunk.length());
				})
				.average()
				.orElse(0D);
	}
	
	private double calculateCoincidenceIndex(
			final Map<Character, Integer> letterFrequencies,
			final int textLength) {
		return textLength == 0 ? 0D : letterFrequencies
				.values()
				.parallelStream()
				.mapToDouble(letterFrequency -> letterFrequency * (letterFrequency - 1D))
				.sum() / (textLength * (textLength - 1));
	}
	
}
