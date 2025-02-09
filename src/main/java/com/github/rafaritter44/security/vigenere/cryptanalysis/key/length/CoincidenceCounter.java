package com.github.rafaritter44.security.vigenere.cryptanalysis.key.length;

import static java.lang.Math.abs;
import static java.util.Comparator.comparing;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.IntStream;

import com.github.rafaritter44.security.vigenere.cryptanalysis.util.CiphertextSplitter;

public class CoincidenceCounter implements KeyLengthFinder {
	
	private final CiphertextSplitter ciphertextSplitter;
	private final double actualCoincidenceIndex;
	private final int maxKeyLength;
	
	public CoincidenceCounter(
			final CiphertextSplitter ciphertextSplitter,
			final double actualCoincidenceIndex,
			final int maxKeyLength) {
		this.ciphertextSplitter = ciphertextSplitter;
		this.actualCoincidenceIndex = actualCoincidenceIndex;
		this.maxKeyLength = maxKeyLength;
	}
	
	@Override
	public List<Integer> findKeyLengths(final String ciphertext) {
		if (ciphertext == null) {
			return Collections.emptyList();
		}
		return IntStream
				.rangeClosed(1, maxKeyLength)
				.parallel()
				.boxed()
				.collect(toMap(identity(), keyLength -> calculateCoincidenceIndex(ciphertext, keyLength)))
				.entrySet()
				.parallelStream()
				.sorted(comparing(index -> abs(actualCoincidenceIndex - index.getValue())))
				.map(Entry::getKey)
				.collect(toList());
	}
	
	private double calculateCoincidenceIndex(final String ciphertext, final int keyLength) {
		return ciphertextSplitter
				.splitCiphertext(ciphertext, keyLength)
				.parallelStream()
				.mapToDouble(chunk -> {
					final Map<Character, Integer> letterFrequencies = chunk
						.chars()
						.parallel()
						.mapToObj(letter -> (char) letter)
						.collect(toMap(identity(), letter -> 1, Integer::sum));
					return calculateCoincidenceIndex(letterFrequencies, chunk.length());
				})
				.average()
				.orElse(0D);
	}
	
	private double calculateCoincidenceIndex(
			final Map<Character, Integer> letterFrequencies,
			final double textLength) {
		return textLength == 0 ? 0D : letterFrequencies
				.values()
				.parallelStream()
				.mapToDouble(letterFrequency -> letterFrequency * (letterFrequency - 1D))
				.sum() / (textLength * (textLength - 1D));
	}
	
}
