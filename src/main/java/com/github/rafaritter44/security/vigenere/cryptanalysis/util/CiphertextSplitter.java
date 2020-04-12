package com.github.rafaritter44.security.vigenere.cryptanalysis.util;

import java.util.ArrayList;
import java.util.List;

public class CiphertextSplitter {
	
	public ArrayList<String> splitCiphertext(final String ciphertext, final int keyLength) {
		final ArrayList<String> splitCiphertext = new ArrayList<>();
		if (ciphertext == null || keyLength < 1) {
			return splitCiphertext;
		}
		for (int i = 0; i < keyLength; i++) {
			splitCiphertext.add("");
		}
		final int ciphertextLength = ciphertext.length();
		for (int letterIndex = 0; letterIndex < ciphertextLength; letterIndex++) {
			final char letter = ciphertext.charAt(letterIndex);
			final int splitCiphertextIndex = letterIndex % keyLength;
			splitCiphertext.set(splitCiphertextIndex, splitCiphertext.get(splitCiphertextIndex) + letter);
		}
		return splitCiphertext;
	}
	
	public String mergeSplitPlaintext(final List<String> splitPlaintext) {
		if (splitPlaintext == null || splitPlaintext.isEmpty() || splitPlaintext.contains(null)) {
			return "";
		}
		final StringBuilder mergedPlaintext = new StringBuilder();
		final int keyLength = splitPlaintext.size();
		boolean over = false;
		for (int letterIndex = 0; !over; letterIndex++) {
			for (int splitPlaintextIndex = 0; splitPlaintextIndex < keyLength; splitPlaintextIndex++) {
				final String chunk = splitPlaintext.get(splitPlaintextIndex);
				if (letterIndex >= chunk.length()) {
					over = true;
					break;
				}
				mergedPlaintext.append(chunk.charAt(letterIndex));
			}
		}
		return mergedPlaintext.toString();
	}
	
}
