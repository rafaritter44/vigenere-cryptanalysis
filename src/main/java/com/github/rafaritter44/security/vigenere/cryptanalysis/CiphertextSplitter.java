package com.github.rafaritter44.security.vigenere.cryptanalysis;

import java.util.ArrayList;

public class CiphertextSplitter {
	
	public ArrayList<String> splitCiphertext(final String ciphertext, final int keyLength) {
		final ArrayList<String> splitCiphertext = new ArrayList<>();
		if (ciphertext == null || keyLength < 1) {
			return splitCiphertext;
		}
		for (int i = 0; i < keyLength; i++) {
			splitCiphertext.add("");
		}
		final int cipertextLength = ciphertext.length();
		for (int letterIndex = 0; letterIndex < cipertextLength; letterIndex++) {
			final char letter = ciphertext.charAt(letterIndex);
			final int splitCiphertextIndex = letterIndex % keyLength;
			splitCiphertext.set(splitCiphertextIndex, splitCiphertext.get(splitCiphertextIndex) + letter);
		}
		return splitCiphertext;
	}
	
}
