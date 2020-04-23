package com.github.rafaritter44.security.vigenere.cryptanalysis;

import java.util.HashMap;
import java.util.Map;

public class VigenereSquare {
	
	private final Map<Character, Map<Character, Character>> vigenereSquare;
	
	public VigenereSquare(final String alphabet) {
		vigenereSquare = new HashMap<>();
		final char[] alphabetLetters = alphabet.toCharArray();
		final int alphabetLength = alphabet.length();
		String shiftedAlphabet = alphabet;
		for (char alphabetLetter : alphabetLetters) {
			vigenereSquare.put(alphabetLetter, new HashMap<>());
			final char[] shiftedAlphabetLetters = shiftedAlphabet.toCharArray();
			for (int i = 0; i < alphabetLength; i++) {
				vigenereSquare.get(alphabetLetter).put(shiftedAlphabetLetters[i], alphabetLetters[i]);
			}
			shiftedAlphabet = shiftedAlphabet.substring(1, shiftedAlphabet.length()) + shiftedAlphabet.charAt(0);
		}
	}
	
	/**
	 * This method can be called in one of 2 ways: either passing both the plaintext letter and the ciphertext
	 * letter, in which case it returns the key letter; or passing the key letter and the ciphertext letter, in
	 * which case it returns the plaintext letter.
	 * 
	 * @param letter either the plaintext letter or the key letter
	 * @param ciphertextLetter the ciphertext letter
	 * @return the key letter if received the plaintext letter, or the plaintext letter if received the key letter
	 */
	public char decrypt(final char letter, final char ciphertextLetter) {
		return vigenereSquare.get(letter).get(ciphertextLetter);
	}
	
}
