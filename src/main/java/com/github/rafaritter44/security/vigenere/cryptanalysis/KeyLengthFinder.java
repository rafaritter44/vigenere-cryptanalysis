package com.github.rafaritter44.security.vigenere.cryptanalysis;

import java.util.List;

public interface KeyLengthFinder {
	
	List<Integer> findKeyLength(String ciphertext);
	
}
