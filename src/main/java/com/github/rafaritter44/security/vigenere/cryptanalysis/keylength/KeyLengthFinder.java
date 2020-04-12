package com.github.rafaritter44.security.vigenere.cryptanalysis.keylength;

import java.util.List;

public interface KeyLengthFinder {
	
	List<Integer> findKeyLengths(String ciphertext);
	
}
