package com.github.rafaritter44.security.vigenere.cryptanalysis.decrypt;

public class DifferentAlphabetSizesException extends RuntimeException {
	
	private static final long serialVersionUID = 8916246857057772851L;
	
	public DifferentAlphabetSizesException(final int sizeA, final int sizeB) {
		super(String.format("The alphabet sizes are different: %d and %d", sizeA, sizeB));
	}

}
