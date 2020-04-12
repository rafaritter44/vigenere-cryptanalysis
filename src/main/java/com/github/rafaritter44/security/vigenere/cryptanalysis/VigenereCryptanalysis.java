package com.github.rafaritter44.security.vigenere.cryptanalysis;

import java.util.List;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import com.github.rafaritter44.security.vigenere.cryptanalysis.config.CryptanalysisConfig;

public class VigenereCryptanalysis {
	
	public static void main(final String[] args) {
		final AnnotationConfigApplicationContext appCtxt = new AnnotationConfigApplicationContext(CryptanalysisConfig.class);
		final Cryptanalyser cryptanalyser = appCtxt.getBean(Cryptanalyser.class);
		cryptanalyser.setCiphertext(args[0]);
		cryptanalyser.findKeyLengths();
		final List<Integer> keyLengths = cryptanalyser.getKeyLengths();
		final int amountOfKeyLengths = keyLengths.size();
		for (int i = 0; i < amountOfKeyLengths; i++) {
			cryptanalyser.decrypt(keyLengths.get(i)).ifPresent(System.out::println);
		}
		appCtxt.close();
	}
	
}
