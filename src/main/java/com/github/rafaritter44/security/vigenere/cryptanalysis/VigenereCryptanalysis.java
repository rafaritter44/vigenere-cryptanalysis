package com.github.rafaritter44.security.vigenere.cryptanalysis;

import java.util.List;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import com.github.rafaritter44.security.vigenere.cryptanalysis.config.CryptanalysisConfig;
import com.github.rafaritter44.security.vigenere.cryptanalysis.io.FileManager;

public class VigenereCryptanalysis {
	
	private static final int CIPHERTEXT = 0;
	
	public static void main(final String[] args) {
		if (args.length < 1 || args[CIPHERTEXT] == null || args[CIPHERTEXT].isEmpty()) {
			System.err.println("Inform the file to be decrypted");
			System.exit(1);
		}
		final AnnotationConfigApplicationContext appCtxt = new AnnotationConfigApplicationContext(CryptanalysisConfig.class);
		final Cryptanalyser cryptanalyser = appCtxt.getBean(Cryptanalyser.class);
		final FileManager fileManager = appCtxt.getBean(FileManager.class);
		final String ciphertext = fileManager.read(args[CIPHERTEXT]);
		cryptanalyser.setCiphertext(ciphertext);
		cryptanalyser.findKeyLengths();
		final List<Integer> keyLengths = cryptanalyser.getKeyLengths();
		final int amountOfKeyLengths = keyLengths.size();
		for (int i = 0; i < amountOfKeyLengths; i++) {
			cryptanalyser.decrypt(keyLengths.get(i)).ifPresent(System.out::println);
		}
		appCtxt.close();
	}
	
}
