package com.github.rafaritter44.security.vigenere.cryptanalysis;

import java.util.List;
import java.util.Optional;
import java.util.Scanner;

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
		final Optional<String> ciphertext = fileManager.read(args[CIPHERTEXT]);
		if (!ciphertext.isPresent()) {
			System.err.println("No such file: " + args[CIPHERTEXT]);
			System.exit(1);
		}
		cryptanalyser.setCiphertext(ciphertext.get());
		cryptanalyser.findKeyLengths();
		final List<Integer> keyLengths = cryptanalyser.getKeyLengths();
		final int amountOfKeyLengths = keyLengths.size();
		final Scanner scanner = new Scanner(System.in);
		for (int i = 0; i < amountOfKeyLengths; i++) {
			cryptanalyser.decrypt(keyLengths.get(i)).ifPresent(plaintext -> {
				System.out.println(plaintext);
				System.out.println("Is that it? (y/n)");
				if ("y".equalsIgnoreCase(scanner.nextLine())) {
					final String plaintextFile = args[CIPHERTEXT].replace(".", ".plaintext.");
					fileManager.write(plaintextFile, plaintext);
					System.out.println("Plaintext written to " + plaintextFile);
					scanner.close();
					appCtxt.close();
					System.exit(0);
				}
			});
		}
		scanner.close();
		appCtxt.close();
	}
	
}
