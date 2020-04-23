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
			final int keyLengthIndex = i;
			cryptanalyser.findKeys(i);
			cryptanalyser.decrypt(i).ifPresent(plaintext -> {
				System.out.println(plaintext);
				final int keyLength = keyLengths.get(keyLengthIndex);
				System.out.printf("Key length: %d\n", keyLength);
				System.out.printf("Key: %s\n", cryptanalyser.getKey());
				System.out.println("Is that it? (y/n)");
				if ("y".equalsIgnoreCase(scanner.nextLine())) {
					final String plaintextFile = args[CIPHERTEXT].replace(".", ".plaintext.");
					fileManager.write(plaintextFile, plaintext);
					System.out.println("Plaintext written to " + plaintextFile);
					scanner.close();
					appCtxt.close();
					System.exit(0);
				}
				System.out.println("Try another key length? (y/n)");
				if (!"y".equalsIgnoreCase(scanner.nextLine())) {
					while (true) {
						System.out.printf("Change which letter from the key? [0-%d]\n", keyLength - 1);
						final String input = scanner.nextLine();
						if (input.matches("[0-9]+")) {
							final int keyLetterIndex = Integer.parseInt(input);
							final Optional<String> newPlaintext = cryptanalyser.decrypt(keyLengthIndex, keyLetterIndex);
							if (newPlaintext.isPresent()) {
								System.out.println(newPlaintext.get());
								System.out.printf("Key: %s\n", cryptanalyser.getKey());
								System.out.println("Is that it? (y/n)");
								if ("y".equalsIgnoreCase(scanner.nextLine())) {
									final String plaintextFile = args[CIPHERTEXT].replace(".", ".plaintext.");
									fileManager.write(plaintextFile, newPlaintext.get());
									System.out.println("Plaintext written to " + plaintextFile);
									scanner.close();
									appCtxt.close();
									System.exit(0);
								} else {
									System.out.println("Try another key length? (y/n)");
									if ("y".equalsIgnoreCase(scanner.nextLine())) {
										break;
									}
								}
							} else {
								System.out.println("No options left for that letter.");
								System.out.println("Try another key length? (y/n)");
								if ("y".equalsIgnoreCase(scanner.nextLine())) {
									break;
								}
							}
						}
					}
				}
			});
		}
		scanner.close();
		appCtxt.close();
	}
	
}
