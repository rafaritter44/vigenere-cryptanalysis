package com.github.rafaritter44.security.vigenere.cryptanalysis.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.rafaritter44.security.vigenere.cryptanalysis.Cryptanalyser;
import com.github.rafaritter44.security.vigenere.cryptanalysis.VigenereSquare;
import com.github.rafaritter44.security.vigenere.cryptanalysis.io.FileManager;
import com.github.rafaritter44.security.vigenere.cryptanalysis.key.FrequencyAnalyzer;
import com.github.rafaritter44.security.vigenere.cryptanalysis.key.length.CoincidenceCounter;
import com.github.rafaritter44.security.vigenere.cryptanalysis.key.length.KeyLengthFinder;
import com.github.rafaritter44.security.vigenere.cryptanalysis.util.CiphertextSplitter;

@Configuration
public class CryptanalysisConfig {
	
	@Bean
	public Cryptanalyser cryptanalyser(
			final KeyLengthFinder keyLengthFinder,
			final FrequencyAnalyzer frequencyAnalyzer,
			final CiphertextSplitter ciphertextSplitter,
			final VigenereSquare vigenereSquare) {
		return new Cryptanalyser(keyLengthFinder, frequencyAnalyzer, ciphertextSplitter, vigenereSquare);
	}
	
	@Bean
	public FrequencyAnalyzer frequencyAnalyzer(
			final VigenereSquare vigenereSquare,
			final @Qualifier("portugueseLetterFrequencies") Map<Character, Double> letterFrequencies,
			final @Qualifier("alphabet") String alphabet) {
		return new FrequencyAnalyzer(vigenereSquare, letterFrequencies, alphabet);
	}
	
	@Bean
	public VigenereSquare VigenereSquare(final @Qualifier("alphabet") String alphabet) {
		return new VigenereSquare(alphabet);
	}
	
	@Bean
	public KeyLengthFinder keyLengthFinder(
			final CiphertextSplitter ciphertextSplitter,
			final @Qualifier("portugueseCoincidenceIndex") double actualCoincidenceIndex,
			final @Qualifier("maxKeyLength") int maxKeyLength) {
		return new CoincidenceCounter(ciphertextSplitter, actualCoincidenceIndex, maxKeyLength);
	}
	
	@Bean
	public CiphertextSplitter ciphertextSplitter() {
		return new CiphertextSplitter();
	}
	
	@Bean
	public FileManager fileManager() {
		return new FileManager();
	}
	
	@Bean("alphabet")
	public String alphabet() {
		return "abcdefghijklmnopqrstuvwxyz";
	}
	
	@Bean("portugueseLetterFrequencies")
	public Map<Character, Double> portugueseLetterFrequencies() {
		final HashMap<Character, Double> letterFrequencies = new HashMap<>();
		letterFrequencies.put('a', 0.14634 + 0.00733 + 0.00562 + 0.00118 + 0.00072);
		letterFrequencies.put('e', 0.12570 + 0.00450 + 0.00337);
		letterFrequencies.put('o', 0.09735 + 0.00635 + 0.00296 + 0.00040);
		letterFrequencies.put('s', 0.06805);
		letterFrequencies.put('r', 0.06530);
		letterFrequencies.put('i', 0.06186 + 0.00132);
		letterFrequencies.put('d', 0.04992);
		letterFrequencies.put('m', 0.04738);
		letterFrequencies.put('n', 0.04446);
		letterFrequencies.put('t', 0.04336);
		letterFrequencies.put('c', 0.03882 + 0.00530);
		letterFrequencies.put('u', 0.03639 + 0.00207 + 0.00026);
		letterFrequencies.put('l', 0.02779);
		letterFrequencies.put('p', 0.02523);
		letterFrequencies.put('v', 0.01575);
		letterFrequencies.put('g', 0.01303);
		letterFrequencies.put('q', 0.01204);
		letterFrequencies.put('b', 0.01043);
		letterFrequencies.put('f', 0.01023);
		letterFrequencies.put('h', 0.00781);
		letterFrequencies.put('z', 0.00470);
		letterFrequencies.put('j', 0.00397);
		letterFrequencies.put('x', 0.00253);
		letterFrequencies.put('w', 0.00037);
		letterFrequencies.put('k', 0.00015);
		letterFrequencies.put('y', 0.00006);
		return letterFrequencies;
	}
	
	@Bean("portugueseCoincidenceIndex")
	public double portugueseCoincidenceIndex() {
		return 0.072723;
	}
	
	@Bean("maxKeyLength")
	public int maxKeyLength() {
		return 20;
	}
	
}
