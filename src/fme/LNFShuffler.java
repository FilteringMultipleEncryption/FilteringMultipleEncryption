package fme;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.EncryptionUtil;
import hash.HashFunction;

public class LNFShuffler {

	protected int d;
	protected double beta;
	protected ArrayList<byte[]> allValues;
	protected ArrayList<byte[]> sampledValues;
	protected LNFAbstractDummyDistribution distribution;
	protected PublicKey pk;
	protected int b = -1;
	protected HashFunction hashFunction;

	public LNFShuffler(int d, double beta, LNFAbstractDummyDistribution distribution, PublicKey pk, int b,
			HashFunction hashFunction) {
		this.d = d;
		this.beta = beta;
		this.distribution = distribution;
		allValues = new ArrayList<byte[]>();
		sampledValues = new ArrayList<byte[]>();
		this.pk = pk;
		this.b = b;
		this.hashFunction = hashFunction;
	}

	public void receiveValue(byte[] value) {
		allValues.add(value);
	}

	/**
	 * Round1
	 */
	public void sampleAndAddFakeValues() {

		for (byte[] value : allValues) {
			if (Math.random() < beta) {
				sampledValues.add(value);
			}
		}
		allValues.clear();

		for (int i = 0; i < b; i++) {
			int zi = distribution.sample();
			for (int j = 0; j < zi; j++) {
				byte[] encryptedValue;
				try {
					encryptedValue = EncryptionUtil.encrypt(pk, i);
					sampledValues.add(encryptedValue);
				} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
						| NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public void addFakeValues(int counts[]) {

		for (int i = 0; i < b; i++) {
			int zi = distribution.sample();
			counts[i] += zi;
		}
	}

	/**
	 * Ruond2
	 * 
	 * @param filteringInfo
	 * @throws NoSuchAlgorithmException
	 */
	public void sampleAndAddFakeValues(HashSet<Integer> filteringInfo) throws NoSuchAlgorithmException {
		sampledValues.clear();
		for (byte[] value : allValues) {
			if (Math.random() < beta) {
				sampledValues.add(value);
			}
		}
		allValues.clear();

		for (int i = 0; i < d; i++) {
			int hashValue = hashFunction.calculateHash(i);
			if (!filteringInfo.contains(hashValue)) {
				continue;
			}
			int zi = distribution.sample();
			for (int j = 0; j < zi; j++) {
				byte[] encryptedValue;
				try {
					encryptedValue = EncryptionUtil.encrypt(pk, i);
					sampledValues.add(encryptedValue);
				} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
						| NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
					e.printStackTrace();
				}
			}
		}

		int zi = distribution.sample();
		for (int j = 0; j < zi; j++) {
			byte[] encryptedValue;
			try {
				encryptedValue = EncryptionUtil.encrypt(pk, Util.nonExist);
				sampledValues.add(encryptedValue);
			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
					| NoSuchPaddingException | NoSuchProviderException e) {
				e.printStackTrace();
			}
		}
	}

	public void addFakeValues(HashSet<Integer> filteringInfo, int counts[]) throws NoSuchAlgorithmException {

		for (int i = 0; i < d; i++) {
			if (filteringInfo.contains(i)) {
				int zi = distribution.sample();
				counts[i] += zi;
			}
		}
	}

	public ArrayList<byte[]> getPermutatedValues() {
		// Collections.shuffle(sampledValues);for test
		return sampledValues;
	}

}
