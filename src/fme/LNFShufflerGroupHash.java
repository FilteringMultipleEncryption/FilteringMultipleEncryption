package fme;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.EncryptionUtil;
import hash.KeyIdAndHashedValue;

public class LNFShufflerGroupHash {

	private int d;
	private double beta;
	private ArrayList<byte[]> allValues;
	private ArrayList<byte[]> sampledValues;
	private ArrayList<byte[]> permutatedValues;
	protected LNFAbstractDummyDistribution distribution;
	private PublicKey pk;
	private int groupNum = -1;
	private int b = -1;

	public LNFShufflerGroupHash(int d, double beta, LNFAbstractDummyDistribution distribution, PublicKey pk) {
		this.d = d;
		this.beta = beta;
		this.distribution = distribution;
		allValues = new ArrayList<byte[]>();
		sampledValues = new ArrayList<byte[]>();
		this.pk = pk;
	}

	public LNFShufflerGroupHash(int d, double beta, LNFAbstractDummyDistribution distribution, PublicKey pk,
			int groupNum, int b) {
		this.d = d;
		this.beta = beta;
		this.distribution = distribution;
		allValues = new ArrayList<byte[]>();
		sampledValues = new ArrayList<byte[]>();
		this.pk = pk;
		this.groupNum = groupNum;
		this.b = b;
	}

	public void receiveValue(byte[] value) {
		allValues.add(value);
	}

	public void sampleAndAddFakeValues() {

		for (byte[] value : allValues) {
			if (Math.random() < beta) {
				sampledValues.add(value);
			}
		}

		for (int i = 0; i < d; i++) {
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

	public void sampleAndAddFakeHashedValues() {

		if (groupNum == -1) {
			System.err.println("Please set the groupNum by the Constructor!");
		}

		for (byte[] value : allValues) {
			if (Math.random() < beta) {
				sampledValues.add(value);
			}
		}

		for (int g = 0; g < groupNum; g++) {
			for (int i = 0; i < b; i++) {
				int zi = distribution.sample();

				for (int j = 0; j < zi; j++) {
					byte[] encryptedValue;
					KeyIdAndHashedValue hashedKeyAndValue = new KeyIdAndHashedValue(g, i);
					try {
						encryptedValue = EncryptionUtil.encrypt(pk, hashedKeyAndValue);
						sampledValues.add(encryptedValue);
					} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
							| NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
						e.printStackTrace();
					}
				}
			}
		}

	}

	public void permutation() {
		Collections.shuffle(sampledValues);
		permutatedValues = new ArrayList<byte[]>();
		for (byte[] value : sampledValues) {
			permutatedValues.add(value);
		}
	}

	public ArrayList<byte[]> getPermutatedValues() {
		return permutatedValues;
	}

}
