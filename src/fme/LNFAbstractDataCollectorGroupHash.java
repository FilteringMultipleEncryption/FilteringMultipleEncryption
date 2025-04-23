package fme;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.EncryptionUtil;
import hash.HashFunction;
import hash.HashUtil;
import hash.JK;

public class LNFAbstractDataCollectorGroupHash extends LNFAbstractDataCollector {

	private HashFunction hashFunctions[];
	private ArrayList<byte[]> permutatedValues;
	private float[] frequency;

	protected LNFAbstractDataCollectorGroupHash(double epsilon, double delta, int d, int n, PrivateKey privateKey) {
		super(epsilon, delta, d, n, privateKey);
		frequency = new float[d];
	}

	public void receivesHashes(ArrayList<byte[]> permutatedValues) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		this.permutatedValues = permutatedValues;
		calcFreqDistHashes();
	}

	public void calcFreqDistHashes() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

		ArrayList<HashSet<JK>> supportingSetMap = HashUtil.getSupportingSetMap(d, hashFunctions);

		// for test
		double sa[] = new double[d];
		double saTotal = 0;
		double saTotal2 = 0;
		double c = 0;

		HashMap<JK, Integer> countingMap = new HashMap<JK, Integer>();
		int groupNum = hashFunctions.length;
		int b = hashFunctions[0].getRange();
		for (int j = 0; j < groupNum; j++) {
			for (int k = 0; k < b; k++) {
				JK jk = new JK(j, k);
				countingMap.put(jk, 0);
			}
		}

		for (byte[] encryptedValue : permutatedValues) {
			int values[] = EncryptionUtil.decryptHashes(privateKey, encryptedValue);
			JK jk = new JK(values[0], values[1]);
			countingMap.put(jk, countingMap.get(jk) + 1);
		}

		for (int i = 0; i < d; i++) {
			int hjkSum = 0;
			for (JK jk : supportingSetMap.get(i)) {
				hjkSum += countingMap.get(jk);
				c += hjkSum;
			}

			sa[i] = hjkSum - groupNum * mu - n / b;
			saTotal += Math.abs(sa[i]);
			saTotal2 += sa[i];
			frequency[i] = (float) ((double) b / (n * beta * (b - 1)) * (hjkSum - n * beta / b - groupNum * mu));
		}

	}

	public float[] getFrequency() {
		return frequency;
	}

	public LNFAbstractDummyDistribution getDistribution() {
		return distribution;
	}

	public double getBeta() {
		return beta;
	}

	public double getExpectedError() {
		return expectedError;
	}

	public double getExpectedApproximatedError() {
		return expectedApproximatedError;
	}

	public double getExpectedErrorHash() {
		return expectedErrorHash;
	}

	public double getExpectedApproximatedErrorHash() {
		return expectedApproximatedErrorHash;
	}

	public double getExpectedErrorBaselineHash(float orgFrequency[], int g) {

		double vhij_sum = 0.0;

		for (int j = 0; j < d; j++) {
			double temp = ((double) n * n * orgFrequency[j] * orgFrequency[j] * beta * beta / g
					+ n * orgFrequency[j] * beta * (1 - beta) / g) * (1.0 / b) * (1 - 1.0 / b)
					+ n * orgFrequency[j] * beta * (1 - beta) / g * (1.0 / b / b);
			vhij_sum += temp;
		}
		vhij_sum *= (d - 1);

		double error = (double) b * b / ((double) n * n * beta * beta * (b - 1) * (b - 1))
				* (n * beta * (1 - beta) + vhij_sum + g * distribution.getSigma2() * d);

		return error;

	}

	public void setParameters(HashFunction[] hashFunctions) {
		this.hashFunctions = hashFunctions;
		this.b = hashFunctions[0].getRange();

	}
}
