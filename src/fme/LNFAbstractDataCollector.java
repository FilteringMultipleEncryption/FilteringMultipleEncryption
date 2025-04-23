package fme;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.EncryptionUtil;
import hash.HashFunction;
import hash.HashUtil;
import hash.JK;

public abstract class LNFAbstractDataCollector {

	protected double epsilon;
	protected double delta;
	protected int d;
	protected int n;
	protected double beta;
	protected int[] frequency1;
	protected float[] frequency2;
	protected LNFAbstractDummyDistribution distribution;
	protected double expectedError;
	protected double expectedApproximatedError;
	protected double expectedErrorHash;
	protected double expectedApproximatedErrorHash;
	protected double mu;
	protected PrivateKey privateKey;
	protected int l;
	protected double alpha;
	protected HashSet<Integer> filteringInfo4hash;
	protected HashSet<Integer> filteringInfo;
	private HashFunction hashFunction;
	protected int remainingItemNum = -1;
	protected int b;

	HashSet<Integer> filteringInfoKey = new HashSet<Integer>();

	int shuffledCount1[];// for key value
	int shuffledCountMinus1[];// for key value

	protected LNFAbstractDataCollector(double epsilon, double delta, int d, int n, PrivateKey privateKey) {
		this.epsilon = epsilon;
		this.delta = delta;
		this.d = d;
		this.n = n;
		frequency1 = new int[b];
		frequency2 = new float[d];
	}

	protected LNFAbstractDataCollector(double epsilon, double delta, int d, int n, PrivateKey privateKey,
			double alpha) {
		this.epsilon = epsilon;
		this.delta = delta;
		this.d = d;
		this.n = n;
		this.alpha = alpha;
		this.privateKey = privateKey;
	}

	public void setParameters(int b, int l, HashFunction hashFunction) {
		this.b = b;
		this.l = l;
		this.hashFunction = hashFunction;
		frequency1 = new int[b];
		frequency2 = new float[d];
	}

	public void receivesAlgorithm1_(ArrayList<byte[]> permutatedValues)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {

		ArrayList<HashSet<JK>> supportingSetMap = HashUtil.getSupportingSetMap(d, new HashFunction[] { hashFunction });

		// for test
		double sa[] = new double[d];
		double saTotal = 0;
		double saTotal2 = 0;
		double c = 0;

		HashMap<JK, Integer> countingMap = new HashMap<JK, Integer>();
		int groupNum = 1;
		for (int j = 0; j < groupNum; j++) {
			for (int k = 0; k < b; k++) {
				JK jk = new JK(j, k);
				countingMap.put(jk, 0);
			}
		}

		for (byte[] encryptedValue : permutatedValues) {
			int value = EncryptionUtil.decrypt(privateKey, encryptedValue);
			JK jk = new JK(0, value);
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
			frequency2[i] = (float) ((double) b / (n * beta * (b - 1)) * (hjkSum - n * beta / b - groupNum * mu));

		}

	}

	public void receivesAlgorithm1(ArrayList<byte[]> permutatedValues)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {

		HashMap<Integer, HashSet<Integer>> map = new HashMap<Integer, HashSet<Integer>>();
		for (int i = 0; i < b; i++) {
			map.put(i, new HashSet<Integer>());
		}

		for (int i = 0; i < d; i++) {
			int hashValue = hashFunction.calculateHash(i);
			map.get(hashValue).add(i);
		}

		for (byte[] encryptedValue : permutatedValues) {
			int hashValue = EncryptionUtil.decrypt(privateKey, encryptedValue);
			for (int coverValue : map.get(hashValue)) {
				frequency2[coverValue]++;
			}

		}

		for (int i = 0; i < d; i++) {
			frequency2[i] = (float) (b / (n * beta * (b - 1)) * (frequency2[i] - n * beta / b - mu));
		}

	}

	public void receives1(ArrayList<byte[]> permutatedValues) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		for (byte[] encryptedValue : permutatedValues) {
			int value = EncryptionUtil.decrypt(privateKey, encryptedValue);
			frequency1[value]++;
		}
		generateFilteringInfo();
		frequency1 = null;// release memory.
	}

	public void receives1(int counts[]) {
		frequency1 = counts;
		generateFilteringInfo();
	}

	public void receives1WO(int counts[], int dDash2) {
		frequency1 = counts;
		generateFilteringInfoWO(dDash2);
	}

	public void receives1keyValue(int counts[], int kappa) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

		double count[] = new double[d];
		int dDash = d + kappa;

		HashMap<Integer, Set<Integer>> map = new HashMap<Integer, Set<Integer>>();
		for (int i = 0; i < d; i++) {

			int keyValueId = Util.getKeyValueId(i, -1, dDash);
			int hashValue = hashFunction.calculateHash(keyValueId);
			if (map.containsKey(hashValue)) {
				map.get(hashValue).add(i);
			} else {
				Set<Integer> set = new HashSet<Integer>();
				set.add(i);
				map.put(hashValue, set);
			}
			keyValueId = Util.getKeyValueId(i, 1, dDash);
			hashValue = hashFunction.calculateHash(keyValueId);
			if (map.containsKey(hashValue)) {
				map.get(hashValue).add(i);
			} else {
				Set<Integer> set = new HashSet<Integer>();
				set.add(i);
				map.put(hashValue, set);
			}
		}

		// for (File file : files) {
		// ArrayList<byte[]> list = loadArrayListFromFile(kryo, file.getAbsolutePath());
		// for (byte[] encryptedValue : list) {
		// int hashValue = EncryptionUtil.decrypt(privateKey, encryptedValue);

		for (int i = 0; i < b; i++) {
			Set<Integer> keys = map.get(i);
			if (keys != null) {
				for (int key : keys) {
					if (key < d) {
						// count[key] += (double) counts[i] / keys.size();
						count[key] += (double) counts[i];
					}
				}
			}
		}

		generateFilteringInfoKeyValue(count, kappa);
	}

	public void receives1keyValueKeys(int counts[], int kappa) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

		double count[] = new double[d];
		int dDash = d + kappa;

		HashMap<Integer, Set<Integer>> map = new HashMap<Integer, Set<Integer>>();
		for (int i = 0; i < d; i++) {

			int keyValueId = Util.getKeyValueId(i, -1, dDash);
			int hashValue = hashFunction.calculateHash(keyValueId);
			if (map.containsKey(hashValue)) {
				map.get(hashValue).add(i);
			} else {
				Set<Integer> set = new HashSet<Integer>();
				set.add(i);
				map.put(hashValue, set);
			}
			keyValueId = Util.getKeyValueId(i, 1, dDash);
			hashValue = hashFunction.calculateHash(keyValueId);
			if (map.containsKey(hashValue)) {
				map.get(hashValue).add(i);
			} else {
				Set<Integer> set = new HashSet<Integer>();
				set.add(i);
				map.put(hashValue, set);
			}
		}

		for (int i = 0; i < b; i++) {
			Set<Integer> keys = map.get(i);
			if (keys != null) {
				for (int key : keys) {
					if (key < d) {
						// count[key] += (double) counts[i] / keys.size();
						count[key] += (double) counts[i];
					}
				}
			}
		}

		generateFilteringInfoKeyValue(count, kappa);
	}

	public void receives2(ArrayList<byte[]> permutatedValues) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

		for (byte[] encryptedValue : permutatedValues) {
			int value = EncryptionUtil.decrypt(privateKey, encryptedValue);

			if (value == Util.nonExist) {
				continue;
			}

			if (filteringInfo.contains(value)) {
				frequency2[value]++;
			}

		}

		for (int i = 0; i < d; i++) {
			if (filteringInfo.contains(i)) {
				frequency2[i] = (float) (1.0 / n / beta * (frequency2[i] - mu));
			}
		}

		remainingItemNum = filteringInfo.size();
	}

	public void receives2(int counts[]) {

		for (int i = 0; i < d; i++) {
			if (filteringInfo.contains(i)) {
				frequency2[i] = (float) (1.0 / n / beta * (counts[i] - mu));
			}
		}

		remainingItemNum = filteringInfo.size();
	}

	public void receives2keyValueWO(int counts[], int kappa) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

		// HashSet<Integer> notContains = new HashSet<Integer>();
		shuffledCount1 = new int[d];
		shuffledCountMinus1 = new int[d];

		for (int id = 0; id < 2 * (d + kappa); id++) {

			Map.Entry<Integer, Integer> key_value = Util.getMap(id, d + kappa);
			int key = key_value.getKey();
			if (key >= d) {
				continue;
			}
			int value = key_value.getValue();

			if (filteringInfo.contains(id)) {
				if (value == 1) {
					shuffledCount1[key] += counts[id];
				} else if (value == -1) {
					shuffledCountMinus1[key] += counts[id];
				} else {
					System.err.println("Error");
					System.exit(-1);
				}
			}
		}

		for (int k = 0; k < d; k++) {
			frequency2[k] = (float) (kappa / beta / n * (shuffledCount1[k] + shuffledCountMinus1[k] - 2 * mu));
		}

		// remainingItemNum = first_round_contains.size();
		remainingItemNum = filteringInfo.size();
	}

	public void receives2keyValue(int counts[], int kappa) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

		// HashSet<Integer> notContains = new HashSet<Integer>();
		shuffledCount1 = new int[d];
		shuffledCountMinus1 = new int[d];

		for (int id = 0; id < 2 * (d + kappa); id++) {

			Map.Entry<Integer, Integer> key_value = Util.getMap(id, d + kappa);
			int key = key_value.getKey();
			if (key >= d) {
				continue;
			}
			int value = key_value.getValue();

			if (filteringInfoKey.contains(key)) {
				if (value == 1) {
					shuffledCount1[key] += counts[id];
				} else if (value == -1) {
					shuffledCountMinus1[key] += counts[id];
				} else {
					System.err.println("Error");
					System.exit(-1);
				}
			}
		}

		for (int k = 0; k < d; k++) {
			if (filteringInfo.contains(k)) {
				frequency2[k] = (float) (kappa / beta / n * (shuffledCount1[k] + shuffledCountMinus1[k] - 2 * mu));
			}
		}

		// remainingItemNum = first_round_contains.size();
		remainingItemNum = filteringInfo.size();
	}

	public int getRemainingItemNum() {
		return remainingItemNum;
	}

	private void generateFilteringInfo() {

		filteringInfo = new HashSet<Integer>();
		filteringInfo4hash = new HashSet<Integer>();
		int zth = distribution.getZth(alpha);
		int topIndex[] = Util.getTopIndices(frequency1, l);

		for (int index : topIndex) {
			if (frequency1[index] >= zth) {
				filteringInfo4hash.add(index);
			} else {
				break;
			}
		}

		for (int i = 0; i < d; i++) {
			int hashValue = hashFunction.calculateHash(i);
			if (filteringInfo4hash.contains(hashValue)) {
				filteringInfo.add(i);
			}
		}

	}

	private void generateFilteringInfoWO(int dDash2) {

		filteringInfo = new HashSet<Integer>();
		filteringInfo4hash = new HashSet<Integer>();
		int zth = distribution.getZth(alpha);
		int topIndex[] = Util.getTopIndices(frequency1, l);

		for (int index : topIndex) {
			if (frequency1[index] >= zth) {
				filteringInfo4hash.add(index);
			} else {
				break;
			}
		}

		for (int i = 0; i < dDash2; i++) {
			int hashValue = hashFunction.calculateHash(i);
			if (filteringInfo4hash.contains(hashValue)) {
				filteringInfo.add(i);
			}
		}

	}

	private void generateFilteringInfoKeyValue(double count[], int kappa) throws NoSuchAlgorithmException {
		filteringInfo4hash = new HashSet<Integer>();
		filteringInfo = new HashSet<Integer>();
		int zth = distribution.getZth(alpha);
		int topIndex[] = Util.getTopIndices(count, l);

		for (int index : topIndex) {
			if (count[index] >= zth) {
				filteringInfoKey.add(index);
				filteringInfo.add(Util.getKeyValueId(index, -1, d + kappa));
				filteringInfo.add(Util.getKeyValueId(index, 1, d + kappa));
				int hashValue1 = hashFunction.calculateHash(Util.getKeyValueId(index, -1, d + kappa));
				int hashValue2 = hashFunction.calculateHash(Util.getKeyValueId(index, 1, d + kappa));
				filteringInfo4hash.add(hashValue1);
				filteringInfo4hash.add(hashValue2);
			} else {
				break;
			}
		}

	}

	public HashSet<Integer> getFilteringInfo4hash() {

		return filteringInfo4hash;
	}

	public HashSet<Integer> getFilteringInfoKey() {

		return filteringInfoKey;
	}

	public HashSet<Integer> getFilteringInfo() {

		return filteringInfo;
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

	public float[] getFrequency() {
		return frequency2;
	}

	public float[] getMean(int kappa, float f[]) {

		float mean[] = new float[f.length];
		for (int k = 0; k < d; k++) {
			if (filteringInfoKey.contains(k)) {
				if (f[k] <= 0) {
					mean[k] = (float) 0.0;
					// mean[k] = (float) 1.0;
				} else {
					mean[k] = (float) (kappa / beta / n / f[k] * (shuffledCount1[k] - shuffledCountMinus1[k]));
				}
			} else {
				mean[k] = (float) 1.0;
			}
		}

		return mean;
	}

	public float[] getMeanWO(int kappa, float f[]) {

		float mean[] = new float[f.length];
		for (int k = 0; k < d; k++) {
			if (f[k] <= 0) {
				mean[k] = (float) 0.0;
				// mean[k] = (float) 1.0;
			} else {
				mean[k] = (float) (kappa / beta / n / f[k] * (shuffledCount1[k] - shuffledCountMinus1[k]));
			}

		}

		return mean;
	}

	public double getExpectedError_() {
		double error = (1 - beta) / (beta * n) + distribution.getSigma2() * d / (beta * beta * n * n);
		return error;
	}

	public double getExpectedErrorCommonHash2() {
		double vhij = ((double) n * n * beta * beta / d + n * beta * (1 - beta)) * (1.0 / b) * (1 - 1.0 / b)
				+ n * beta * (1 - beta) * (1.0 / b / b);
		vhij *= (d - 1.0) / d;

		double error = (double) b * b / ((double) n * n * beta * beta * (b - 1) * (b - 1))
				* (n * beta * (1 - beta) + d * vhij + distribution.getSigma2() * d);
		return error;
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
}
