package fme;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import hash.HashFunction;

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
	protected List<Integer> turn2OrgValues;
	protected int b;

	HashSet<Integer> filteringInfoKey = new HashSet<Integer>();

	int shuffledCount1[];// for key value
	int shuffledCountMinus1[];// for key value

	protected LNFAbstractDataCollector(double epsilon, double delta, int d, int n) {
		this.epsilon = epsilon;
		this.delta = delta;
		this.d = d;
		this.n = n;
		frequency1 = new int[b];
		frequency2 = new float[d];
	}

	protected LNFAbstractDataCollector(double epsilon, double delta, int d, int n, double alpha) {
		this.epsilon = epsilon;
		this.delta = delta;
		this.d = d;
		this.n = n;
		this.alpha = alpha;
	}

	public void setParameters(int b, int l, HashFunction hashFunction) {
		this.b = b;
		this.l = l;
		this.hashFunction = hashFunction;
		frequency1 = new int[b];
		frequency2 = new float[d];
	}

	public void receives1(int counts[]) {
		frequency1 = counts;
		generateFilteringInfo();
	}

	public void receives1(List<Integer> hashValues, List<Integer> vals) {
		turn2OrgValues = vals;
		for (int hashValue : hashValues) {
			frequency1[hashValue]++;
		}
		generateFilteringInfo();

		for (int i = 0; i < hashValues.size(); i++) {
			if (!filteringInfo4hash.contains(hashValues.get(i))) {
				turn2OrgValues.set(i, null);
			}
		}
	}

	public void receives1keyValue(List<Integer> hashValues, List<Integer> vals, int kappa)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {

		turn2OrgValues = vals;

		double counts[] = new double[b];
		for (int hashValue : hashValues) {
			counts[hashValue]++;
		}

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
						count[key] += (double) counts[i];
					}
				}
			}
		}

		generateFilteringInfoKeyValue(count, kappa);

		for (int i = 0; i < hashValues.size(); i++) {
			if (!filteringInfo4hash.contains(hashValues.get(i))) {
				turn2OrgValues.set(i, null);
			}
		}
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

		for (int i = 0; i < b; i++) {
			Set<Integer> keys = map.get(i);
			if (keys != null) {
				for (int key : keys) {
					if (key < d) {
						count[key] += (double) counts[i];
					}
				}
			}
		}

		generateFilteringInfoKeyValue(count, kappa);
	}

	public void receives2(int counts[]) {

		for (int i = 0; i < d; i++) {
			if (filteringInfo.contains(i)) {
				frequency2[i] = (float) (1.0 / n / beta * (counts[i] - mu));
			}
		}

	}

	public void receives2(List<Integer> vals) {

		int counts[] = new int[d];
		for (Integer val : vals) {
			if (val != null) {
				counts[val]++;
			}
		}

		for (int i = 0; i < d; i++) {
			if (filteringInfo.contains(i)) {
				frequency2[i] = (float) (1.0 / n / beta * (counts[i] - mu));
			}
		}

	}

	public void receives2keyValue(int counts[], int kappa) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

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

	}

	public void receives2keyValue(List<Integer> vals, int kappa) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

		int counts[] = new int[2 * (d + kappa)];
		for (Integer val : vals) {
			if (val != null) {
				counts[val]++;
			}
		}

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

	public HashSet<Integer> getFilteringInfo() {

		return filteringInfo;
	}

	public LNFAbstractDummyDistribution getDistribution() {
		return distribution;
	}

	public double getBeta() {
		return beta;
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
				} else {
					mean[k] = (float) (kappa / beta / n / f[k] * (shuffledCount1[k] - shuffledCountMinus1[k]));
				}
			} else {
				mean[k] = (float) 1.0;
			}
		}

		return mean;
	}

}
