package fme;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import hash.HashFunction;

public class LNFUser {

	protected int value = -100;
	protected int hashValue = -100;
	protected HashMap<Integer, Double> keyValue;
	protected HashFunction hashFunction;
	protected static int kappa;

	protected boolean isRemaining = true;

	public LNFUser(int value) {
		this.value = value;
	}

	public LNFUser(int value, HashFunction hashFunction) throws NoSuchAlgorithmException {
		this.value = value;
		hashValue = hashFunction.calculateHash(value);
	}

	public LNFUser(HashMap<Integer, Double> keyValue, HashFunction hashFunction, int kappa) {
		this.keyValue = keyValue;
		this.hashFunction = hashFunction;
		LNFUser.kappa = kappa;
	}

	public int getOriginalValue() {
		return value;
	}

	public int getHashValue() {
		return hashValue;
	}

	public int getFilteredValue(HashSet<Integer> filteringInfo) {
		if (filteringInfo.contains(hashValue)) {
			return value;
		} else {
			isRemaining = false;
			return Util.nonExist;
		}

	}

	public boolean isRemaining() {
		return this.isRemaining;
	}

	public void setPoisonedValue(Set<Integer> targets, Random random) {
		List<Integer> list = new ArrayList<Integer>();
		list.addAll(targets);
		int rand = (int) (random.nextDouble() * targets.size());
		value = list.get(rand);
	}

	public void keyValuePerturbation(int d, Random rand) throws NoSuchAlgorithmException {
		int keyValSize = keyValue.size();
		int addNum = Math.max(kappa - keyValSize, 0);
		int dDash = d + kappa;

		HashSet<Integer> keySet = new HashSet<Integer>();
		keySet.addAll(keyValue.keySet());

		for (int j = 0; j < addNum; j++) {
			keySet.add(d + 1 + j);
		}
		int key = keySet.stream().skip(rand.nextInt(keySet.size())).findFirst().get();
		double value = keyValue.getOrDefault(key, 0.0);

		int vStar = Integer.MAX_VALUE;
		if (rand.nextDouble() < (1 + value) / 2.0) {
			vStar = 1;
		} else {
			vStar = -1;
		}

		this.value = Util.getKeyValueId(key, vStar, dDash);
		hashValue = hashFunction.calculateHash(this.value);
	}

}
