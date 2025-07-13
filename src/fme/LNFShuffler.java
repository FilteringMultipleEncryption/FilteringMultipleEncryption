package fme;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;

import hash.HashFunction;

public class LNFShuffler {

	protected int d;
	protected double beta;
	protected ArrayList<Integer> allHashValues;
	protected ArrayList<Integer> allOrgValues;
	protected ArrayList<Integer> sampledHashValues;
	protected ArrayList<Integer> sampledOrgValues;
	protected LNFAbstractDummyDistribution distribution;
	protected List<Integer> turn2values;
	protected int b = -1;
	protected HashFunction hashFunction;

	public LNFShuffler(int d, double beta, LNFAbstractDummyDistribution distribution, int b,
			HashFunction hashFunction) {
		this.d = d;
		this.beta = beta;
		this.distribution = distribution;
		this.b = b;
		this.hashFunction = hashFunction;
		allHashValues = new ArrayList<Integer>();
		allOrgValues = new ArrayList<Integer>();
		sampledHashValues = new ArrayList<Integer>();
		sampledOrgValues = new ArrayList<Integer>();
	}

	private boolean[] getSampleBools(int n, Random rand) {
		boolean bs[] = new boolean[n];
		for (int i = 0; i < n; i++) {
			if (rand.nextDouble() < beta) {
				bs[i] = true;
			} else {
				bs[i] = false;
			}
		}
		return bs;
	}

	/**
	 * Round1
	 */
	public void receiveValue(int hashValue, int orgValue) {
		allHashValues.add(hashValue);
		allOrgValues.add(orgValue);
	}

	/**
	 * Round1
	 */
	public void sampleAndAddFakeValues(Random rand) {

		boolean bs[] = getSampleBools(allHashValues.size(), rand);

		for (int i = 0; i < bs.length; i++) {
			if (bs[i]) {
				sampledHashValues.add(allHashValues.get(i));
				sampledOrgValues.add(allOrgValues.get(i));
			}
		}

		allHashValues.clear();
		allOrgValues.clear();

		for (int i = 0; i < b; i++) {
			int zi = distribution.sample();
			for (int j = 0; j < zi; j++) {
				sampledHashValues.add(i);
				sampledOrgValues.add(null);
			}
		}
	}

	public void receiveValues2(List<Integer> vals) {
		turn2values = vals;
	}

	public List<Integer> getSampledHashValues() {
		return sampledHashValues;
	}

	public List<Integer> getSampledOrgValues() {
		return sampledOrgValues;
	}

	public void addFakeValues(HashSet<Integer> filteringInfo) throws NoSuchAlgorithmException {
		for (int i = 0; i < d; i++) {
			if (filteringInfo.contains(i)) {
				int zi = distribution.sample();
				for (int j = 0; j < zi; j++) {
					turn2values.add(i);
				}
			}
		}
	}

	public List<Integer> getTurn2Values() {
		return turn2values;

	}

}
