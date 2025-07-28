package fme;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.math3.distribution.NormalDistribution;

import data.CategoricalDataConfig;
import data.KeyValueDataConfig;
import encryption.ENCRYPTION_MODE;
import encryption.EncryptionUtil;
import util.KeyVals;

public class Util {

	public static final int nonExist = Integer.MIN_VALUE;
	public static final int seed4poisoning = 12345;

	public static int getB(boolean isHigh, int n, int d, double mu, double alpha, double beta, ENCRYPTION_MODE mode) {
		int tau1 = EncryptionUtil.getSize(mode, 1);
		int tau2 = EncryptionUtil.getSize(mode, 2);
		int tau3 = EncryptionUtil.getSize(mode, 3);
		if (isHigh) {
			double t1 = (double) tau1 * (mu + 1.0) * beta * (1 - alpha) * n * d;
			double t2 = (2.0 * tau1 + tau2 + tau3) * mu;
			int b = (int) Math.sqrt(t1 / t2);
			return b;
		} else {
			int l = Util.getL(false, n, d, beta);
			double t1 = (double) tau1 * (mu + 1.0) * l * d;
			double t2 = (2.0 * tau1 + tau2 + tau3) * mu;
			int b = (int) Math.sqrt(t1 / t2);
			return b;
		}
	}

	public static float[] significance_threshold(float est_org[], int n, double variance_i, double alpha,
			int targetNum) {

		NormalDistribution nd = new NormalDistribution();
		int domain_size = est_org.length;

		double estn[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			estn[i] = est_org[i] * n;
		}

		double std = Math.sqrt(variance_i);
		double threshold = nd.inverseCumulativeProbability(1 - alpha / targetNum) * std;
		for (int k = 0; k < domain_size; k++) {

			if (estn[k] < threshold) {
				estn[k] = 0;
			}

		}

		double sum = 0;

		sum = 0;
		for (double es : estn) {
			sum += es;
		}

		if (sum == 0) {
			for (int k = 0; k < estn.length; k++) {
				estn[k] = n / domain_size;
			}
		}

		float result[] = new float[domain_size];
		for (int i = 0; i < domain_size; i++) {
			result[i] = (float) (estn[i] / n);
		}

		return result;

	}

	public static void truncateSortedResults(float[] results, int n) {
		int length = results.length;
		if (n >= length) {
			return;
		}
		Integer[] indices = new Integer[length];
		for (int i = 0; i < length; i++) {
			indices[i] = i;
		}

		Arrays.sort(indices, Comparator.comparing((Integer i) -> results[i]).reversed());

		for (int i = n + 1; i < length; i++) {
			results[indices[i]] = 0.0f;
		}
	}

	public static double getMga(double estimatedDistributionWithoutFakes[], double estimatedDistributionWithFakes[],
			Set<Integer> poisoningTargetAttributes) {
		double mga = 0.0;
		for (int targetAtt : poisoningTargetAttributes) {
			mga += (estimatedDistributionWithFakes[targetAtt] - estimatedDistributionWithoutFakes[targetAtt]);

		}
		return mga;
	}

	public static double getMga(double estimatedDistributionWithoutFakes[], double estimatedDistributionWithFakes[],
			List<Integer> poisoningTargetAttributes) {
		double mga = 0.0;
		for (int targetAtt : poisoningTargetAttributes) {
			mga += (estimatedDistributionWithFakes[targetAtt] - estimatedDistributionWithoutFakes[targetAtt]);

		}
		return mga;
	}

	public static double getMga(float estimatedDistributionWithoutFakes[], float estimatedDistributionWithFakes[],
			List<Integer> poisoningTargetAttributes) {
		double mga = 0.0;
		for (int targetAtt : poisoningTargetAttributes) {
			mga += (estimatedDistributionWithFakes[targetAtt] - estimatedDistributionWithoutFakes[targetAtt]);

		}
		return mga;
	}

	public static double getNormalizedValue(double val, double min, double max) {
		double normalizedValue = 2 * (val - min) / (max - min) - 1;
		return normalizedValue;
	}

	public static double getL(List<HashMap<Integer, Double>> keyVals, double percentile) {
		int nums[] = new int[keyVals.size()];
		for (int i = 0; i < keyVals.size(); i++) {
			nums[i] = keyVals.get(i).size();
		}

		Arrays.sort(nums);

		double index = (percentile / 100.0) * (nums.length - 1);
		int lowerIndex = (int) Math.floor(index);
		int upperIndex = (int) Math.ceil(index);

		if (lowerIndex == upperIndex) {
			return nums[lowerIndex];
		}

		double fraction = index - lowerIndex;
		return nums[lowerIndex] + fraction * (nums[upperIndex] - nums[lowerIndex]);

	}

	public static int getKeyNum(List<HashMap<Integer, Double>> keyVals) {
		int keyNum = 0;
		for (HashMap<Integer, Double> keyVal : keyVals) {
			for (int key : keyVal.keySet()) {
				if (key > keyNum) {
					keyNum = key;
				}
			}
		}

		keyNum += 1;
		return keyNum;
	}

	public static KeyVals getOrgKeyVals(KeyValueDataConfig data) throws IOException {
		String fileName = "dataset/" + data.name() + ".txt";
		TreeSet<String> userSet = new TreeSet<String>();
		TreeSet<String> keySet = new TreeSet<String>();
		double maxValue = -Double.MAX_VALUE;
		double minValue = Double.MAX_VALUE;

		BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));

		String line = "";
		while ((line = br.readLine()) != null) {
			String ss[] = line.split("\t");
			userSet.add(ss[0]);

			for (int i = 1; i < ss.length; i += 2) {
				keySet.add(ss[i]);
				double val = Double.parseDouble(ss[i + 1]);
				if (maxValue < val) {
					maxValue = val;
				}
				if (minValue > val) {
					minValue = val;
				}
			}
		}
		br.close();

		HashMap<String, Integer> userIdMap = new HashMap<String, Integer>();
		HashMap<String, Integer> keyIdMap = new HashMap<String, Integer>();
		int newId = 0;
		for (String s : userSet) {
			userIdMap.put(s, newId++);
		}
		newId = 0;
		for (String s : keySet) {
			keyIdMap.put(s, newId++);
		}

		int userNum = userSet.size();

		List<HashMap<Integer, Double>> keyVals = new ArrayList<HashMap<Integer, Double>>();
		for (int i = 0; i < userNum; i++) {
			keyVals.add(new HashMap<Integer, Double>());
		}

		br = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));
		while ((line = br.readLine()) != null) {
			String ss[] = line.split("\t");

			String userId = ss[0];
			for (int i = 1; i < ss.length; i += 2) {
				keyVals.get(userIdMap.get(userId)).put(keyIdMap.get(ss[i]),
						getNormalizedValue(Double.parseDouble(ss[i + 1]), minValue, maxValue));
			}

		}

		br.close();

		KeyVals keyValsClass = new KeyVals(keyVals, keyIdMap.size());

		return keyValsClass;

	}

	public static int[] getOrgVals(CategoricalDataConfig data) {
		String fileName = "dataset/" + data.name() + ".txt";
		int vals[] = null;
		try {
			TreeSet<String> set = new TreeSet<String>();
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));
			int count = 0;
			String line = "";
			while ((line = br.readLine()) != null) {
				count++;
				set.add(line);
			}
			br.close();

			int newId = 0;
			HashMap<String, Integer> map = new HashMap<String, Integer>();
			for (String val : set) {
				map.put(val, newId++);
			}

			vals = new int[count];
			br = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));
			count = 0;
			while ((line = br.readLine()) != null) {
				vals[count++] = map.get(line);
			}

			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return vals;
	}

	public static List<Integer> getRandomElements(int size, int targetNum, Random rand) {
		List<Integer> numbers = new ArrayList<>();
		for (int i = 0; i < size; i++) {
			numbers.add(i);
		}

		Collections.shuffle(numbers, rand);

		return new ArrayList<>(numbers.subList(0, targetNum));
	}

	public static double getMse(double originalFrequency[], float expectedFrequency[]) {
		int categoryNum = originalFrequency.length;
		double error = 0.0;
		for (int i = 0; i < categoryNum; i++) {
			if (Double.isNaN(originalFrequency[i])) {
				continue;
			}
			error += Math.pow(originalFrequency[i] - expectedFrequency[i], 2);
		}
		return error;
	}

	public static double getMse(float originalFrequency[], float expectedFrequency[]) {
		int categoryNum = originalFrequency.length;
		double error = 0.0;
		for (int i = 0; i < categoryNum; i++) {
			if (Double.isNaN(originalFrequency[i])) {
				continue;
			}
			error += Math.pow(originalFrequency[i] - expectedFrequency[i], 2);
		}
		return error;
	}

	public static double getMse(double originalFrequency[], double expectedFrequency[]) {
		int categoryNum = originalFrequency.length;
		double error = 0.0;
		for (int i = 0; i < categoryNum; i++) {
			if (Double.isNaN(originalFrequency[i])) {
				continue;
			}
			error += Math.pow(originalFrequency[i] - expectedFrequency[i], 2);
		}
		return error;
	}

	public static double getMse(double[] f1, double[] f2, double g[], int K) {
		if (f1.length != f2.length || f1.length != g.length) {
			throw new IllegalArgumentException("SHould be the same length.");
		}

		int d = g.length;
		Integer[] indices = new Integer[d];
		for (int i = 0; i < d; i++) {
			indices[i] = i;
		}

		Arrays.sort(indices, (i, j) -> Double.compare(g[j], g[i]));

		double sum = 0.0;
		for (int i = 0; i < K && i < d; i++) {
			if (Double.isNaN(f1[i])) {
				continue;
			}
			int idx = indices[i];
			double diff = f1[idx] - f2[idx];
			sum += diff * diff;
		}

		return sum;
	}

	public static double getMse(double[] f1, float[] f2, double g[], int K) {
		if (f1.length != f2.length || f1.length != g.length) {
			throw new IllegalArgumentException("SHould be the same length.");
		}

		int d = g.length;
		Integer[] indices = new Integer[d];
		for (int i = 0; i < d; i++) {
			indices[i] = i;
		}

		Arrays.sort(indices, (i, j) -> Double.compare(g[j], g[i]));

		double sum = 0.0;
		for (int i = 0; i < K && i < d; i++) {
			if (Double.isNaN(f1[i])) {
				continue;
			}
			int idx = indices[i];
			double diff = f1[idx] - f2[idx];
			sum += diff * diff;
		}

		return sum;
	}

	public static double getMse(float[] f1, float[] f2, float g[], int K) {
		if (f1.length != f2.length || f1.length != g.length) {
			throw new IllegalArgumentException("SHould be the same length.");
		}

		int d = g.length;
		Integer[] indices = new Integer[d];
		for (int i = 0; i < d; i++) {
			indices[i] = i;
		}

		Arrays.sort(indices, (i, j) -> Double.compare(g[j], g[i]));

		double test1[] = new double[K];
		double test2[] = new double[K];

		double sum = 0.0;
		for (int i = 0; i < K && i < d; i++) {
			int idx = indices[i];
			double diff = f1[idx] - f2[idx];
			sum += diff * diff;

			test1[i] = f1[idx];
			test2[i] = f2[idx];
		}

		return sum;
	}

	public static double[] getOrgFrequency(List<HashMap<Integer, Double>> keyVals, int d) {

		double[] originalFrequency = new double[d];

		for (HashMap<Integer, Double> map : keyVals) {
			for (int id : map.keySet()) {
				originalFrequency[id]++;
			}
		}

		int n = keyVals.size();
		for (int i = 0; i < d; i++) {
			originalFrequency[i] /= n;
		}

		return originalFrequency;
	}

	public static double[] getOrgFrequency(LNFUser users[], int d) {
		double[] originalFrequency = new double[d];
		for (LNFUser user : users) {
			originalFrequency[user.getOriginalValue()]++;
		}
		for (int i = 0; i < d; i++) {
			originalFrequency[i] /= users.length;
		}
		return originalFrequency;
	}

	public static float[] getOrgFrequencyFloat(LNFUser users[], int d) {
		float[] originalFrequency = new float[d];
		for (LNFUser user : users) {
			originalFrequency[user.getOriginalValue()]++;
		}
		for (int i = 0; i < d; i++) {
			originalFrequency[i] /= users.length;
		}
		return originalFrequency;
	}

	public static float[] getOrgFrequencyFloat(int data[], int d) {
		float[] originalFrequency = new float[d];
		for (int v : data) {
			originalFrequency[v]++;
		}
		for (int i = 0; i < d; i++) {
			originalFrequency[i] /= data.length;
		}
		return originalFrequency;
	}

	public static int[] getTopIndices(int[] frequency, int l) {
		int n = frequency.length;

		Integer[] indices = new Integer[n];
		for (int i = 0; i < n; i++) {
			indices[i] = i;
		}

		Arrays.sort(indices, (a, b) -> {
			if (frequency[b] != frequency[a]) {
				return Integer.compare(frequency[b], frequency[a]);
			}
			return Integer.compare(a, b);
		});

		int[] topIndices = new int[Math.min(l, n)];
		for (int i = 0; i < topIndices.length; i++) {
			topIndices[i] = indices[i];
		}

		return topIndices;
	}

	public static int[] getTopIndices(double[] frequency, int l) {
		int n = frequency.length;

		Integer[] indices = new Integer[n];
		for (int i = 0; i < n; i++) {
			indices[i] = i;
		}

		Arrays.sort(indices, (a, b) -> {
			if (frequency[b] != frequency[a]) {
				return Double.compare(frequency[b], frequency[a]);
			}
			return Integer.compare(a, b);
		});

		int[] topIndices = new int[Math.min(l, n)];
		for (int i = 0; i < topIndices.length; i++) {
			topIndices[i] = indices[i];
		}

		return topIndices;
	}

	public static double[] getTopKfrequency(float frequency[], int realFrequency[], int k) {
		int[] topIndices = getTopIndices(realFrequency, k);
		double results[] = new double[k];
		int count = 0;
		for (int topIndex : topIndices) {
			results[count++] = frequency[topIndex];
		}
		return results;
	}

	public static int[] getTopKfrequency(int frequency[], int k) {
		int[] topIndices = getTopIndices(frequency, k);
		int results[] = new int[k];
		int count = 0;
		for (int topIndex : topIndices) {
			results[count++] = frequency[topIndex];
		}
		return results;
	}

	public static double[] getOrgMean(List<HashMap<Integer, Double>> keyVals, int d, int orgD) {
		int counts[] = new int[d];
		double means[] = new double[d];
		for (Map<Integer, Double> maps : keyVals) {
			for (Map.Entry<Integer, Double> map : maps.entrySet()) {
				int key = map.getKey();
				double value = map.getValue();
				counts[key]++;
				means[key] += value;
			}
		}

		for (int i = 0; i < orgD; i++) {
			means[i] /= counts[i];
		}
		for (int i = orgD; i < d; i++) {
			means[i] = Double.NaN;
		}
		return means;
	}

	public static double cap(double data, double min, double max) {
		double val = Math.max(data, min);
		val = Math.min(val, max);

		return val;
	}

	public static void cap(double[] data, double min, double max) {
		for (int i = 0; i < data.length; i++) {
			double val = Math.max(data[i], min);
			val = Math.min(val, max);
			data[i] = val;
		}
	}

	public static void cap(float[] data, int min, int max) {
		for (int i = 0; i < data.length; i++) {
			float val = Math.max(data[i], min);
			val = Math.min(val, max);
			data[i] = val;
		}
	}

	public static int getKeyValueId(int key, int value, int d) {
		int s = (int) (key + 0.5 * (value + 1) * d);
		return s;
	}

	public static Map.Entry<Integer, Integer> getMap(int id, int d) {
		int key = id % d;
		int value = 0;
		if (id < d) {
			value = -1;
		} else {
			value = 1;
		}
		Map.Entry<Integer, Integer> entry = new AbstractMap.SimpleEntry<>(key, value);
		return entry;
	}

	public static int getL(boolean b, int n, int d, double beta) {
		double temp = (double) n * n / d;
		temp = Math.max(temp, 50);
		return (int) temp;
	}

	public static List<HashMap<Integer, Double>> sampling(List<HashMap<Integer, Double>> keyVals, double sampling,
			Random rand) {
		List<HashMap<Integer, Double>> result = new ArrayList<>();

		for (HashMap<Integer, Double> map : keyVals) {
			if (rand.nextDouble() < sampling) {
				result.add(map);
			}
		}

		return result;
	}

	public static double getDoubleArg(String[] args, int index, double defaultValue) {
		if (args.length > index) {
			return Double.parseDouble(args[index]);
		}
		return defaultValue;
	}

	public static Integer getIntArg(String[] args, int index, Integer defaultValue) {
		if (args.length > index) {
			return Integer.parseInt(args[index]);
		}
		return defaultValue;
	}

	public static boolean getBooleanArg(String[] args, int index, boolean defaultValue) {
		if (args.length > index) {
			return Boolean.parseBoolean(args[index]);
		}
		return defaultValue;
	}

}
