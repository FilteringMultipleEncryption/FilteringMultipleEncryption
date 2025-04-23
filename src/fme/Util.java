package fme;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.math3.distribution.NormalDistribution;

import encryption.ENCRYPTION_MODE;
import encryption.EncryptionUtil;
import util.KeyVals;

public class Util {

	public static final int nonExist = Integer.MIN_VALUE;
	public static final int seed4poisoning = 12345;

	public static void form1toform2(String inputFileName, String outputFileName) throws IOException {
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputFileName)));
		BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(inputFileName)));
		String line = "";
		while ((line = br.readLine()) != null) {
			String ss[] = line.split("\t");
			String userId = ss[0];
			for (int i = 1; i < ss.length; i += 2) {
				String productId = ss[i];
				String value = ss[i + 1];
				bw.write(userId + "\t" + productId + "\t" + value);
				bw.newLine();
			}
		}

		br.close();
		bw.close();
	}

	public static void multiple(double frequency[], double ratio) {
		for (int i = 0; i < frequency.length; i++) {
			frequency[i] *= ratio;
		}
	}

	public static void multiple(float frequency[], double ratio) {
		for (int i = 0; i < frequency.length; i++) {
			frequency[i] *= ratio;
		}
	}

	public static int getCategoryNum(int data[]) {
		HashSet<Integer> set = new HashSet<Integer>();
		for (int d : data) {
			set.add(d);
		}
		int categoryNum = set.size();
		return categoryNum;
	}

	public static double[] significance_threshold(double est_org[], int n, double estimated_l2_loss) {

		NormalDistribution nd = new NormalDistribution();
		double alpha = 0.05;
		int domain_size = est_org.length;

		double estn[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			estn[i] = est_org[i] * n;
		}

		double variance_i = estimated_l2_loss * n * n / domain_size;

		int zeroCount = 0;
		double std = Math.sqrt(variance_i);
		double threshold = nd.inverseCumulativeProbability(1 - alpha / domain_size) * std;
		for (int k = 0; k < domain_size; k++) {
			if (estn[k] < threshold) {
				zeroCount++;
				estn[k] = 0;
			}
		}

		double sum = 0;
		for (int k = 0; k < domain_size; k++) {
			sum += estn[k];
		}

		if (sum < n) {
			for (int k = 0; k < domain_size; k++) {
				if (estn[k] == 0) {
					estn[k] = (n - sum) / zeroCount;
				}
			}
		}

		sum = 0;
		for (double es : estn) {
			sum += es;
		}

		if (sum != 0) {
			for (int k = 0; k < domain_size; k++) {
				estn[k] = (estn[k] / sum) * n;
			}
		} else {
			for (int k = 0; k < estn.length; k++) {
				estn[k] = n / domain_size;
			}
		}

		double result[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			result[i] = estn[i] / n;
		}

		return result;

	}

	public static int getB(boolean isHigh, int n, int d, double mu, double alpha, double beta, ENCRYPTION_MODE mode) {
		int c1 = EncryptionUtil.getSize(mode, 1);
		int c2 = EncryptionUtil.getSize(mode, 2);
		int c3 = EncryptionUtil.getSize(mode, 3);
		if (isHigh) {
			double t1 = (double) c1 * (mu + 1.0) * beta * (1 - alpha) * n * d;
			double t2 = (2.0 * c1 + c2 + c3) * mu;
			int b = (int) Math.sqrt(t1 / t2);
			return b;
		} else {
			int l = Util.getL(false, n, d, beta);
			double t1 = (double) c1 * (mu + 1.0) * l * d;
			double t2 = (2.0 * c1 + c2 + c3) * mu;
			int b = (int) Math.sqrt(t1 / t2);
			return b;
		}
	}

	public static double[] significance_threshold2(double est_org[], int n, double estimated_l2_loss, boolean sumOne) {

		NormalDistribution nd = new NormalDistribution();
		double alpha = 0.05;
		int domain_size = est_org.length;

		double estn[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			estn[i] = est_org[i] * n;
		}

		double variance_i = estimated_l2_loss * n * n / domain_size;

		int zeroCount = 0;
		double std = Math.sqrt(variance_i);
		double threshold = nd.inverseCumulativeProbability(1 - alpha / domain_size) * std;
		for (int k = 0; k < domain_size; k++) {
			if (estn[k] < threshold) {
				zeroCount++;
				estn[k] = 0;
			}
		}

		double sum = 0;
		// for (int k = 0; k < domain_size; k++) {
		// sum += estn[k];
		// }
		//
		// if (sum < n) {
		// for (int k = 0; k < domain_size; k++) {
		// if (estn[k] == 0) {
		// // estn[k] = (n - sum) / zeroCount;
		// }
		// }
		// }
		//
		sum = 0;
		for (double es : estn) {
			sum += es;
		}
		//
		// if (sum != 0) {
		// for (int k = 0; k < domain_size; k++) {
		// // estn[k] = (estn[k] / sum) * n;
		// if (estn[k] != 0) {
		// estn[k] += (org_sum * n - sum) / (domain_size - zeroCount);
		// }
		// }
		//
		// } else {
		// for (int k = 0; k < estn.length; k++) {
		// estn[k] = org_sum * n / domain_size;
		// }
		// }

		if (sum != 0) {
			if (sumOne) {
				if (sum > n) {
					for (int k = 0; k < domain_size; k++) {
						// estn[k] = (estn[k] / sum) * n;
						// if (estn[k] != 0) {
						// estn[k] += (org_sum * n - sum) / (domain_size - zeroCount);
						// }
					}
				}
			}
		} else {
			for (int k = 0; k < estn.length; k++) {
				estn[k] = n / domain_size;
			}
		}

		double result[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			result[i] = estn[i] / n;
		}

		// for (int i = 0; i < domain_size; i++) {
		// if (result[i] < 0) {
		// result[i] = 0;
		// }
		// }
		//
		// sum = 0.0;
		// for (double r : result) {
		// sum += r;
		// }
		// for (int i = 0; i < domain_size; i++) {
		// if (result[i] != 0) {
		// result[i] = org_sum * result[i] / sum;
		// }
		// }

		return result;

	}

	public static float[] significance_threshold(float est_org[], int n, double estimated_l2_loss) {

		NormalDistribution nd = new NormalDistribution();
		double alpha = 0.05;
		int domain_size = est_org.length;

		double estn[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			estn[i] = est_org[i] * n;
		}

		double variance_i = estimated_l2_loss * n * n / domain_size;

		int zeroCount = 0;
		double std = Math.sqrt(variance_i);
		double threshold = nd.inverseCumulativeProbability(1 - alpha / domain_size) * std;
		for (int k = 0; k < domain_size; k++) {
			if (estn[k] < threshold) {
				zeroCount++;
				estn[k] = 0;
			}
		}

		double sum = 0;
		for (int k = 0; k < domain_size; k++) {
			sum += estn[k];
		}

		if (sum < n) {
			for (int k = 0; k < domain_size; k++) {
				if (estn[k] == 0) {
					estn[k] = (n - sum) / zeroCount;
				}
			}
		}

		sum = 0;
		for (double es : estn) {
			sum += es;
		}

		if (sum != 0) {
			for (int k = 0; k < domain_size; k++) {
				estn[k] = (estn[k] / sum) * n;
			}
		} else {
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

	public static float[] significance_threshold2(float est_org[], int n, double estimated_l2_loss, int target_size,
			double alpha, boolean sumOne) {

		NormalDistribution nd = new NormalDistribution();
		// double alpha = 0.1;
		int domain_size = est_org.length;

		double estn[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			estn[i] = est_org[i] * n;
		}

		double variance_i = estimated_l2_loss * n * n / domain_size;

		int zeroCount = 0;
		double std = Math.sqrt(variance_i);
		// double threshold = nd.inverseCumulativeProbability(1 - alpha / domain_size) *
		// std;
		double threshold = nd.inverseCumulativeProbability(1 - alpha / target_size) * std;
		for (int k = 0; k < domain_size; k++) {
			if (estn[k] < threshold) {
				zeroCount++;
				estn[k] = 0;

			}
		}

		double sum = 0;
		// for (int k = 0; k < domain_size; k++) {
		// sum += estn[k];
		// }
		//
		// if (sum < n) {
		// for (int k = 0; k < domain_size; k++) {
		// if (estn[k] == 0) {
		// // estn[k] = (n - sum) / zeroCount;
		// }
		// }
		// }
		//
		sum = 0;
		for (double es : estn) {
			sum += es;
		}
		//
		// if (sum != 0) {
		// for (int k = 0; k < domain_size; k++) {
		// // estn[k] = (estn[k] / sum) * n;
		// if (estn[k] != 0) {
		// estn[k] += (n - sum) / (domain_size - zeroCount);
		// }
		// }
		// } else {
		// for (int k = 0; k < estn.length; k++) {
		// estn[k] = n / domain_size;
		// }
		// }

		if (sum != 0) {
			if (sumOne) {
				if (sum > n) {
					for (int k = 0; k < domain_size; k++) {
						estn[k] = (estn[k] / sum) * n;
						// if (estn[k] != 0) {
						// estn[k] += (org_sum * n - sum) / (domain_size - zeroCount);
						// }
					}
				}
			}
		} else {
			for (int k = 0; k < estn.length; k++) {
				estn[k] = n / domain_size;
			}
		}

		float result[] = new float[domain_size];
		for (int i = 0; i < domain_size; i++) {
			result[i] = (float) (estn[i] / n);
		}

		// for (int i = 0; i < domain_size; i++) {
		// if (result[i] < 0) {
		// result[i] = 0;
		// }
		// }
		// sum = 0.0;
		// for (double r : result) {
		// sum += r;
		// }
		// for (int i = 0; i < domain_size; i++) {
		// if (result[i] != 0) {
		// result[i] = (float) (result[i] / sum);
		// }
		// }

		return result;

	}

	public static float[] significance_threshold2(float est_org[], int n, double variance_i, double alpha,
			int targetNum, boolean sumOne) {

		NormalDistribution nd = new NormalDistribution();
		int domain_size = est_org.length;

		double estn[] = new double[domain_size];
		for (int i = 0; i < domain_size; i++) {
			estn[i] = est_org[i] * n;
		}

		int testCount = 0;
		int zeroCount = 0;
		double std = Math.sqrt(variance_i);
		double threshold = nd.inverseCumulativeProbability(1 - alpha / targetNum) * std;
		for (int k = 0; k < domain_size; k++) {
			if (estn[k] <= 0) {
				testCount++;
			}
			if (estn[k] < threshold) {
				zeroCount++;
				estn[k] = 0;
			}

		}

		double sum = 0;
		// for (int k = 0; k < domain_size; k++) {
		// sum += estn[k];
		// }
		//
		// if (sum < n) {
		// for (int k = 0; k < domain_size; k++) {
		// if (estn[k] == 0) {
		// // estn[k] = (n - sum) / zeroCount;
		// }
		// }
		// }

		sum = 0;
		for (double es : estn) {
			sum += es;
		}

		if (sum != 0) {
			if (sumOne) {
				if (sum > n) {
					for (int k = 0; k < domain_size; k++) {
						// estn[k] = (estn[k] / sum) * n;
						// if (estn[k] != 0) {
						// estn[k] += (n - sum) / (domain_size - zeroCount);
						// }
					}
				}
			}
		} else {
			for (int k = 0; k < estn.length; k++) {
				estn[k] = n / domain_size;
			}
		}

		float result[] = new float[domain_size];
		for (int i = 0; i < domain_size; i++) {
			result[i] = (float) (estn[i] / n);
		}

		// truncateSortedResults(result, n);

		// for (int i = 0; i < domain_size; i++) {
		// if (result[i] < 0) {
		// result[i] = 0;
		// }
		// }
		// sum = 0.0;
		// for (double r : result) {
		// sum += r;
		// }
		// for (int i = 0; i < domain_size; i++) {
		// if (result[i] != 0) {
		// result[i] = (float) (org_sum * result[i] / sum);
		// }
		// }

		return result;

	}

	public static void truncateSortedResults(float[] results, int n) {
		int length = results.length;
		if (n >= length) {
			return;
		}
		// インデックス配列を作成
		Integer[] indices = new Integer[length];
		for (int i = 0; i < length; i++) {
			indices[i] = i;
		}

		// インデックスを元に降順ソート
		Arrays.sort(indices, Comparator.comparing((Integer i) -> results[i]).reversed());

		// 上位 n+1 番目以降を 0 にする
		for (int i = n + 1; i < length; i++) {
			results[indices[i]] = 0.0f;
		}
	}

	// public static double[] significance_threshold2(double est_org[], int n,
	// double estimated_l2_loss, int target_size,
	// double alpha) {
	//
	// NormalDistribution nd = new NormalDistribution();
	// // double alpha = 0.1;
	// int domain_size = est_org.length;
	//
	// double estn[] = new double[domain_size];
	// for (int i = 0; i < domain_size; i++) {
	// estn[i] = est_org[i] * n;
	// }
	//
	// double variance_i = estimated_l2_loss * n * n / domain_size;
	//
	// int zeroCount = 0;
	// double std = Math.sqrt(variance_i);
	// double threshold = nd.inverseCumulativeProbability(1 - alpha / target_size) *
	// std;
	// for (int k = 0; k < domain_size; k++) {
	// if (estn[k] < threshold) {
	// zeroCount++;
	// estn[k] = 0;
	//
	// }
	// }
	//
	// double sum = 0;
	// for (int k = 0; k < domain_size; k++) {
	// sum += estn[k];
	// }
	//
	// if (sum < n) {
	// for (int k = 0; k < domain_size; k++) {
	// if (estn[k] == 0) {
	// // estn[k] = (n - sum) / zeroCount;
	// }
	// }
	// }
	//
	// sum = 0;
	// for (double es : estn) {
	// sum += es;
	// }
	//
	// if (sum != 0) {
	// for (int k = 0; k < domain_size; k++) {
	// // estn[k] = (estn[k] / sum) * n;
	// if (estn[k] != 0) {
	// estn[k] += (n - sum) / (domain_size - zeroCount);
	// }
	// }
	// } else {
	// for (int k = 0; k < estn.length; k++) {
	// estn[k] = n / domain_size;
	// }
	// }
	//
	// double result[] = new double[domain_size];
	// for (int i = 0; i < domain_size; i++) {
	// result[i] = estn[i] / n;
	// }
	//
	// for (int i = 0; i < domain_size; i++) {
	// if (result[i] < 0) {
	// result[i] = 0;
	// }
	// }
	// sum = 0.0;
	// for (double r : result) {
	// sum += r;
	// }
	// for (int i = 0; i < domain_size; i++) {
	// if (result[i] != 0) {
	// result[i] = result[i] / sum;
	// }
	// }
	//
	// return result;
	//
	// }

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

	public static double[] normalization(double histogram[]) {
		int categoryNum = histogram.length;
		double min = Double.MAX_VALUE;
		for (double v : histogram) {
			if (v < min) {
				min = v;
			}
		}

		double sum = 0.0;
		for (int i = 0; i < categoryNum; i++) {
			sum += histogram[i] - min;
		}

		double histogram2[] = new double[categoryNum];
		for (int i = 0; i < categoryNum; i++) {
			if (sum != 0) {
				histogram2[i] = (histogram[i] - min) / sum;
			} else {
				histogram2[i] = histogram[i];
			}
		}
		return histogram2;
	}

	public static float[] normalization(float histogram[]) {
		int categoryNum = histogram.length;
		double min = Double.MAX_VALUE;
		for (double v : histogram) {
			if (v < min) {
				min = v;
			}
		}

		double sum = 0.0;
		for (int i = 0; i < categoryNum; i++) {
			sum += histogram[i] - min;
		}

		float histogram2[] = new float[categoryNum];
		for (int i = 0; i < categoryNum; i++) {
			if (sum != 0) {
				histogram2[i] = (float) ((histogram[i] - min) / sum);
			} else {
				histogram2[i] = histogram[i];
			}
		}
		return histogram2;
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

	public static KeyVals getOrgKeyVals(String dataName) throws IOException {
		String fileName = "dataset/" + dataName + ".txt";
		TreeSet<String> userSet = new TreeSet<String>();
		TreeSet<String> keySet = new TreeSet<String>();
		double maxValue = -Double.MAX_VALUE;
		double minValue = Double.MAX_VALUE;

		int testTransactionCount = 0;

		BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));

		double sum = 0;
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
				testTransactionCount++;
				sum += Double.parseDouble(ss[i + 1]);
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

	public static int[] getOrgVals(String dataName) {
		String fileName = "dataset/" + dataName + ".txt";
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

	// public static List<Integer> getRandomElements(int size, int targetNum) {
	// List<Integer> numbers = new ArrayList<>();
	// for (int i = 0; i < size; i++) {
	// numbers.add(i);
	// }
	//
	// Collections.shuffle(numbers);
	// List<Integer> list = new ArrayList<>(numbers.subList(0, targetNum));
	// return list;
	// }

	public static List<Integer> getRandomElements(int size, int targetNum, long seed) {
		List<Integer> numbers = new ArrayList<>();
		for (int i = 0; i < size; i++) {
			numbers.add(i);
		}

		Random random = new Random(seed);
		Collections.shuffle(numbers, random);

		return new ArrayList<>(numbers.subList(0, targetNum));
	}

	public static double getMSE(double originalFrequency[], float expectedFrequency[]) {
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

	public static double getMSE(float originalFrequency[], float expectedFrequency[]) {
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

	public static double getMSE(double originalFrequency[], double expectedFrequency[]) {
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

	public static double getMAE(float originalFrequency[], float expectedFrequency[]) {
		int categoryNum = originalFrequency.length;
		double error = 0.0;
		for (int i = 0; i < categoryNum; i++) {
			if (Double.isNaN(originalFrequency[i])) {
				continue;
			}
			error += Math.abs(originalFrequency[i] - expectedFrequency[i]);
		}
		return error;
	}

	public static double getMAE(double originalFrequency[], double expectedFrequency[]) {
		int categoryNum = originalFrequency.length;
		double error = 0.0;
		for (int i = 0; i < categoryNum; i++) {
			if (Double.isNaN(originalFrequency[i])) {
				continue;
			}
			error += Math.abs(originalFrequency[i] - expectedFrequency[i]);
		}
		return error;
	}

	public static double[] getOrgFrequency_OLD(List<HashMap<Integer, Double>> keyVals, int d) {

		double[] originalFrequency = new double[d];
		int transactionNum = 0;

		for (HashMap<Integer, Double> map : keyVals) {
			for (int id : map.keySet()) {
				originalFrequency[id]++;
				transactionNum++;
			}
		}

		for (int i = 0; i < d; i++) {
			originalFrequency[i] /= transactionNum;
		}

		return originalFrequency;
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

	/**
	 * @param values
	 * @return
	 */
	public static long getByteSize(ArrayList<byte[]> values) {
		long size = 0;
		for (byte[] v : values) {
			size += v.length;
		}
		return size;
	}

	/**
	 * Returns the indices of the top `l` elements in the `frequency` array. The indices are sorted in descending order of their corresponding values in `frequency`. If two elements have the same
	 * frequency, the indices are sorted in ascending order.
	 *
	 * @param frequency The array of frequency values.
	 * @param l         The number of top elements to retrieve.
	 * @return An array containing the indices of the top `l` elements.
	 */
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

	/**
	 * Returns the top `k` frequency values from the `frequency` array based on the indices of the top `k` elements in the `realFrequency` array.
	 *
	 * @param frequency     The array of frequency values (e.g., floating-point values).
	 * @param realFrequency The array of integer frequencies used for ranking.
	 * @param k             The number of top elements to retrieve.
	 * @return An array containing the top `k` frequency values.
	 */
	public static double[] getTopKfrequency(float frequency[], int realFrequency[], int k) {
		int[] topIndices = getTopIndices(realFrequency, k);
		double results[] = new double[k];
		int count = 0;
		for (int topIndex : topIndices) {
			results[count++] = frequency[topIndex];
		}
		return results;
	}

	/**
	 * Returns the top `k` frequency values from the `frequency` array. The values are determined based on their frequencies in the `frequency` array.
	 *
	 * @param frequency The array of integer frequency values.
	 * @param k         The number of top elements to retrieve.
	 * @return An array containing the top `k` frequency values.
	 */
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

	public static float[] getOrgFrequencyGroupHash(List<ArrayList<LFNUserGroupHash>> groupUsers, int d) {
		float[] originalFrequency = new float[d];
		int n = 0;
		for (ArrayList<LFNUserGroupHash> users : groupUsers) {
			for (LFNUserGroupHash user : users) {
				originalFrequency[user.getOriginalValue()]++;
				n++;
			}
		}
		for (int i = 0; i < d; i++) {
			originalFrequency[i] /= n;
		}
		return originalFrequency;
	}

	public static double getEstimatedLoss2OfCommonHash(double orgFrequency[], int n, int d, int b, double beta,
			double variance) {

		double sum = 0.0;
		for (int i = 0; i < d; i++) {
			double omega = 0.0;
			for (int j = 0; j < d; j++) {
				if (i == j) {
					continue;
				}
				omega += (double) n * n * orgFrequency[j] * orgFrequency[j] * beta * beta
						+ n * orgFrequency[j] * beta * (1 - beta) * (b - 1) / b / b
						+ n * orgFrequency[j] * beta * (1 - beta) / b / b;
			}

			sum += n * orgFrequency[i] * beta * (1 - beta) + variance + omega;
		}

		double l2loss = (double) b * b / n / n / beta / beta / Math.pow(b - 1, 2) + sum;
		return l2loss;
	}

	public static double getLambda(int n, int d, int l, int b, double alpha, double beta) {
		double Lambda = -1;
		if (beta * n <= l && l <= b) {
			Lambda = (beta * n + alpha * (l - beta * n)) * d / b;
		} else if (l <= beta * n) {
			Lambda = (double) l * d / b;
		} else {
			System.err.println("Undefined parameter");
		}
		return Lambda;
	}

	public static int getD(String dataName) {
		int categoryNum = -1;
		if (dataName.equals("foursquare_10")) {
			categoryNum = 10 * 10;
		} else if (dataName.equals("foursquare_100")) {
			categoryNum = 100 * 100;
		} else if (dataName.equals("foursquare_1000")) {
			categoryNum = 1000 * 1000;
		} else if (dataName.equals("foursquare_10000")) {
			categoryNum = 10000 * 10000;
		} else if (dataName.equals("aol_3_500000")) {
			categoryNum = (int) Math.pow(2, 24);
		} else if (dataName.equals("aol_3_10000")) {
			categoryNum = (int) Math.pow(2, 24);
		} else if (dataName.equals("foursquare_g")) {
			categoryNum = 10000;
		}
		return categoryNum;
	}

	public static int getKeyValueId(int key, int value, int d) {
		if (value == -1) {
			return key;
		} else {
			return d + key;
		}
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

	public static List<HashMap<Integer, Double>> sampling(List<HashMap<Integer, Double>> keyVals, double sampling) {
		List<HashMap<Integer, Double>> result = new ArrayList<>();
		Random rand = new Random();

		for (HashMap<Integer, Double> map : keyVals) {
			if (rand.nextDouble() < sampling) {
				result.add(map);
			}
		}

		return result;
	}

}
