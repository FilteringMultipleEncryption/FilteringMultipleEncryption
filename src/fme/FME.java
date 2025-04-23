package fme;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.ENCRYPTION_MODE;
import encryption.EncryptionUtil;
import hash.HashFunction;
import sageo.SAGeoDataCollector;
import util.KeyVals;

public class FME {
	public static void main(String args[])
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		// test();
		testKV();
	}

	public static void testKV()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String dataName = "ecommerce";
		double epsilon = 1.0;
		double delta = 1E-12;
		double alpha = 0.05;
		double beta = 1.0;
		boolean largeL = false;

		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		KeyPair keyPair = EncryptionUtil.getKeyPair(ENCRYPTION_MODE.RSA);
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();

		KeyVals keyValsClass = Util.getOrgKeyVals(dataName);
		List<HashMap<Integer, Double>> keyVals_temp = keyValsClass.getKeyVals();
		int orgD = keyValsClass.getAllKeyNum();
		int d = orgD;

		int kappa = (int) Math.ceil(Util.getL(keyVals_temp, 90));
		int dDash = d + kappa;

		List<HashMap<Integer, Double>> keyVals = Util.sampling(keyVals_temp, 0.05);
		int n = keyVals.size();

		SAGeoDataCollector dataCollector = new SAGeoDataCollector(epsilon / 2, delta / 2, d, n, privateKey, alpha);

		int b = -1;
		int l = -1;
		if (largeL) {
			b = Util.getB(true, n, 2 * dDash, dataCollector.getDistribution().getMu(), alpha, beta,
					ENCRYPTION_MODE.RSA);
			l = b;
		} else {
			l = Util.getL(false, n, 2 * dDash, beta);
			b = Util.getB(false, n, 2 * dDash, dataCollector.getDistribution().getMu(), alpha, beta,
					ENCRYPTION_MODE.RSA);
		}

		HashFunction hashFunction = new HashFunction(d, b);

		int counts[] = new int[b];
		int counts2[] = new int[2 * dDash];
		for (int i = 0; i < n; i++) {
			HashMap<Integer, Double> keyVal = keyVals.get(i);
			LNFUser user = new LNFUser(keyVal, hashFunction, kappa);
			user.keyValuePerturbation(d);
			counts[user.getHashValue()]++;
			counts2[user.getOriginalValue()]++;
		}
		dataCollector.setParameters(b, l, hashFunction);

		LNFShuffler shuffler = new LNFShuffler(2 * dDash, dataCollector.getBeta(), dataCollector.getDistribution(),
				publicKey, b, hashFunction);

		shuffler.addFakeValues(counts);
		dataCollector.receives1keyValue(counts, kappa);

		HashSet<Integer> filteringInfo = dataCollector.getFilteringInfo();

		for (int i = 0; i < 2 * dDash; i++) {
			if (!filteringInfo.contains(i)) {
				counts2[i] = 0;
			}
		}

		shuffler.addFakeValues(filteringInfo, counts2);
		dataCollector.receives2keyValue(counts2, kappa);

		float frequency[] = dataCollector.getFrequency();
		Util.cap(frequency, 0, 1);
		float mean[] = dataCollector.getMean(kappa, frequency);
		Util.cap(mean, -1, 1);

		double orgFrequency[] = Util.getOrgFrequency(keyVals_temp, d);
		double orgMean[] = Util.getOrgMean(keyVals_temp, d, orgD);

		double mseFrequency = Util.getMse(orgFrequency, frequency, orgFrequency, 50);
		double mseMean = Util.getMse(orgMean, mean, orgFrequency, 50);

		System.out.println(mseFrequency + ", " + mseMean);
	}

	public static void test()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		String dataName = "foursquare_1000";
		double epsilon = 1.0;
		double delta = 1E-12;
		double alpha = 0.05;
		double beta = 1.0;
		boolean largeL = false;
		int orgData[] = Util.getOrgVals(dataName);
		int n = orgData.length;
		int d = Util.getD(dataName);

		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		KeyPair keyPair = EncryptionUtil.getKeyPair(ENCRYPTION_MODE.RSA);
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();

		SAGeoDataCollector dataCollector = new SAGeoDataCollector(epsilon / 2, delta / 2, d, n, privateKey, alpha);

		int b = -1;
		int l = -1;

		if (largeL) {
			b = Util.getB(true, n, d, dataCollector.getDistribution().getMu(), alpha, beta, ENCRYPTION_MODE.RSA);
			l = b;
		} else {
			l = Util.getL(false, n, d, beta);
			b = Util.getB(false, n, d, dataCollector.getDistribution().getMu(), alpha, beta, ENCRYPTION_MODE.RSA);
		}

		HashFunction hashFunction = new HashFunction(d, b);
		dataCollector.setParameters(b, l, hashFunction);

		int hashValues[] = new int[d];
		for (int i = 0; i < d; i++) {
			hashValues[i] = hashFunction.calculateHash(i);
		}

		dataCollector.setParameters(b, l, hashFunction);

		LNFShuffler shuffler = new LNFShuffler(d, dataCollector.getBeta(), dataCollector.getDistribution(), publicKey,
				b, hashFunction);

		int counts[] = new int[b];

		for (int v : orgData) {
			if (Math.random() < beta) {
				counts[hashValues[v]]++;
			}
		}

		shuffler.addFakeValues(counts);
		dataCollector.receives1(counts);
		HashSet<Integer> filteringInfo = dataCollector.getFilteringInfo();

		counts = new int[d];
		for (int v : orgData) {
			if (filteringInfo.contains(v) && Math.random() < beta) {
				counts[v]++;
			}
		}

		shuffler.addFakeValues(filteringInfo, counts);
		dataCollector.receives2(counts);

		double sigma2 = dataCollector.getDistribution().getSigma2();
		float frequency[] = dataCollector.getFrequency();
		float frequency_thresholding[] = Util.significance_threshold2(frequency, n, sigma2, alpha, d, true);

		float[] originalFrequency = Util.getOrgFrequencyFloat(orgData, d);

		double mse = Util.getMSE(originalFrequency, frequency_thresholding);
		System.out.println(mse / d);
	}
}
