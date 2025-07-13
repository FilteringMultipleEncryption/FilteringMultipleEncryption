package fme;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashSet;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import data.CategoricalDataConfig;
import encryption.ENCRYPTION_MODE;
import hash.HashFunction;
import sageo.SAGeoDataCollector;

public class CategoricalFME {
	public static void main(String args[])
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {

		String targetDataName = null;
		// default values
		double epsilon = 1.0;
		double delta = 1E-12;
		double alpha = 0.05;
		double beta = 1.0;
		int topK = 50;
		ENCRYPTION_MODE encryption = ENCRYPTION_MODE.RSA;
		boolean isLargeL = true;
		Integer seed = null;

		try {
			targetDataName = args[0];
			epsilon = Util.getDoubleArg(args, 1, epsilon);
			delta = Util.getDoubleArg(args, 2, delta);
			alpha = Util.getDoubleArg(args, 3, alpha);
			beta = Util.getDoubleArg(args, 4, beta);
			topK = Util.getIntArg(args, 5, topK);
			encryption = args.length > 6 ? ENCRYPTION_MODE.valueOf(args[6].toUpperCase()) : encryption;
			isLargeL = Util.getBooleanArg(args, 7, isLargeL);
			seed = Util.getIntArg(args, 8, seed);
		} catch (Exception e) {
			String osName = System.getProperty("os.name").toLowerCase();
			String cpSeparator = osName.contains("win") ? ";" : ":";

			System.err.println("Usage: java -cp \"lib/*" + cpSeparator
					+ "bin\" fme.CategoricalFME <targetDataName> <epsilon> <delta> <alpha> <beta> <topK> <encryption_mode> <isLargeL> <seed>");
			System.err.println("Example: java -cp \"lib/*" + cpSeparator
					+ "bin\" fme.CategoricalFME foursquare 1.0 1E-12 0.05 1.0 50 RSA true 12345");
			return;
		}

		execute(CategoricalDataConfig.valueOf(targetDataName), epsilon, delta, alpha, beta, topK, encryption, isLargeL,
				seed);

	}

	public static void execute(CategoricalDataConfig data, double epsilon, double delta, double alpha, double beta,
			int topK, ENCRYPTION_MODE encryption, boolean isLargeL, Integer seed1)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		Random rand = null;
		if (seed1 == null) {
			rand = new Random();
		} else {
			rand = new Random(seed1);
		}

		int orgData[] = Util.getOrgVals(data);
		int n = data.getN();
		int d = data.getD();

		SAGeoDataCollector dataCollector = new SAGeoDataCollector(epsilon / 2, delta / 2, d, n, alpha, rand);

		int b = -1;
		int l = -1;

		if (isLargeL) {
			b = Util.getB(true, n, d, dataCollector.getDistribution().getMu(), alpha, beta, encryption);
			l = b;
		} else {
			l = Util.getL(false, n, d, beta);
			b = Util.getB(false, n, d, dataCollector.getDistribution().getMu(), alpha, beta, encryption);
		}

		HashFunction hashFunction = new HashFunction(d, b, rand);
		dataCollector.setParameters(b, l, hashFunction);

		LNFUser users[] = new LNFUser[n];
		for (int i = 0; i < n; i++) {
			users[i] = new LNFUser(orgData[i], hashFunction);
		}

		dataCollector.setParameters(b, l, hashFunction);
		LNFShuffler shuffler = new LNFShuffler(d, dataCollector.getBeta(), dataCollector.getDistribution(), b,
				hashFunction);

		for (int i = 0; i < n; i++) {
			shuffler.receiveValue(users[i].getHashValue(), users[i].getOriginalValue());
		}
		shuffler.sampleAndAddFakeValues(rand);

		dataCollector.receives1(shuffler.getSampledHashValues(), shuffler.getSampledOrgValues());
		HashSet<Integer> filteringInfo = dataCollector.getFilteringInfo();

		shuffler.receiveValues2(dataCollector.getTurn2OrgValues());
		shuffler.addFakeValues(filteringInfo);
		dataCollector.receives2(shuffler.getTurn2Values());

		double sigma2 = dataCollector.getDistribution().getSigma2();
		float frequency[] = dataCollector.getFrequency();
		float frequency_thresholding[] = Util.significance_threshold(frequency, n, sigma2, alpha, d);

		float[] originalFrequency = Util.getOrgFrequencyFloat(orgData, d);

		double mse = Util.getMse(originalFrequency, frequency_thresholding, originalFrequency, topK);
		System.out.println("Frequency MSE: " + mse / topK);
	}

}
