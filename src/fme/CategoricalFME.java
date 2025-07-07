package fme;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashSet;

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

		try {
			targetDataName = args[0];
			epsilon = Util.getDoubleArg(args, 1, 1.0);
			delta = Util.getDoubleArg(args, 2, 1E-12);
			alpha = Util.getDoubleArg(args, 3, 0.05);
			beta = Util.getDoubleArg(args, 4, 1.0);
			topK = Util.getIntArg(args, 5, 50);
			encryption = args.length > 6 ? ENCRYPTION_MODE.valueOf(args[6].toUpperCase()) : ENCRYPTION_MODE.RSA;
			isLargeL = Util.getBooleanArg(args, 7, true);
		} catch (Exception e) {
			String osName = System.getProperty("os.name").toLowerCase();
			String cpSeparator = osName.contains("win") ? ";" : ":";

			System.err.println("Usage: java -cp \"lib/*" + cpSeparator
					+ "bin\" fme.CategoricalFME <targetDataName> <epsilon> <delta> <alpha> <beta> <topK> <encryption_mode> <isLargeL>");
			System.err.println("Example: java -cp \"lib/*" + cpSeparator
					+ "bin\" fme.CategoricalFME foursquare 1.0 1E-12 0.05 1.0 50 RSA true");
			return;
		}

		execute(CategoricalDataConfig.valueOf(targetDataName), epsilon, delta, alpha, beta, topK, encryption, isLargeL);

	}

	public static void execute(CategoricalDataConfig data, double epsilon, double delta, double alpha, double beta,
			int topK, ENCRYPTION_MODE encryption, boolean isLargeL)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		int orgData[] = Util.getOrgVals(data);
		int n = data.getN();
		int d = data.getD();

		SAGeoDataCollector dataCollector = new SAGeoDataCollector(epsilon / 2, delta / 2, d, n, alpha);

		int b = -1;
		int l = -1;

		if (isLargeL) {
			b = Util.getB(true, n, d, dataCollector.getDistribution().getMu(), alpha, beta, encryption);
			l = b;
		} else {
			l = Util.getL(false, n, d, beta);
			b = Util.getB(false, n, d, dataCollector.getDistribution().getMu(), alpha, beta, encryption);
		}

		HashFunction hashFunction = new HashFunction(d, b);
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
		shuffler.sampleAndAddFakeValues();

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
		System.out.println(mse / topK);
	}

}
