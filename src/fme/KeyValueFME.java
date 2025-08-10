/* NOTE: The purpose of this code is to evaluate the MSE of the FME protocol.
Thus, this code does not implement multiple encryption or the communication between parties.*/
package fme;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import data.KeyValueDataConfig;
import encryption.ENCRYPTION_MODE;
import hash.HashFunction;
import sageo.SAGeoDataCollector;
import util.KeyVals;

public class KeyValueFME {
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
					+ "bin\" fme.KeyValueFME <targetDataName> <epsilon> <delta> <alpha> <beta> <topK> <encryption_mode> <isLargeL> <seed>");
			System.err.println("Example: java -cp \"lib/*" + cpSeparator
					+ "bin\" fme.KeyValueFME amazon 1.0 1E-12 0.05 1.0 50 RSA true 12345");
			return;
		}

		execute(KeyValueDataConfig.valueOf(targetDataName), epsilon, delta, alpha, beta, topK, encryption, isLargeL,
				seed);

	}

	public static void execute(KeyValueDataConfig data, double epsilon, double delta, double alpha, double beta,
			int topK, ENCRYPTION_MODE encryption, boolean isLargeL, Integer seed)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		Random rand = null;
		if (seed == null) {
			rand = new Random();
		} else {
			rand = new Random(seed);
		}

		KeyVals keyValsClass = Util.getOrgKeyVals(data);
		List<HashMap<Integer, Double>> keyVals_temp = keyValsClass.getKeyVals();
		int orgD = keyValsClass.getAllKeyNum();
		int d = orgD;

		int kappa = (int) Math.ceil(Util.getL(keyVals_temp, 90));
		int dDash = d + kappa;

		List<HashMap<Integer, Double>> keyVals = Util.sampling(keyVals_temp, 0.05, rand);
		int n = keyVals.size();

		SAGeoDataCollector dataCollector = new SAGeoDataCollector(epsilon / 2, delta / 2, d, n, alpha, rand);

		int b = -1;
		int l = -1;
		if (isLargeL) {
			b = Util.getB(true, n, dDash, dataCollector.getDistribution().getMu(), alpha, beta, encryption);
			l = b;
		} else {
			l = Util.getL(false, n, dDash, beta);
			b = Util.getB(false, n, dDash, dataCollector.getDistribution().getMu(), alpha, beta, encryption);
		}

		HashFunction hashFunction = new HashFunction(dDash, b, rand);

		LNFUser users[] = new LNFUser[n];

		for (int i = 0; i < n; i++) {
			HashMap<Integer, Double> keyVal = keyVals.get(i);
			LNFUser user = new LNFUser(keyVal, hashFunction, kappa);
			users[i] = user;
			/* Padding-and-Sampling (Section VII) */
			user.keyValuePerturbation(d, rand);
		}
		dataCollector.setParameters(b, l, hashFunction);

		LNFShuffler shuffler = new LNFShuffler(dDash, dataCollector.getBeta(), dataCollector.getDistribution(), b,
				hashFunction);

		/* Send hash values and input values (users -> shuffler) (Algorithm 1, l.1-3) */
		for (int i = 0; i < n; i++) {
			shuffler.receiveValue(users[i].getHashValue(), users[i].getOriginalValue());
		}

		/* Random sampling (Algorithm 1, l.4) */
		/* Dummy hash data addition (Algorithm 1, l.5-7) */
		shuffler.sampleAndAddFakeValues(rand);

		/* Random shuffling (Algorithm 1, l.8) */
		shuffler.shuffle(rand);

		/* Filtering (Algorithm 1, l.10-12) */
		/* TKV-FK (Section VII) */
		dataCollector.receives1keyValue(shuffler.getSampledHashValues(), shuffler.getSampledOrgValues(), kappa);
		HashSet<Integer> filteringInfo = dataCollector.getFilteringInfo();

		/* Send selected items and shuffled data (data collector -> shuffler) (Algorithm 1, l.18) */
		shuffler.receiveValues2(dataCollector.getTurn2OrgValues());

		/* Dummy input data addition (Algorithm 1, l.19-22) */
		shuffler.addFakeValues2(filteringInfo);

		/* Random shuffling (Algorithm 1, l.23) */
		shuffler.shuffle2(rand);

		/* Compute an unbiased estimate (Algorithm 1, l.25-29) */ /* Calculate unbiased estimates (Section VII) */
		dataCollector.receives2keyValue(shuffler.getTurn2Values(), kappa);

		float frequency[] = dataCollector.getFrequency();
		Util.cap(frequency, 0, 1);
		float mean[] = dataCollector.getMean(kappa, frequency);
		Util.cap(mean, -1, 1);

		double orgFrequency[] = Util.getOrgFrequency(keyVals_temp, d);
		double orgMean[] = Util.getOrgMean(keyVals_temp, d, orgD);

		double mseFrequency = Util.getMse(orgFrequency, frequency, orgFrequency, topK) / topK;
		double mseMean = Util.getMse(orgMean, mean, orgFrequency, topK) / topK;

		System.out.println("Frequency MSE: " + mseFrequency);
		System.out.println("Mean MSE: " + mseMean);
	}

}
