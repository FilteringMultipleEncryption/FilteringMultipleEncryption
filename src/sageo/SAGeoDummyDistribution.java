package sageo;

import java.util.Random;

import fme.LNFAbstractDummyDistribution;

public class SAGeoDummyDistribution extends LNFAbstractDummyDistribution {

	// The original domain of the PMF is [0, infinity), but it corresponds up to the
	// point where the CDF exceeds the targetCumulativeValue.
	private static double targetCumulativeValue = 0.999999999;
	private Random random;
	private double[] cumulativeProbabilities;

	public SAGeoDummyDistribution(int nu, double kappa, double ql, double qr, Random rand) {
		this.random = rand;
		int size = getSize(nu, ql, qr);
		cumulativeProbabilities = new double[size];
		double cumulativeProbability = 0.0;
		for (int k = 0; k < size; k++) {
			double probability = -1;
			if (k <= nu - 1) {
				probability = 1.0 / kappa * Math.pow(ql, nu - k);
			} else {
				probability = 1.0 / kappa * Math.pow(qr, k - nu);
			}
			cumulativeProbability += probability;
			cumulativeProbabilities[k] = cumulativeProbability;
		}

		for (int k = 0; k <= nu - 1; k++) {
			super.mu += k * Math.pow(ql, nu - k);
		}
		super.mu += (qr + (1 - qr) * nu) / Math.pow(1 - qr, 2);
		super.mu /= kappa;

		double kappaStar = ql / (1 - ql) + 1 / (1 - qr);
		super.sigma2 = (1 / kappaStar) * (ql * (1 + ql) / Math.pow(1 - ql, 3) + qr * (1 + qr) / Math.pow(1 - qr, 3));
	}

	@Override
	public int sample() {
		double r = random.nextDouble();
		for (int k = 0; k < cumulativeProbabilities.length; k++) {
			if (r <= cumulativeProbabilities[k]) {
				return k;
			}
		}
		return cumulativeProbabilities.length;
	}

	private static int getSize(double mu, double ql, double qr) {
		int result = (int) Math.ceil(-1 + mu
				+ Math.log(
						((1 + Math.pow(ql, 1 + mu) * (-1 + qr) - ql * qr) * (-1 + targetCumulativeValue)) / (-1 + ql))
						/ Math.log(qr));
		return result;
	}

	@Override
	protected int getZth(double alpha) {
		for (int i = 0; i < cumulativeProbabilities.length; i++) {
			if (cumulativeProbabilities[i] > 1 - alpha) {
				return i;
			}
		}
		return cumulativeProbabilities.length - 1;
	}

}
