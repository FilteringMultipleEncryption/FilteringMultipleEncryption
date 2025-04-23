package sageo;

import java.security.PrivateKey;

import fme.LNFAbstractDataCollector;

public class SAGeoDataCollector extends LNFAbstractDataCollector {

	public SAGeoDataCollector(double epsilon, double delta, int d, int n, PrivateKey privateKey, double alpha) {
		super(epsilon, delta, d, n, privateKey, alpha);

		double ql = -1;
		double qr = -1;
		int nu = -1;
		double kappa = -1;
		double bestLoss = Double.MAX_VALUE;
		// double initial = SageoUtil.getBetaConstraint(epsilon);
		double initial = 1;
		double step = 0.000001;
		for (double tbeta = initial; tbeta < 1 + step; tbeta += step) {
			if (tbeta > 1) {
				tbeta = 1;
			}
			double tql = SageoUtil.getQl(epsilon, tbeta);
			double tqr = SageoUtil.getQr(epsilon, tbeta);
			int tnu = SageoUtil.getNu(epsilon, delta, tbeta, tql, tqr);
			double tkappa = SageoUtil.getKappa(tql, tqr, tnu);

			expectedError = SageoUtil.getExpectedError(n, d, tql, tqr, tbeta);
			if (expectedError < bestLoss) {
				bestLoss = expectedError;
				beta = tbeta;
				ql = tql;
				qr = tqr;
				nu = tnu;
				kappa = tkappa;
			}
		}

		expectedError = bestLoss;
		expectedApproximatedError = SageoUtil.getApproximatedExpectedError(epsilon, n, d, beta);
		mu = SageoUtil.getMu(nu, ql, qr, kappa);
		distribution = new SAGeoDummyDistribution(nu, kappa, ql, qr);

	}

	public SAGeoDataCollector(double epsilon, double delta, int d, int n, PrivateKey privateKey) {
		super(epsilon, delta, d, n, privateKey);

		double ql = -1;
		double qr = -1;
		int nu = -1;
		double kappa = -1;
		double bestLoss = Double.MAX_VALUE;
		// double initial = SageoUtil.getBetaConstraint(epsilon);
		double initial = 1;
		double step = 0.000001;
		for (double tbeta = initial; tbeta < 1 + step; tbeta += step) {
			if (tbeta > 1) {
				tbeta = 1;
			}
			double tql = SageoUtil.getQl(epsilon, tbeta);
			double tqr = SageoUtil.getQr(epsilon, tbeta);
			int tnu = SageoUtil.getNu(epsilon, delta, tbeta, tql, tqr);
			double tkappa = SageoUtil.getKappa(tql, tqr, tnu);

			expectedError = SageoUtil.getExpectedError(n, d, tql, tqr, tbeta);
			if (expectedError < bestLoss) {
				bestLoss = expectedError;
				beta = tbeta;
				ql = tql;
				qr = tqr;
				nu = tnu;
				kappa = tkappa;
			}
		}

		expectedError = bestLoss;
		expectedApproximatedError = SageoUtil.getApproximatedExpectedError(epsilon, n, d, beta);
		mu = SageoUtil.getMu(nu, ql, qr, kappa);
		distribution = new SAGeoDummyDistribution(nu, kappa, ql, qr);

	}

}
