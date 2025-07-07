package sageo;

public class SageoUtil {
	public static double getMu(int nu, double ql, double qr, double kappa) {
		double mu = 0.0;

		for (int k = 0; k <= nu - 1; k++) {
			mu += k * Math.pow(ql, nu - k);
		}
		mu += (qr + (1 - qr) * nu) / Math.pow(1 - qr, 2);
		mu /= kappa;

		return mu;
	}

	public static double getBetaConstraint(double epsilon) {
		double constraint = 1 - Math.exp(-epsilon / 2);
		return constraint;
	}

	public static double getQl(double epsilon, double beta) {
		double ql = (Math.exp(-epsilon / 2) - 1 + beta) / beta;
		return ql;
	}

	public static double getQr(double epsilon, double beta) {
		double qr = beta / (Math.exp(epsilon / 2) - 1 + beta);
		return qr;
	}

	public static int getNu(double epsilon, double delta, double beta, double ql, double qr) {
		double nu = Math
				.log((delta * (-1 + ql * qr))
						/ ((2 - 2 * (-1 + beta) * Math.exp(epsilon / 2) * (-1 + ql) + (-2 + delta) * ql) * (-1 + qr)))
				/ Math.log(ql);
		return (int) Math.ceil(nu);
	}

	public static double getKappa(double ql, double qr, int nu) {
		double kappa = ql * (1 - Math.pow(ql, nu)) / (1 - ql) + 1 / (1 - qr);
		return kappa;
	}

	public static double getExpectedError(int n, int d, double ql, double qr, double beta) {
		double error = (1.0 - beta) / (beta * n) + d / ((ql / (1.0 - ql) + 1.0 / (1 - qr)) * beta * beta * n * n)
				* (ql * (1.0 + ql) / Math.pow((1.0 - ql), 3) + qr * (1.0 + qr) / Math.pow((1.0 - qr), 3));
		return error;
	}

	public static double getApproximatedExpectedError(double epsilon, int n, int d, double beta) {
		double error = (1.0 - beta) / beta / n + 8.0 * d / n / n / epsilon / epsilon;
		return error;
	}

	public static double getSigma2(int n, int d, double ql, double qr) {
		double sigma2 = 1.0 / ((ql / (1.0 - ql) + 1.0 / (1 - qr)))
				* (ql * (1.0 + ql) / Math.pow((1.0 - ql), 3) + qr * (1.0 + qr) / Math.pow((1.0 - qr), 3));
		return sigma2;
	}

}
