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

	public static double getExpectedErrorAlgorithm1(int n, int d, double ql, double qr, double beta, int g, int b) {

		double sigma2 = getSigma2(n, d, ql, qr);

		double vhij = ((double) n * n * beta * beta / ((double) g * d) + n * beta * (1 - beta) / g) * (1.0 / b)
				* (1 - 1.0 / b) + n * beta * (1 - beta) / g * (1.0 / b / b);

		vhij *= (d - 1.0) / d;

		double error = (double) b * b / ((double) n * n * beta * beta * (b - 1) * (b - 1))
				* (n * beta * (1 - beta) + d * vhij + g * sigma2 * d);

		return error;
	}

	public static double getExpectedErrorHash2(int n, int d, double ql, double qr, double beta, int g, int b,
			double fis[]) {

		double sigma2 = getSigma2(n, d, ql, qr);

		double vhij_sum = 0.0;

		for (int i = 0; i < d; i++) {
			double vhij = 0.0;

			for (int j = 0; j < d; j++) {
				if (i == j) {
					continue;
				}
				double temp = ((double) n * n * fis[j] * fis[j] * beta * beta / g + n * fis[j] * beta * (1 - beta) / g)
						* (1.0 / b) * (1 - 1.0 / b) + n * fis[j] * beta * (1 - beta) / g * (1.0 / b / b);
				vhij += temp;
			}
			vhij_sum += vhij;
		}

		double error = (double) b * b / ((double) n * n * beta * beta * (b - 1) * (b - 1))
				* (n * beta * (1 - beta) + vhij_sum + g * sigma2 * d);

		return error;

	}

	public static double getApproximatedExpectedErrorHash(int n, int d, double ql, double qr, double beta, int g,
			int b) {

		double sigma2 = getSigma2(n, d, ql, qr);
		double error = ((double) n * n / b + g * sigma2 * d) / n / n;

		return error;

	}

}
