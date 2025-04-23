package fme;

public abstract class LNFAbstractDummyDistribution {

	protected double mu;
	protected double sigma2;

	protected abstract int sample();

	protected abstract int getZth(double alpha);

	public double getMu() {
		return mu;
	}

	public double getSigma2() {
		return sigma2;
	}


}
