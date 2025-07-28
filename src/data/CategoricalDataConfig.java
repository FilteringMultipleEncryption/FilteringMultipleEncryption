package data;

public enum CategoricalDataConfig {
	foursquare(1000000, 18201), aol(16777216, 10000);

	private final int n;
	private final int d;

	CategoricalDataConfig(int d, int n) {
		this.d = d;
		this.n = n;
	}

	public int getD() {
		return d;
	}

	public int getN() {
		return n;
	}

}
