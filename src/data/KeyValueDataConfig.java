package data;

public enum KeyValueDataConfig {
	ecommerce(1206, 23486), amazon(249274, 1210271);

	private final int n;
	private final int d;

	KeyValueDataConfig(int d, int n) {
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
