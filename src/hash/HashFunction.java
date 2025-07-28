package hash;

import java.util.Random;

public class HashFunction {
	private int range = -1;
	private int p;
	private int u;
	private int v;

	public HashFunction(int d, int range, Random rand) {

		this.p = findPrimeInRange(d);
		this.range = range;
		u = (int) (rand.nextDouble() * (p - 1)) + 1;
		v = (int) (rand.nextDouble() * p);
	}

	public static int findPrimeInRange(int B) {
		for (int i = B; i < 2 * B; i++) {
			if (isPrime(i)) {
				return i;
			}
		}
		return -1;
	}

	private static boolean isPrime(int number) {
		if (number <= 1) {
			return false;
		}
		if (number == 2) {
			return true;
		}
		if (number % 2 == 0) {
			return false;
		}
		for (int i = 3; i <= Math.sqrt(number); i += 2) {
			if (number % i == 0) {
				return false;
			}
		}
		return true;
	}

	public int calculateHash(int input) {
		long h = ((long) u * input + v) % p;
		return (int) (h % range);
	}

	public int getRange() {
		return range;
	}

}
