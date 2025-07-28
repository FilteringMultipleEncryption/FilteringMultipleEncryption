package hash;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;

public class HashUtil {

	public static ArrayList<HashSet<JK>> getSupportingSetMap(int d, HashFunction hashFunctions[])
			throws NoSuchAlgorithmException {
		int groupNum = hashFunctions.length;
		ArrayList<HashSet<JK>> si = new ArrayList<HashSet<JK>>();

		for (int i = 0; i < d; i++) {
			HashSet<JK> jkSet = new HashSet<JK>();
			si.add(jkSet);
		}

		for (int i = 0; i < d; i++) {
			for (int j = 0; j < groupNum; j++) {
				int k = hashFunctions[j].calculateHash(i);
				JK jk = new JK(j, k);
				si.get(i).add(jk);
			}
		}
		return si;
	}

}
