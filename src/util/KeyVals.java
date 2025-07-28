package util;

import java.util.HashMap;
import java.util.List;

public class KeyVals {
	List<HashMap<Integer, Double>> keyVals;
	int allKeyNum;

	public KeyVals(List<HashMap<Integer, Double>> keyVals, int allKeyNum) {
		this.keyVals = keyVals;
		this.allKeyNum = allKeyNum;
	}

	public List<HashMap<Integer, Double>> getKeyVals() {
		return keyVals;
	}

	public int getAllKeyNum() {
		return allKeyNum;
	}
}
