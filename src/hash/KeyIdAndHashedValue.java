package hash;

public class KeyIdAndHashedValue {
	private int id;
	private int hashedValue;

	public KeyIdAndHashedValue(int id, int hashedValue) {
		this.id = id;
		this.hashedValue = hashedValue;
	}

	public int getGroupId() {
		return id;
	}

	public int getHashedValue() {
		return hashedValue;
	}
}
