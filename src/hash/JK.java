package hash;

public class JK {
	private int groupId = -1;
	private int hashValue = -1;

	public JK(int groupId, int hashValue) {
		this.groupId = groupId;
		this.hashValue = hashValue;
	}

	public int getGroupId() {
		return groupId;
	}

	public int getHashValue() {
		return hashValue;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		JK other = (JK) obj;
		return this.groupId == other.groupId && this.hashValue == other.hashValue;
	}

	@Override
	public int hashCode() {
		int result = Integer.hashCode(groupId);
		result = 31 * result + Integer.hashCode(hashValue);
		return result;
	}
}