package fme;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.EncryptionUtil;
import hash.HashFunction;
import hash.KeyIdAndHashedValue;

public class LFNUserGroupHash extends LNFUser {
	private KeyIdAndHashedValue hashedKeyAndValue = null;

	public LFNUserGroupHash(int value, PublicKey pk, int groupId, HashFunction hashUtil)
			throws NoSuchAlgorithmException {
		super(value, pk);
		hashedKeyAndValue = new KeyIdAndHashedValue(groupId, hashUtil.calculateHash(value));
	}

	public LFNUserGroupHash(PublicKey pk) throws NoSuchAlgorithmException {
		super(pk);
	}

	public void setFakeValue(int value, int groupId, HashFunction hashFunction) throws NoSuchAlgorithmException {
		super.value = value;
		hashedKeyAndValue = new KeyIdAndHashedValue(groupId, hashFunction.calculateHash(value));
	}

	// For evaluation only
	public int getOriginalValue() {
		return value;
	}

	public byte[] getValue() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return EncryptionUtil.encrypt(pk, value);
	}

	public byte[] getHashKeyAndValue() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return EncryptionUtil.encrypt(pk, hashedKeyAndValue);
	}

	public void setPoisonedValue(Set<Integer> targets) {
		List<Integer> list = new ArrayList<Integer>();
		list.addAll(targets);
		int rand = (int) (Math.random() * targets.size());
		value = list.get(rand);
	}
}
