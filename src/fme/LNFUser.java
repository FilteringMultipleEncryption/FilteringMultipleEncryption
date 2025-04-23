package fme;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.EncryptionUtil;
import hash.HashFunction;

public class LNFUser {

	protected int value = -100;
	// If pk is null, the value will not be encrypted.
	protected PublicKey pk;
	protected int hashValue = -100;
	protected HashMap<Integer, Double> keyValue;
	protected HashFunction hashFunction;

	protected static int kappa;

	protected boolean isRemaining = true;

	public LNFUser(PublicKey pk) {
		this.pk = pk;
	}

	public void setFakeValue(int fakeValue, HashFunction hashFunction) throws NoSuchAlgorithmException {
		value = fakeValue;
		hashValue = hashFunction.calculateHash(value);
	}

	public LNFUser(int value, PublicKey pk) {
		this.value = value;
		this.pk = pk;
	}

	public LNFUser(int value, PublicKey pk, HashFunction hashFunction) throws NoSuchAlgorithmException {
		this.value = value;
		this.pk = pk;
		hashValue = hashFunction.calculateHash(value);
	}

	public LNFUser(int value, HashFunction hashFunction) throws NoSuchAlgorithmException {
		this.value = value;
		hashValue = hashFunction.calculateHash(value);
	}

	public LNFUser(HashMap<Integer, Double> keyValue, HashFunction hashFunction, int kappa) {
		this.keyValue = keyValue;
		this.hashFunction = hashFunction;
		LNFUser.kappa = kappa;
	}

	// For evaluation only
	public int getOriginalValue() {
		return value;
	}

	/**
	 * Round1
	 * 
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchProviderException
	 */
	public byte[] getEncryptedHashValue() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return EncryptionUtil.encrypt(pk, hashValue);
	}

	public int getHashValue() {
		return hashValue;
	}

	/**
	 * Round2
	 * 
	 * @param filteringInfo
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchProviderException
	 */
	public byte[] getEncryptedFilteredValue(HashSet<Integer> filteringInfo)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException, NoSuchProviderException {

		if (filteringInfo.contains(hashValue)) {
			return EncryptionUtil.encrypt(pk, value);
		} else {
			isRemaining = false;
			return EncryptionUtil.encrypt(pk, Util.nonExist);
		}

	}

	public int getFilteredValue(HashSet<Integer> filteringInfo) {
		if (filteringInfo.contains(hashValue)) {
			return value;
		} else {
			isRemaining = false;
			return Util.nonExist;
		}

	}

	public boolean isRemaining() {
		return this.isRemaining;
	}

	// public byte[] getValueKeyValue(HashSet<Integer> filteringInfo)
	// throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
	// NoSuchAlgorithmException,
	// NoSuchPaddingException, NoSuchProviderException {
	//
	// if (filteringInfo.contains(value)) {
	// return EncryptionUtil.encrypt(pk, value);
	// } else {
	// return EncryptionUtil.encrypt(pk, Util.nonExist);
	// }
	//
	// }

	public void setPoisonedValue(Set<Integer> targets) {
		List<Integer> list = new ArrayList<Integer>();
		list.addAll(targets);
		int rand = (int) (Math.random() * targets.size());
		value = list.get(rand);
	}

	public void keyValuePerturbation(int d) throws NoSuchAlgorithmException {
		int keyValSize = keyValue.size();
		int addNum = Math.max(kappa - keyValSize, 0);
		int dDash = d + kappa;

		HashSet<Integer> keySet = new HashSet<Integer>();
		keySet.addAll(keyValue.keySet());

		for (int j = 0; j < addNum; j++) {
			keySet.add(keyValSize + 1 + j);
		}
		int key = keySet.stream().skip(new Random().nextInt(keySet.size())).findFirst().get();
		double value = keyValue.getOrDefault(key, 0.0);

		double rand = Math.random();
		int vStar = Integer.MAX_VALUE;
		if (rand < (1 + value) / 2.0) {
			vStar = 1;
		} else {
			vStar = -1;
		}


		this.value = Util.getKeyValueId(key, vStar, dDash);
		hashValue = hashFunction.calculateHash(this.value);
	}

}
