package fme;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.EncryptionUtil;
import hash.HashFunction;

public class LNFUserKeyValue {

	protected int value;
	// If pk is null, the value will not be encrypted.
	protected PublicKey pk;
	protected int hashValue;
	protected HashMap<Integer, Double> keyValue;

	public LNFUserKeyValue(PublicKey pk) {
		this.pk = pk;
	}

	public void setFakeValue(int fakeValue, HashFunction hashFunction) throws NoSuchAlgorithmException {
		value = fakeValue;
		hashValue = hashFunction.calculateHash(value);
	}

	public LNFUserKeyValue(int value, PublicKey pk) {
		this.value = value;
		this.pk = pk;
	}

	public LNFUserKeyValue(int value, PublicKey pk, HashFunction hashFunction) throws NoSuchAlgorithmException {
		this.value = value;
		this.pk = pk;
		hashValue = hashFunction.calculateHash(value);
	}

	public LNFUserKeyValue(HashMap<Integer, Double> keyValue, PublicKey pk) {
		this.keyValue = keyValue;
		this.pk = pk;
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
	public byte[] getHashValue() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return EncryptionUtil.encrypt(pk, hashValue);
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
	public byte[] getValue(HashSet<Integer> filteringInfo) throws InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {

		if (filteringInfo.contains(hashValue)) {
			return EncryptionUtil.encrypt(pk, value);
		} else {
			return EncryptionUtil.encrypt(pk, -1);
		}

	}

	public void setPoisonedValue(Set<Integer> targets) {
		List<Integer> list = new ArrayList<Integer>();
		list.addAll(targets);
		int rand = (int) (Math.random() * targets.size());
		value = list.get(rand);
	}
}
