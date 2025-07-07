package encryption;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import hash.KeyIdAndHashedValue;

public class EncryptionUtil {

	public static int getSize(ENCRYPTION_MODE mode, int turn) {
		if (mode == ENCRYPTION_MODE.ECIES) {
			if (turn == 1) {
				return 712;
			} else if (turn == 2) {
				return 1392;
			} else if (turn == 3) {
				return 2027;
			} else {
				return -1;
			}
		} else if (mode == ENCRYPTION_MODE.RSA) {
			if (turn == 1) {
				return 2048;
			} else if (turn == 2) {
				return 2048 * 2;
			} else if (turn == 3) {
				return 2048 * 3;
			} else {
				return -1;
			}
		} else {
			return -1;
		}
	}

	public static byte[] int2bytearray(int i) {
		byte[] bytes = new byte[4];
		bytes[0] = (byte) (i >> 24);
		bytes[1] = (byte) (i >> 16);
		bytes[2] = (byte) (i >> 8);
		bytes[3] = (byte) i;
		return bytes;
	}

	private static byte[] int2bytearray(int int1, int int2) {
		byte[] bytes = new byte[8];

		bytes[0] = (byte) (int1 >> 24);
		bytes[1] = (byte) (int1 >> 16);
		bytes[2] = (byte) (int1 >> 8);
		bytes[3] = (byte) int1;

		bytes[4] = (byte) (int2 >> 24);
		bytes[5] = (byte) (int2 >> 16);
		bytes[6] = (byte) (int2 >> 8);
		bytes[7] = (byte) int2;
		return bytes;
	}

	private static int bytearray2int(byte[] b) {
		int i = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
		return i;
	}

	private static int[] bytearray2int2(byte[] b) {
		int int1 = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);

		int int2 = ((b[4] & 0xFF) << 24) | ((b[5] & 0xFF) << 16) | ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);

		return new int[] { int1, int2 };
	}

	private static Cipher encrypter = null;
	private static Cipher decrypter = null;
	private static ENCRYPTION_MODE eMode = null;

	public static byte[] encrypt(PublicKey publicKey, KeyIdAndHashedValue hashedValue)
			throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, NoSuchProviderException {
		if (publicKey == null) {
			return int2bytearray(hashedValue.getGroupId(), hashedValue.getHashedValue());
		} else {
			if (encrypter == null) {
				if (eMode == ENCRYPTION_MODE.ECIES) {
					encrypter = Cipher.getInstance("ECIES", "BC");
				} else if (eMode == ENCRYPTION_MODE.RSA) {
					encrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
				}
				encrypter.init(Cipher.ENCRYPT_MODE, publicKey);
			}

			byte[] buffer = int2bytearray(hashedValue.getGroupId(), hashedValue.getHashedValue());
			byte[] encrypted = encrypter.doFinal(buffer);
			return encrypted;
		}
	}

	public static byte[] encrypt(PublicKey publicKey, int value) throws IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
		if (publicKey == null) {
			return int2bytearray(value);
		} else {
			if (encrypter == null) {
				if (eMode == ENCRYPTION_MODE.ECIES) {
					encrypter = Cipher.getInstance("ECIES", "BC");
				} else if (eMode == ENCRYPTION_MODE.RSA) {
					encrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
				}
				encrypter.init(Cipher.ENCRYPT_MODE, publicKey);
			}

			byte[] buffer = int2bytearray(value);
			byte[] encrypted = encrypter.doFinal(buffer);
			return encrypted;
		}
	}

	public static byte[] encryptECIES(PublicKey publicKey, int value)
			throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, NoSuchProviderException {

		encrypter = Cipher.getInstance("ECIES", "BC");
		encrypter.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] buffer = int2bytearray(value);
		byte[] encrypted = encrypter.doFinal(buffer);
		return encrypted;
	}

	public static byte[] encryptRSA(PublicKey publicKey, int value)
			throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, NoSuchProviderException {
		encrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
		encrypter.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] buffer = int2bytearray(value);
		byte[] encrypted = encrypter.doFinal(buffer);
		return encrypted;

	}

	public static byte[] encrypt(PublicKey publicKey, byte b[]) throws IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
		if (publicKey == null) {
			return b;
		} else {
			if (encrypter == null) {
				if (eMode == ENCRYPTION_MODE.ECIES) {
					encrypter = Cipher.getInstance("ECIES", "BC");
				} else if (eMode == ENCRYPTION_MODE.RSA) {
					encrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
				}
				encrypter.init(Cipher.ENCRYPT_MODE, publicKey);
			}

			byte[] encrypted = encrypter.doFinal(b);
			return encrypted;
		}
	}

	public static int decrypt(PrivateKey privateKey, byte encrypted[])
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		if (privateKey == null) {
			return bytearray2int(encrypted);
		} else {
			if (decrypter == null) {
				if (eMode == ENCRYPTION_MODE.ECIES) {
					decrypter = Cipher.getInstance("ECIES", "BC");
				} else if (eMode == ENCRYPTION_MODE.RSA) {
					decrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
				}
				decrypter.init(Cipher.DECRYPT_MODE, privateKey);
			}
			byte[] decrypted = decrypter.doFinal(encrypted);
			int value = bytearray2int(decrypted);
			return value;
		}
	}

	public static byte[] decrypt_byte(PrivateKey privateKey, byte encrypted[])
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		if (privateKey == null) {
			return encrypted;
		} else {
			if (decrypter == null) {
				if (eMode == ENCRYPTION_MODE.ECIES) {
					decrypter = Cipher.getInstance("ECIES", "BC");
				} else if (eMode == ENCRYPTION_MODE.RSA) {
					decrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
				}
				decrypter.init(Cipher.DECRYPT_MODE, privateKey);
			}
			byte[] decrypted = decrypter.doFinal(encrypted);
			return decrypted;
		}
	}

	public static int[] decryptHashes(PrivateKey privateKey, byte encrypted[])
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		if (privateKey == null) {
			return bytearray2int2(encrypted);
		} else {
			if (decrypter == null) {
				if (eMode == ENCRYPTION_MODE.ECIES) {
					decrypter = Cipher.getInstance("ECIES", "BC");
				} else if (eMode == ENCRYPTION_MODE.RSA) {
					decrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
				}
				decrypter.init(Cipher.DECRYPT_MODE, privateKey);
			}
			byte[] decrypted = decrypter.doFinal(encrypted);
			int value[] = bytearray2int2(decrypted);
			return value;
		}
	}

	public static KeyPair getKeyPair(ENCRYPTION_MODE eMode)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		EncryptionUtil.eMode = eMode;
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(eMode.toString(), "BC");
		if (eMode == ENCRYPTION_MODE.RSA) {
			keyGen.initialize(2048);
		} else if (eMode == ENCRYPTION_MODE.ECIES) {
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
			keyGen.initialize(ecSpec, new SecureRandom());
		}

		KeyPair keyPair = keyGen.generateKeyPair();

		return keyPair;
	}

	public static byte[] encryptInChunksRSA(PublicKey publicKey, byte[] input, int numChunks) throws Exception {
		if (publicKey == null) {
			return input;
		}

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		int keySizeBytes = ((RSAPublicKey) publicKey).getModulus().bitLength() / 8;
		int hashLen = 32; // SHA-256
		int maxChunkSize = keySizeBytes - 2 * hashLen - 2;

		int chunkSize = (int) Math.ceil((double) input.length / numChunks);

		if (chunkSize > maxChunkSize) {
			throw new IllegalArgumentException("Chunk size exceeds RSA limit. Try increasing the number of chunks.");
		}

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		for (int i = 0; i < input.length; i += chunkSize) {
			int len = Math.min(chunkSize, input.length - i);
			byte[] chunk = Arrays.copyOfRange(input, i, i + len);
			byte[] encryptedChunk = cipher.doFinal(chunk);
			outputStream.write(encryptedChunk);
		}

		return outputStream.toByteArray();
	}

	public static byte[] decryptInChunksRSA(PrivateKey privateKey, byte[] encrypted, int numChunks) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		int keySizeBytes = ((RSAPrivateKey) privateKey).getModulus().bitLength() / 8;

		if (encrypted.length != keySizeBytes * numChunks) {
			throw new IllegalArgumentException();
		}

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		for (int i = 0; i < encrypted.length; i += keySizeBytes) {
			byte[] chunk = Arrays.copyOfRange(encrypted, i, i + keySizeBytes);
			byte[] decryptedChunk = cipher.doFinal(chunk);
			outputStream.write(decryptedChunk);
		}

		return outputStream.toByteArray();
	}
}
