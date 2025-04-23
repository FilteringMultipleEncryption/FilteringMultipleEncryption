package fme;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Random;
import java.util.TreeMap;

public class DataUtil {

	public static boolean deleteFiles(File folder) {
		if (!folder.exists()) {
			return false;
		}
		File[] files = folder.listFiles();
		for (File file : files) {
			if (!file.delete()) {
				return false;
			}
		}
		return true;
	}

	public static boolean deleteFolderRecursively(File folder) {
		if (!folder.exists()) {
			return false;
		}

		File[] files = folder.listFiles();
		if (files != null) {
			for (File file : files) {
				if (file.isDirectory()) {
					deleteFolderRecursively(file);
				} else {
					if (!file.delete()) {
						return false;
					}
				}
			}
		}

		return folder.delete();
	}

	public static double calculateFolderSize(Path folderPath) throws IOException {

		final long[] totalSize = { 0 };

		Files.walkFileTree(folderPath, new SimpleFileVisitor<>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				if (Files.isRegularFile(file)) {
					totalSize[0] += attrs.size();
				}
				return FileVisitResult.CONTINUE;
			}
		});

		return (double) totalSize[0] / 1024 / 1024 / 1024;
	}

	public static void createSyntheticKeyValueData_Gu_Gaussian(String fileName, int numberOfUsers, int numberOfKeys) {
		double keyStdDev = 50; // Standard deviation for keys
		double valueStdDev = 1.0; // Standard deviation for values

		Random random = new Random();

		try (FileWriter writer = new FileWriter(fileName)) {

			// First pass: Generate values and track min/max values
			for (int i = 0; i < numberOfUsers; i++) {
				int key;
				do {
					key = (int) Math.round(random.nextGaussian() * keyStdDev + numberOfKeys / 2.0);
				} while (key < 1 || key > numberOfKeys);

				// Generate a value for the user
				double value;
				do {
					value = random.nextGaussian() * valueStdDev; // Zero-mean Gaussian for value
				} while (value < -1 || value > 1);

				writer.write(key + "," + value + "\n");

			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void createSyntheticKeyValueData_Gu_Uniform(String fileName, int numberOfUsers, int numberOfKeys) {

		try (FileWriter writer = new FileWriter(fileName)) {
			int key = (int) (Math.random() * numberOfKeys);
			double value = -1 + 2 * Math.random();
			writer.write(key + "," + value + "\n");

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public static void createSyntheticKeyValueData_Wu(String fileName, int numberOfUsers, int numberOfKeys) {

		// int numberOfUsers = (int) Math.pow(10, 5); // 10^5 users
		// int numberOfKeys = 100; // 100 keys
		// double keyStdDev = 15.0; // Standard deviation for key frequencies
		double keyStdDev = numberOfKeys * 0.15;
		double valueStdDev = 1.0; // Standard deviation for values

		Random random = new Random();

		double minValue = Double.MAX_VALUE;
		double maxValue = Double.MIN_VALUE;
		double[] values = new double[numberOfUsers];

		try (FileWriter writer = new FileWriter(fileName)) {

			// First pass: Generate values and track min/max values
			for (int i = 0; i < numberOfUsers; i++) {
				// Generate a value for the user
				double value = random.nextGaussian() * valueStdDev; // Zero-mean Gaussian for value
				values[i] = value;

				if (value < minValue)
					minValue = value;
				if (value > maxValue)
					maxValue = value;
			}

			// Second pass: Normalize values, generate keys, and write to file
			for (int i = 0; i < numberOfUsers; i++) {
				int key;
				do {
					key = (int) Math.round(random.nextGaussian() * keyStdDev + numberOfKeys / 2.0);
				} while (key < 1 || key > numberOfKeys);

				// Normalize value to [0, 1]
				double normalizedValue = (values[i] - minValue) / (maxValue - minValue);

				// Write the data to the file
				writer.write(key + "," + normalizedValue + "\n");
			}

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
