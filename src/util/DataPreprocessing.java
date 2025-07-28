package util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class DataPreprocessing {
	public static void main(String args[]) throws IOException {
		if (args.length >= 1) {
			String dataName = args[0];
			if (dataName.equalsIgnoreCase("foursquare")) {
				foursquare();
			} else if (dataName.equalsIgnoreCase("amazon")) {
				amazon();
			}

		} else {
			System.err.println("Usage: java DataProcessing <dataName>");
			System.err.println("Example: java DataProcessing foursquare");
			return;
		}
	}

	private static void amazon() throws IOException {
		String inputFile = "data/ratings_Beauty.csv";
		String outputFile = "dataset/amazon.txt";
		try (BufferedReader br = new BufferedReader(new FileReader(inputFile));
				BufferedWriter bw = new BufferedWriter(new FileWriter(outputFile))) {

			String line;
			boolean isFirstLine = true;

			while ((line = br.readLine()) != null) {
				if (isFirstLine) {
					isFirstLine = false;
					continue;
				}

				String[] parts = line.split(",");
				if (parts.length >= 3) {
					String userId = parts[0];
					String productId = parts[1];
					String rating = parts[2];

					bw.write(userId + "\t" + productId + "\t" + rating);
					bw.newLine();
				}
			}
		}
	}

	private static void foursquare() throws IOException {
		int m = 1000;

		String zipFilePath1 = "data/dataset_UbiComp2016.zip";
		String fileName1 = "dataset_UbiComp2016_UserProfile_NYC.txt";

		String zipFilePath2 = "data/dataset_TIST2015.zip";
		String fileName2 = "dataset_TIST2015_Checkins.txt";
		String fileName3 = "dataset_TIST2015_POIs.txt";

		Set<Integer> userIds = new HashSet<>();
		HashMap<Integer, String> userId2locationId = new HashMap<>();
		HashMap<String, GeoPoint> locationId2geo = new HashMap<>();

		double minLat = 10000;
		double maxLat = -10000;
		double minLon = 10000;
		double maxLon = -10000;

		try (ZipFile zipFile = new ZipFile(zipFilePath1)) {
			ZipEntry entry = zipFile.getEntry(fileName1);
			if (entry == null) {
				System.err.println("File " + fileName1 + " not found in the ZIP archive.");
				return;
			}

			try (BufferedReader br = new BufferedReader(new InputStreamReader(zipFile.getInputStream(entry)))) {
				String line;
				while ((line = br.readLine()) != null) {
					String[] parts = line.split("\t");
					if (parts.length > 0) {
						try {
							userIds.add(Integer.parseInt(parts[0]));
						} catch (NumberFormatException e) {
							System.err.println("Invalid number format: " + parts[0]);
						}
					}
				}
			}
		}

		try (ZipFile zipFile = new ZipFile(zipFilePath2)) {
			ZipEntry entry2 = zipFile.getEntry(fileName2);
			if (entry2 == null) {
				System.err.println("File " + fileName2 + " not found in the ZIP archive.");
				return;
			}

			try (BufferedReader br = new BufferedReader(new InputStreamReader(zipFile.getInputStream(entry2)))) {
				String line;
				while ((line = br.readLine()) != null) {
					String[] parts = line.split("\t");
					if (parts.length >= 2) {
						try {
							int userId = Integer.parseInt(parts[0]);
							String locationId = parts[1];
							if (userIds.contains(userId)) {
								userId2locationId.putIfAbsent(userId, locationId);
							}
						} catch (NumberFormatException e) {
							System.err.println("Invalid number format: " + parts[0]);
						}
					}
				}
			}

			ZipEntry entry3 = zipFile.getEntry(fileName3);
			if (entry3 == null) {
				System.err.println("File " + fileName3 + " not found in the ZIP archive.");
				return;
			}

			try (BufferedReader br = new BufferedReader(new InputStreamReader(zipFile.getInputStream(entry3)))) {
				String line;
				while ((line = br.readLine()) != null) {
					String[] ss = line.split("\t");
					if (ss.length >= 3) {
						String locationId = ss[0];
						try {
							double lat = Double.parseDouble(ss[1]);
							double lon = Double.parseDouble(ss[2]);
							locationId2geo.put(locationId, new GeoPoint(lat, lon));

							if (lat < minLat)
								minLat = lat;
							if (lat > maxLat)
								maxLat = lat;
							if (lon < minLon)
								minLon = lon;
							if (lon > maxLon)
								maxLon = lon;
						} catch (NumberFormatException e) {
							System.err.println("Invalid lat/lon format at: " + Arrays.toString(ss));
						}
					}
				}
			}
		}

		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("dataset/foursquare.txt")));
		for (String locationId : userId2locationId.values()) {
			GeoPoint gp = locationId2geo.get(locationId);
			double lat = gp.getLatitude();
			double lon = gp.getLongitude();

			int latIndex = findPosition(minLat, maxLat, m, lat);
			int lonIndex = findPosition(minLon, maxLon, m, lon);

			int finalId = latIndex + m * lonIndex;
			bw.write("" + finalId);
			bw.newLine();

		}
		bw.close();
	}

	private static int findPosition(double min, double max, int m, double a) {
		if (a < min || a > max) {
			return -1;
		}

		double interval = (max - min) / m;

		int position = (int) ((a - min) / interval);

		if (position == m) {
			position = m - 1;
		}

		return position;
	}

}
