package util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Enumeration;
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
			System.err.println("Usage: java DataPreProcessing <dataName>");
			System.err.println("Example: java DataPreProcessing foursquare");
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

	private static BufferedReader getBufferedReader(String path, String fileName) throws IOException {
		File f = new File(path);

		if (!f.exists() && path.toLowerCase().endsWith(".zip")) {
			File parent = f.getParentFile();
			if (parent != null && parent.isDirectory()) {
				File candidate = new File(parent, fileName);
				if (candidate.exists() && candidate.isFile()) {
					return new BufferedReader(new FileReader(candidate, StandardCharsets.UTF_8));
				}
				File stemDir = new File(parent, f.getName().replaceFirst("(?i)\\.zip$", ""));
				File candidate2 = new File(stemDir, fileName);
				if (candidate2.exists() && candidate2.isFile()) {
					return new BufferedReader(new FileReader(candidate2, StandardCharsets.UTF_8));
				}
			}
			throw new IOException("Path not found: " + path);
		}

		if (f.isDirectory()) {
			File target = new File(f, fileName);
			if (target.exists() && target.isFile()) {
				return new BufferedReader(new FileReader(target, StandardCharsets.UTF_8));
			}
			throw new IOException("File not found in directory: " + new File(f, fileName).getAbsolutePath());
		}

		if (f.isFile() && !path.toLowerCase().endsWith(".zip")) {
			if (fileName == null || fileName.isEmpty() || f.getName().equals(fileName)) {
				return new BufferedReader(new FileReader(f, StandardCharsets.UTF_8));
			} else {
				File sibling = new File(f.getParentFile(), fileName);
				if (sibling.exists() && sibling.isFile()) {
					return new BufferedReader(new FileReader(sibling, StandardCharsets.UTF_8));
				}
				throw new IOException("File name mismatch: " + f.getName() + " (expected " + fileName + ")");
			}
		}

		if (f.isFile() && path.toLowerCase().endsWith(".zip")) {
			final ZipFile zipFile = new ZipFile(f);
			try {
				ZipEntry entry = zipFile.getEntry(fileName);

				if (entry == null) {
					Enumeration<? extends ZipEntry> entries = zipFile.entries();
					while (entries.hasMoreElements()) {
						ZipEntry e = entries.nextElement();
						if (!e.isDirectory() && e.getName().endsWith("/" + fileName)) {
							entry = e;
							break;
						}
					}
				}
				if (entry == null) {
					zipFile.close();
					throw new IOException("Entry not found in zip: " + fileName + " in " + path);
				}

				FilterInputStream fis = new FilterInputStream(zipFile.getInputStream(entry)) {
					@Override
					public void close() throws IOException {
						try {
							super.close();
						} finally {
							zipFile.close();
						}
					}
				};
				return new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8));
			} catch (IOException e) {
				try {
					zipFile.close();
				} catch (IOException ignore) {
				}
				throw e;
			}
		}

		throw new IOException("Invalid path: " + path);
	}

	private static BufferedReader openFirstAvailable(String[] paths, String fileName) throws IOException {
		IOException last = null;
		for (String p : paths) {
			try {
				return getBufferedReader(p, fileName);
			} catch (IOException e) {
				last = e; 
			}
		}
		throw (last != null) ? last : new IOException("No valid path found for " + fileName);
	}

	private static void foursquare() throws IOException {
		final int m = 1000;

		final String fileNameUserProfile = "dataset_UbiComp2016_UserProfile_NYC.txt";
		final String fileNameCheckins = "dataset_TIST2015_Checkins.txt";
		final String fileNamePOIs = "dataset_TIST2015_POIs.txt";

		final String[] profilePaths = { "data", 
				"data/dataset_UbiComp2016.zip", 
				"data/dataset_UbiComp2016" 
		};
		final String[] tistPaths = { "data", 
				"data/dataset_TIST2015.zip", 
				"data/dataset_TIST2015" 
		};

		Set<Integer> userIds = new HashSet<>();
		HashMap<Integer, String> userId2locationId = new HashMap<>();
		HashMap<String, GeoPoint> locationId2geo = new HashMap<>();

		double minLat = Double.POSITIVE_INFINITY;
		double maxLat = Double.NEGATIVE_INFINITY;
		double minLon = Double.POSITIVE_INFINITY;
		double maxLon = Double.NEGATIVE_INFINITY;

		try (BufferedReader br = openFirstAvailable(profilePaths, fileNameUserProfile)) {
			String line;
			while ((line = br.readLine()) != null) {
				String[] parts = line.split("\t");
				if (parts.length > 0) {
					try {
						userIds.add(Integer.parseInt(parts[0]));
					} catch (NumberFormatException e) {
						System.err.println("Invalid userId: " + parts[0]);
					}
				}
			}
		}

		try (BufferedReader br = openFirstAvailable(tistPaths, fileNameCheckins)) {
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
						System.err.println("Invalid userId: " + parts[0]);
					}
				}
			}
		}

		try (BufferedReader br = openFirstAvailable(tistPaths, fileNamePOIs)) {
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
						System.err.println("Invalid lat/lon: " + Arrays.toString(ss));
					}
				}
			}
		}

		File outDir = new File("dataset");
		if (!outDir.exists())
			outDir.mkdirs();

		try (BufferedWriter bw = new BufferedWriter(
				new FileWriter(new File(outDir, "foursquare.txt"), StandardCharsets.UTF_8))) {
			for (String locationId : userId2locationId.values()) {
				GeoPoint gp = locationId2geo.get(locationId);
				if (gp == null)
					continue;

				double lat = gp.getLatitude();
				double lon = gp.getLongitude();

				int latIndex = findPosition(minLat, maxLat, m, lat);
				int lonIndex = findPosition(minLon, maxLon, m, lon);

				if (latIndex < 0 || lonIndex < 0)
					continue; 

				int finalId = latIndex + m * lonIndex;
				bw.write(Integer.toString(finalId));
				bw.newLine();
			}
		}
	}

}
