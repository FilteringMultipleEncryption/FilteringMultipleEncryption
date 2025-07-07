package util;

import java.util.Objects;

public class GeoPoint {
	private final double latitude;
	private final double longitude;

	public GeoPoint(double latitude, double longitude) {
		if (latitude < -90.0 || latitude > 90.0) {
			throw new IllegalArgumentException("Latitude must be between -90 and 90 degrees.");
		}
		if (longitude < -180.0 || longitude > 180.0) {
			throw new IllegalArgumentException("Longitude must be between -180 and 180 degrees.");
		}
		this.latitude = latitude;
		this.longitude = longitude;
	}

	public double getLatitude() {
		return latitude;
	}

	public double getLongitude() {
		return longitude;
	}

	@Override
	public String toString() {
		return "GeoPoint{" + "latitude=" + latitude + ", longitude=" + longitude + '}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		GeoPoint geoPoint = (GeoPoint) o;
		return Double.compare(geoPoint.latitude, latitude) == 0 && Double.compare(geoPoint.longitude, longitude) == 0;
	}

	@Override
	public int hashCode() {
		return Objects.hash(latitude, longitude);
	}
}