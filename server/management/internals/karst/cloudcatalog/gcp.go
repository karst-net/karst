// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudcatalog

// gcp is a representative subset of Google Cloud's public regions (not
// exhaustive -- see the package doc comment). Zones (the -a/-b/-c suffix on
// a region) are physically co-located with their parent region and carry no
// coordinates of their own in this catalog, the same convention used for
// Azure Availability Zones.
var gcp = []Region{
	{Provider: "gcp", Code: "us-east1", Name: "South Carolina", Lat: 33.8361, Lon: -81.1637, Kind: KindRegion},
	{Provider: "gcp", Code: "us-east4", Name: "Northern Virginia", Lat: 37.3719, Lon: -79.8164, Kind: KindRegion},
	{Provider: "gcp", Code: "us-east5", Name: "Columbus", Lat: 39.9612, Lon: -82.9988, Kind: KindRegion},
	{Provider: "gcp", Code: "us-central1", Name: "Iowa", Lat: 41.2619, Lon: -95.8608, Kind: KindRegion},
	{Provider: "gcp", Code: "us-west1", Name: "Oregon", Lat: 45.5946, Lon: -121.1787, Kind: KindRegion},
	{Provider: "gcp", Code: "us-west2", Name: "Los Angeles", Lat: 34.0522, Lon: -118.2437, Kind: KindRegion},
	{Provider: "gcp", Code: "us-west3", Name: "Salt Lake City", Lat: 40.7608, Lon: -111.8910, Kind: KindRegion},
	{Provider: "gcp", Code: "us-west4", Name: "Las Vegas", Lat: 36.1699, Lon: -115.1398, Kind: KindRegion},
	{Provider: "gcp", Code: "us-south1", Name: "Dallas", Lat: 32.7767, Lon: -96.7970, Kind: KindRegion},
	{Provider: "gcp", Code: "northamerica-northeast1", Name: "Montreal", Lat: 45.5017, Lon: -73.5673, Kind: KindRegion},
	{Provider: "gcp", Code: "northamerica-northeast2", Name: "Toronto", Lat: 43.6532, Lon: -79.3832, Kind: KindRegion},
	{Provider: "gcp", Code: "northamerica-south1", Name: "Queretaro", Lat: 20.5888, Lon: -100.3899, Kind: KindRegion},
	{Provider: "gcp", Code: "southamerica-east1", Name: "Sao Paulo", Lat: -23.5505, Lon: -46.6333, Kind: KindRegion},
	{Provider: "gcp", Code: "southamerica-west1", Name: "Santiago", Lat: -33.4489, Lon: -70.6693, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west1", Name: "Belgium", Lat: 50.8503, Lon: 4.3517, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west2", Name: "London", Lat: 51.5072, Lon: -0.1276, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west3", Name: "Frankfurt", Lat: 50.1109, Lon: 8.6821, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west4", Name: "Netherlands", Lat: 53.4386, Lon: 6.8355, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west6", Name: "Zurich", Lat: 47.3769, Lon: 8.5417, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west8", Name: "Milan", Lat: 45.4642, Lon: 9.1900, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west9", Name: "Paris", Lat: 48.8566, Lon: 2.3522, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west10", Name: "Berlin", Lat: 52.5200, Lon: 13.4050, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-west12", Name: "Turin", Lat: 45.0703, Lon: 7.6869, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-north1", Name: "Finland", Lat: 60.5693, Lon: 27.1878, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-central2", Name: "Warsaw", Lat: 52.2297, Lon: 21.0122, Kind: KindRegion},
	{Provider: "gcp", Code: "europe-southwest1", Name: "Madrid", Lat: 40.4168, Lon: -3.7038, Kind: KindRegion},
	{Provider: "gcp", Code: "me-west1", Name: "Tel Aviv", Lat: 32.0853, Lon: 34.7818, Kind: KindRegion},
	{Provider: "gcp", Code: "me-central1", Name: "Doha", Lat: 25.2854, Lon: 51.5310, Kind: KindRegion},
	{Provider: "gcp", Code: "me-central2", Name: "Dammam", Lat: 26.4207, Lon: 50.0888, Kind: KindRegion},
	{Provider: "gcp", Code: "africa-south1", Name: "Johannesburg", Lat: -26.2041, Lon: 28.0473, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-east1", Name: "Taiwan", Lat: 24.0717, Lon: 120.5624, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-east2", Name: "Hong Kong", Lat: 22.3193, Lon: 114.1694, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-northeast1", Name: "Tokyo", Lat: 35.6762, Lon: 139.6503, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-northeast2", Name: "Osaka", Lat: 34.6937, Lon: 135.5023, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-northeast3", Name: "Seoul", Lat: 37.5665, Lon: 126.9780, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-south1", Name: "Mumbai", Lat: 19.0760, Lon: 72.8777, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-south2", Name: "Delhi", Lat: 28.7041, Lon: 77.1025, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-southeast1", Name: "Singapore", Lat: 1.3521, Lon: 103.8198, Kind: KindRegion},
	{Provider: "gcp", Code: "asia-southeast2", Name: "Jakarta", Lat: -6.2088, Lon: 106.8456, Kind: KindRegion},
	{Provider: "gcp", Code: "australia-southeast1", Name: "Sydney", Lat: -33.8688, Lon: 151.2093, Kind: KindRegion},
	{Provider: "gcp", Code: "australia-southeast2", Name: "Melbourne", Lat: -37.8136, Lon: 144.9631, Kind: KindRegion},
}
