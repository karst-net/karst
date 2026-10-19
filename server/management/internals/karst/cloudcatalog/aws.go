// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudcatalog

// aws is the standard commercial-partition region list plus a representative
// set of Local Zones (not exhaustive -- AWS has added dozens more than are
// listed here; see the package doc comment). GovCloud/China partitions are
// out of scope: Discover only ever asks a commercial-partition credential
// for its enabled regions.
var aws = []Region{
	{Provider: "aws", Code: "us-east-1", Name: "US East (N. Virginia)", Lat: 38.9519, Lon: -77.4480, Kind: KindRegion},
	{Provider: "aws", Code: "us-east-2", Name: "US East (Ohio)", Lat: 40.4173, Lon: -82.9071, Kind: KindRegion},
	{Provider: "aws", Code: "us-west-1", Name: "US West (N. California)", Lat: 37.3541, Lon: -121.9552, Kind: KindRegion},
	{Provider: "aws", Code: "us-west-2", Name: "US West (Oregon)", Lat: 45.8696, Lon: -119.6880, Kind: KindRegion},
	{Provider: "aws", Code: "ca-central-1", Name: "Canada (Central)", Lat: 45.5017, Lon: -73.5673, Kind: KindRegion},
	{Provider: "aws", Code: "ca-west-1", Name: "Canada West (Calgary)", Lat: 51.0447, Lon: -114.0719, Kind: KindRegion},
	{Provider: "aws", Code: "sa-east-1", Name: "South America (Sao Paulo)", Lat: -23.5505, Lon: -46.6333, Kind: KindRegion},
	{Provider: "aws", Code: "mx-central-1", Name: "Mexico (Central)", Lat: 19.4326, Lon: -99.1332, Kind: KindRegion},
	{Provider: "aws", Code: "eu-west-1", Name: "Europe (Ireland)", Lat: 53.3498, Lon: -6.2603, Kind: KindRegion},
	{Provider: "aws", Code: "eu-west-2", Name: "Europe (London)", Lat: 51.5072, Lon: -0.1276, Kind: KindRegion},
	{Provider: "aws", Code: "eu-west-3", Name: "Europe (Paris)", Lat: 48.8566, Lon: 2.3522, Kind: KindRegion},
	{Provider: "aws", Code: "eu-central-1", Name: "Europe (Frankfurt)", Lat: 50.1109, Lon: 8.6821, Kind: KindRegion},
	{Provider: "aws", Code: "eu-central-2", Name: "Europe (Zurich)", Lat: 47.3769, Lon: 8.5417, Kind: KindRegion},
	{Provider: "aws", Code: "eu-north-1", Name: "Europe (Stockholm)", Lat: 59.3293, Lon: 18.0686, Kind: KindRegion},
	{Provider: "aws", Code: "eu-south-1", Name: "Europe (Milan)", Lat: 45.4642, Lon: 9.1900, Kind: KindRegion},
	{Provider: "aws", Code: "eu-south-2", Name: "Europe (Spain)", Lat: 40.4168, Lon: -3.7038, Kind: KindRegion},
	{Provider: "aws", Code: "ap-south-1", Name: "Asia Pacific (Mumbai)", Lat: 19.0760, Lon: 72.8777, Kind: KindRegion},
	{Provider: "aws", Code: "ap-south-2", Name: "Asia Pacific (Hyderabad)", Lat: 17.3850, Lon: 78.4867, Kind: KindRegion},
	{Provider: "aws", Code: "ap-northeast-1", Name: "Asia Pacific (Tokyo)", Lat: 35.6762, Lon: 139.6503, Kind: KindRegion},
	{Provider: "aws", Code: "ap-northeast-2", Name: "Asia Pacific (Seoul)", Lat: 37.5665, Lon: 126.9780, Kind: KindRegion},
	{Provider: "aws", Code: "ap-northeast-3", Name: "Asia Pacific (Osaka)", Lat: 34.6937, Lon: 135.5023, Kind: KindRegion},
	{Provider: "aws", Code: "ap-southeast-1", Name: "Asia Pacific (Singapore)", Lat: 1.3521, Lon: 103.8198, Kind: KindRegion},
	{Provider: "aws", Code: "ap-southeast-2", Name: "Asia Pacific (Sydney)", Lat: -33.8688, Lon: 151.2093, Kind: KindRegion},
	{Provider: "aws", Code: "ap-southeast-3", Name: "Asia Pacific (Jakarta)", Lat: -6.2088, Lon: 106.8456, Kind: KindRegion},
	{Provider: "aws", Code: "ap-southeast-4", Name: "Asia Pacific (Melbourne)", Lat: -37.8136, Lon: 144.9631, Kind: KindRegion},
	{Provider: "aws", Code: "ap-southeast-5", Name: "Asia Pacific (Malaysia)", Lat: 3.1390, Lon: 101.6869, Kind: KindRegion},
	{Provider: "aws", Code: "ap-east-1", Name: "Asia Pacific (Hong Kong)", Lat: 22.3193, Lon: 114.1694, Kind: KindRegion},
	{Provider: "aws", Code: "me-south-1", Name: "Middle East (Bahrain)", Lat: 26.0667, Lon: 50.5577, Kind: KindRegion},
	{Provider: "aws", Code: "me-central-1", Name: "Middle East (UAE)", Lat: 24.4539, Lon: 54.3773, Kind: KindRegion},
	{Provider: "aws", Code: "il-central-1", Name: "Israel (Tel Aviv)", Lat: 32.0853, Lon: 34.7818, Kind: KindRegion},
	{Provider: "aws", Code: "af-south-1", Name: "Africa (Cape Town)", Lat: -33.9249, Lon: 18.4241, Kind: KindRegion},

	// A representative sample of Local Zones -- AWS has many more than are
	// listed here (see the package doc comment).
	{Provider: "aws", Code: "us-east-1-bos-1", Name: "Boston Local Zone", Lat: 42.3601, Lon: -71.0589, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-mia-1", Name: "Miami Local Zone", Lat: 25.7617, Lon: -80.1918, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-atl-1", Name: "Atlanta Local Zone", Lat: 33.7490, Lon: -84.3880, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-chi-1", Name: "Chicago Local Zone", Lat: 41.8781, Lon: -87.6298, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-nyc-1", Name: "New York City Local Zone", Lat: 40.7128, Lon: -74.0060, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-phl-1", Name: "Philadelphia Local Zone", Lat: 39.9526, Lon: -75.1652, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-dfw-1", Name: "Dallas Local Zone", Lat: 32.7767, Lon: -96.7970, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-mci-1", Name: "Kansas City Local Zone", Lat: 39.0997, Lon: -94.5786, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-east-1-msp-1", Name: "Minneapolis Local Zone", Lat: 44.9778, Lon: -93.2650, Kind: KindLocalZone, ParentRegion: "us-east-1"},
	{Provider: "aws", Code: "us-west-2-sea-1", Name: "Seattle Local Zone", Lat: 47.6062, Lon: -122.3321, Kind: KindLocalZone, ParentRegion: "us-west-2"},
	{Provider: "aws", Code: "us-west-2-lax-1", Name: "Los Angeles Local Zone", Lat: 34.0522, Lon: -118.2437, Kind: KindLocalZone, ParentRegion: "us-west-2"},
	{Provider: "aws", Code: "us-west-2-las-1", Name: "Las Vegas Local Zone", Lat: 36.1699, Lon: -115.1398, Kind: KindLocalZone, ParentRegion: "us-west-2"},
	{Provider: "aws", Code: "us-west-2-phx-1", Name: "Phoenix Local Zone", Lat: 33.4484, Lon: -112.0740, Kind: KindLocalZone, ParentRegion: "us-west-2"},
	{Provider: "aws", Code: "us-west-2-den-1", Name: "Denver Local Zone", Lat: 39.7392, Lon: -104.9903, Kind: KindLocalZone, ParentRegion: "us-west-2"},
	{Provider: "aws", Code: "us-west-2-hnl-1", Name: "Honolulu Local Zone", Lat: 21.3069, Lon: -157.8583, Kind: KindLocalZone, ParentRegion: "us-west-2"},
}
