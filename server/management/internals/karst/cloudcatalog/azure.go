// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package cloudcatalog

// azure is a representative subset of Azure's public, non-sovereign-cloud
// regions (not exhaustive -- see the package doc comment). Availability
// Zones are not listed individually: Azure does not expose a stable,
// discoverable zone *code* the way AWS does, and the zones that do exist
// (1/2/3) are physically co-located with their parent region, so they carry
// no coordinates of their own in this catalog.
var azure = []Region{
	{Provider: "azure", Code: "eastus", Name: "East US (Virginia)", Lat: 37.3719, Lon: -79.8164, Kind: KindRegion},
	{Provider: "azure", Code: "eastus2", Name: "East US 2 (Virginia)", Lat: 36.6681, Lon: -78.3889, Kind: KindRegion},
	{Provider: "azure", Code: "centralus", Name: "Central US (Iowa)", Lat: 41.5908, Lon: -93.6208, Kind: KindRegion},
	{Provider: "azure", Code: "northcentralus", Name: "North Central US (Illinois)", Lat: 41.8819, Lon: -87.6278, Kind: KindRegion},
	{Provider: "azure", Code: "southcentralus", Name: "South Central US (Texas)", Lat: 29.4167, Lon: -98.5000, Kind: KindRegion},
	{Provider: "azure", Code: "westus", Name: "West US (California)", Lat: 37.7833, Lon: -122.4167, Kind: KindRegion},
	{Provider: "azure", Code: "westus2", Name: "West US 2 (Washington)", Lat: 47.2330, Lon: -119.8520, Kind: KindRegion},
	{Provider: "azure", Code: "westus3", Name: "West US 3 (Arizona)", Lat: 33.4484, Lon: -112.0740, Kind: KindRegion},
	{Provider: "azure", Code: "canadacentral", Name: "Canada Central (Toronto)", Lat: 43.6532, Lon: -79.3832, Kind: KindRegion},
	{Provider: "azure", Code: "canadaeast", Name: "Canada East (Quebec)", Lat: 46.8139, Lon: -71.2080, Kind: KindRegion},
	{Provider: "azure", Code: "brazilsouth", Name: "Brazil South (Sao Paulo)", Lat: -23.5505, Lon: -46.6333, Kind: KindRegion},
	{Provider: "azure", Code: "mexicocentral", Name: "Mexico Central", Lat: 19.4326, Lon: -99.1332, Kind: KindRegion},
	{Provider: "azure", Code: "northeurope", Name: "North Europe (Ireland)", Lat: 53.3498, Lon: -6.2603, Kind: KindRegion},
	{Provider: "azure", Code: "westeurope", Name: "West Europe (Netherlands)", Lat: 52.3667, Lon: 4.9000, Kind: KindRegion},
	{Provider: "azure", Code: "uksouth", Name: "UK South (London)", Lat: 51.5072, Lon: -0.1276, Kind: KindRegion},
	{Provider: "azure", Code: "ukwest", Name: "UK West (Cardiff)", Lat: 51.4816, Lon: -3.1791, Kind: KindRegion},
	{Provider: "azure", Code: "francecentral", Name: "France Central (Paris)", Lat: 48.8566, Lon: 2.3522, Kind: KindRegion},
	{Provider: "azure", Code: "germanywestcentral", Name: "Germany West Central (Frankfurt)", Lat: 50.1109, Lon: 8.6821, Kind: KindRegion},
	{Provider: "azure", Code: "norwayeast", Name: "Norway East (Oslo)", Lat: 59.9139, Lon: 10.7522, Kind: KindRegion},
	{Provider: "azure", Code: "switzerlandnorth", Name: "Switzerland North (Zurich)", Lat: 47.3769, Lon: 8.5417, Kind: KindRegion},
	{Provider: "azure", Code: "swedencentral", Name: "Sweden Central (Gavle)", Lat: 60.6749, Lon: 17.1413, Kind: KindRegion},
	{Provider: "azure", Code: "italynorth", Name: "Italy North (Milan)", Lat: 45.4642, Lon: 9.1900, Kind: KindRegion},
	{Provider: "azure", Code: "polandcentral", Name: "Poland Central (Warsaw)", Lat: 52.2297, Lon: 21.0122, Kind: KindRegion},
	{Provider: "azure", Code: "spaincentral", Name: "Spain Central (Madrid)", Lat: 40.4168, Lon: -3.7038, Kind: KindRegion},
	{Provider: "azure", Code: "uaenorth", Name: "UAE North (Dubai)", Lat: 25.2048, Lon: 55.2708, Kind: KindRegion},
	{Provider: "azure", Code: "israelcentral", Name: "Israel Central", Lat: 32.0853, Lon: 34.7818, Kind: KindRegion},
	{Provider: "azure", Code: "qatarcentral", Name: "Qatar Central (Doha)", Lat: 25.2854, Lon: 51.5310, Kind: KindRegion},
	{Provider: "azure", Code: "southafricanorth", Name: "South Africa North (Johannesburg)", Lat: -26.2041, Lon: 28.0473, Kind: KindRegion},
	{Provider: "azure", Code: "eastasia", Name: "East Asia (Hong Kong)", Lat: 22.3193, Lon: 114.1694, Kind: KindRegion},
	{Provider: "azure", Code: "southeastasia", Name: "Southeast Asia (Singapore)", Lat: 1.3521, Lon: 103.8198, Kind: KindRegion},
	{Provider: "azure", Code: "japaneast", Name: "Japan East (Tokyo)", Lat: 35.6762, Lon: 139.6503, Kind: KindRegion},
	{Provider: "azure", Code: "japanwest", Name: "Japan West (Osaka)", Lat: 34.6937, Lon: 135.5023, Kind: KindRegion},
	{Provider: "azure", Code: "koreacentral", Name: "Korea Central (Seoul)", Lat: 37.5665, Lon: 126.9780, Kind: KindRegion},
	{Provider: "azure", Code: "centralindia", Name: "Central India (Pune)", Lat: 18.5204, Lon: 73.8567, Kind: KindRegion},
	{Provider: "azure", Code: "southindia", Name: "South India (Chennai)", Lat: 13.0827, Lon: 80.2707, Kind: KindRegion},
	{Provider: "azure", Code: "jioindiawest", Name: "Jio India West (Jamnagar)", Lat: 22.4707, Lon: 70.0577, Kind: KindRegion},
	{Provider: "azure", Code: "australiaeast", Name: "Australia East (Sydney)", Lat: -33.8688, Lon: 151.2093, Kind: KindRegion},
	{Provider: "azure", Code: "australiasoutheast", Name: "Australia Southeast (Melbourne)", Lat: -37.8136, Lon: 144.9631, Kind: KindRegion},
	{Provider: "azure", Code: "newzealandnorth", Name: "New Zealand North (Auckland)", Lat: -36.8485, Lon: 174.7633, Kind: KindRegion},
	{Provider: "azure", Code: "indonesiacentral", Name: "Indonesia Central (Jakarta)", Lat: -6.2088, Lon: 106.8456, Kind: KindRegion},
}
