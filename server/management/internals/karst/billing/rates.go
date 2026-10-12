// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

// PilotRateSchedule returns the approved pilot prices as an explicit schedule
// snapshot. Calling this function does not assign the schedule to an account or
// enable billing; callers must opt in and retain the returned version.
func PilotRateSchedule() RateSchedule {
	return RateSchedule{
		Version:            "pilot-2026-10-12-v1",
		Currency:           "USD",
		DeviceTiers:        []DeviceTier{{UpToDevices: 10, MinorPerPeriod: 250}, {UpToDevices: 50, MinorPerPeriod: 150}, {MinorPerPeriod: 75}},
		RelayIncludedBytes: 10_000_000_000,
		RelayUnitBytes:     1_000_000_000,
		RelayMinorPerUnit:  20,
	}
}
