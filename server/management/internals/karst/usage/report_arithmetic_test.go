// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReportDeviceTimeDoesNotOverflowInt64(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(MaxReportWindow)
	report, err := composeReport(start, end, end, 1_000_000_000, nil, []Period{{StartUS: start.UnixMicro(), Complete: true}})
	require.NoError(t, err)
	require.Equal(t, "8035200000000000000000", report.DeviceMicroseconds)
	require.True(t, report.Complete)
}
