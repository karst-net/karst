// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/relayusage"
	"github.com/netbirdio/netbird/management/internals/karst/usage"
)

var ErrInvoiceNotFound = errors.New("billing: finalized invoice not found")

// FinalInvoice is an immutable, versioned input snapshot for a future invoice
// or payment workflow. Amounts are minor currency units; exact values retain
// the calculator inputs, while line amounts are truncated down at finalization.
type FinalInvoice struct {
	SchemaVersion   string             `json:"schema_version"`
	AccountID       string             `json:"account_id"`
	PeriodStart     time.Time          `json:"period_start"`
	PeriodEnd       time.Time          `json:"period_end"`
	ScheduleVersion string             `json:"schedule_version"`
	Currency        string             `json:"currency"`
	DeviceUsage     usage.DeviceReport `json:"device_usage"`
	RelayUsage      relayusage.Report  `json:"relay_usage"`
	DeviceInputHash string             `json:"device_input_sha256"`
	RelayInputHash  string             `json:"relay_input_sha256"`
	DeviceExact     ExactAmount        `json:"device_exact_minor"`
	RelayExact      ExactAmount        `json:"relay_exact_minor"`
	TotalExact      ExactAmount        `json:"total_exact_minor"`
	DeviceMinor     int64              `json:"device_minor"`
	RelayMinor      int64              `json:"relay_minor"`
	TotalMinor      int64              `json:"total_minor"`
	FinalizedAt     time.Time          `json:"finalized_at"`
}

func parseExactNonnegative(amount ExactAmount) (*big.Rat, error) {
	numerator, ok := new(big.Int).SetString(amount.Numerator, 10)
	if !ok || numerator.Sign() < 0 || numerator.String() != amount.Numerator {
		return nil, errors.New("billing: invalid exact invoice amount")
	}
	denominator, ok := new(big.Int).SetString(amount.Denominator, 10)
	if !ok || denominator.Sign() <= 0 || denominator.String() != amount.Denominator {
		return nil, errors.New("billing: invalid exact invoice amount")
	}
	amountRat := new(big.Rat).SetFrac(numerator, denominator)
	if amountRat.Num().String() != amount.Numerator || amountRat.Denom().String() != amount.Denominator {
		return nil, errors.New("billing: noncanonical exact invoice amount")
	}
	return amountRat, nil
}

func truncateMinor(amount *big.Rat) (int64, error) {
	if amount == nil || amount.Sign() < 0 {
		return 0, errors.New("billing: invalid exact invoice amount")
	}
	minor := new(big.Int).Quo(amount.Num(), amount.Denom())
	if !minor.IsInt64() {
		return 0, errors.New("billing: invoice line exceeds supported amount")
	}
	return minor.Int64(), nil
}

func sameInvoiceInputs(a, b FinalInvoice) bool {
	return a.SchemaVersion == b.SchemaVersion && a.AccountID == b.AccountID &&
		a.PeriodStart.Equal(b.PeriodStart) && a.PeriodEnd.Equal(b.PeriodEnd) &&
		a.ScheduleVersion == b.ScheduleVersion && a.Currency == b.Currency &&
		a.DeviceInputHash == b.DeviceInputHash && a.RelayInputHash == b.RelayInputHash &&
		a.DeviceExact == b.DeviceExact && a.RelayExact == b.RelayExact && a.TotalExact == b.TotalExact &&
		a.DeviceMinor == b.DeviceMinor && a.RelayMinor == b.RelayMinor && a.TotalMinor == b.TotalMinor
}

func digestJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
