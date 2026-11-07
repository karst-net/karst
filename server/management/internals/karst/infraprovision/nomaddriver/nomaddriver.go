// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package nomaddriver is the infraprovision.Driver implementation backing
// a Nomad infrastructure connection (ADR-0063; ADR-0067). It is the first
// code in this repository to call Nomad's job-dispatch API at all --
// infraconnections/nomad.go's existing discoverNomad only lists nodes for
// read-only discovery. It dispatches a pre-registered, parameterized
// Nomad job the operator authors and registers themselves (this package
// never registers or edits a job definition, only dispatches instances of
// one that already exists) -- the Nomad analog of AWS's AMI/instance
// type/subnet/security groups: a launch shape set once on the connection,
// never supplied per allocation request.
//
// Not independently verified against a real Nomad cluster in this
// environment -- the same caveat awsdriver's own port of
// bins/karst-scaler-aws's logic already carries for EC2.
package nomaddriver

import (
	"context"
	"fmt"
	"time"

	nomadapi "github.com/hashicorp/nomad/api"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

const tlsServerNameSuffix = "nomad.karst.internal"

// allocationIDMetaKey/tlsServerNameMetaKey are this driver's own
// dispatch-Meta keys, the Nomad analog of awsdriver's EC2 tags
// (karst:pool/karst:tls-server-name) -- Nomad job dispatch has no tagging
// concept of its own, so correlation data travels as Meta instead, read
// back the same way on every call rather than cached in this process (see
// Create's own doc comment).
const (
	allocationIDMetaKey   = "allocation_id"
	controlAPIBaseMetaKey = "control_api_base"
	tokenMetaKey          = "token"
	tlsServerNameMetaKey  = "tls_server_name"
	datacenterMetaKey     = "datacenter"
)

// drainTimeout/drainPollInterval mirror awsdriver's own values -- Nomad
// gives no stronger guarantee about how quickly a deregistered job's
// allocations actually stop than EC2 gives about a guest OS shutdown, so
// there is no principled reason to pick a different bound here.
const (
	drainTimeout      = 120 * time.Second
	drainPollInterval = 5 * time.Second
)

// jobsAPI is the handful of Nomad Jobs calls this driver makes, narrowed
// so tests can supply a fake instead of a real *nomadapi.Client -- the
// same pattern awsdriver's own ec2API interface uses. *nomadapi.Jobs
// (returned by (*nomadapi.Client).Jobs()) satisfies this directly.
type jobsAPI interface {
	ListOptions(opts *nomadapi.JobListOptions, q *nomadapi.QueryOptions) ([]*nomadapi.JobListStub, *nomadapi.QueryMeta, error)
	Info(jobID string, q *nomadapi.QueryOptions) (*nomadapi.Job, *nomadapi.QueryMeta, error)
	Dispatch(jobID string, meta map[string]string, payload []byte, idPrefixTemplate string, q *nomadapi.WriteOptions) (*nomadapi.JobDispatchResponse, *nomadapi.WriteMeta, error)
	Deregister(jobID string, purge bool, q *nomadapi.WriteOptions) (string, *nomadapi.WriteMeta, error)
}

// Driver implements infraprovision.Driver against one Nomad client and
// one connection's own launch defaults: jobID is the pre-registered
// parameterized job to dispatch; datacenter, if set, is passed through as
// dispatch Meta for the operator's own job template to act on (Nomad job
// dispatch does not let a caller override the parent job's own
// Datacenters list directly).
type Driver struct {
	jobs       jobsAPI
	jobID      string
	datacenter string
}

// New builds a Driver from a ready *nomadapi.Client -- infraconnections
// owns building that client from its own decrypted secret; this package
// only ever actuates against one already configured.
func New(client *nomadapi.Client, jobID, datacenter string) *Driver {
	return &Driver{jobs: client.Jobs(), jobID: jobID, datacenter: datacenter}
}

var _ infraprovision.Driver = (*Driver)(nil)

// describeLiveByAllocation looks up an already-dispatched, not-yet-dead
// child of jobID carrying allocationIDMetaKey == allocationID -- the
// Nomad analog of awsdriver's describeLiveInstanceByPool: a tick that
// crashes or restarts between a successful Dispatch and the caller's own
// record of it must not dispatch a second instance for the same
// allocation on retry. Fields.Meta=true is required for List to return
// each stub's Meta at all -- without it every stub's Meta is nil.
func (d *Driver) describeLiveByAllocation(ctx context.Context, allocationID string) (jobID, tlsServerName string, err error) {
	stubs, _, err := d.jobs.ListOptions(
		&nomadapi.JobListOptions{Fields: &nomadapi.JobListFields{Meta: true}},
		(&nomadapi.QueryOptions{}).WithContext(ctx),
	)
	if err != nil {
		return "", "", fmt.Errorf("list jobs: %w", err)
	}
	for _, stub := range stubs {
		if stub.ParentID != d.jobID || stub.Meta[allocationIDMetaKey] != allocationID {
			continue
		}
		if stub.Status == "dead" {
			continue // already torn down -- do not resurrect a finished dispatch
		}
		return stub.ID, stub.Meta[tlsServerNameMetaKey], nil
	}
	return "", "", nil
}

// Create dispatches one instance of jobID, called only after
// describeLiveByAllocation has confirmed nothing live exists for
// allocationID. allocation_id/control_api_base/token/tls_server_name
// travel as dispatch Meta -- the operator's own job template reads them
// via NOMAD_META_* and passes them into karst-relay enroll, the Nomad
// analog of AWS's base64 UserData TOML bundle.
func (d *Driver) Create(ctx context.Context, allocationID string, req infraprovision.CreateRequest) (infraprovision.Instance, error) {
	jobID, tlsServerName, err := d.describeLiveByAllocation(ctx, allocationID)
	if err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: err.Error()}
	}
	if jobID != "" {
		return infraprovision.Instance{ID: jobID, TLSServerName: tlsServerName}, nil
	}
	name := infraprovision.TLSServerNameFor(allocationID, req.Token, tlsServerNameSuffix)
	meta := map[string]string{
		allocationIDMetaKey:   allocationID,
		controlAPIBaseMetaKey: req.ControlAPIBase,
		tokenMetaKey:          req.Token,
		tlsServerNameMetaKey:  name,
	}
	if d.datacenter != "" {
		meta[datacenterMetaKey] = d.datacenter
	}
	resp, _, err := d.jobs.Dispatch(d.jobID, meta, nil, "", (&nomadapi.WriteOptions{}).WithContext(ctx))
	if err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("dispatch job: %s", err)}
	}
	if resp == nil || resp.DispatchedJobID == "" {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("allocation %s: job dispatch returned no job id", allocationID)}
	}
	return infraprovision.Instance{ID: resp.DispatchedJobID, TLSServerName: name}, nil
}

// TLSServerName reads back one dispatched job's own tlsServerNameMetaKey
// Meta entry -- nothing in this process persists it itself (the token it
// was derived from is discarded right after Create returns), so Nomad,
// via this Meta, is the only durable store for it, surviving a
// control-server restart.
func (d *Driver) TLSServerName(ctx context.Context, instanceID string) (string, error) {
	job, _, err := d.jobs.Info(instanceID, (&nomadapi.QueryOptions{}).WithContext(ctx))
	if err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("job info: %s", err)}
	}
	if job == nil {
		return "", nil
	}
	return job.Meta[tlsServerNameMetaKey], nil
}

// Drain deregisters instanceID without purging (Nomad's closest analog to
// EC2 StopInstances -- the job stops taking work but its history is kept)
// then polls until its status reaches "dead" or drainTimeout elapses.
func (d *Driver) Drain(ctx context.Context, instanceID string) error {
	if _, _, err := d.jobs.Deregister(instanceID, false, (&nomadapi.WriteOptions{}).WithContext(ctx)); err != nil {
		return &infraprovision.DriverError{Msg: fmt.Sprintf("deregister job: %s", err)}
	}
	deadline := time.Now().Add(drainTimeout)
	for {
		job, _, err := d.jobs.Info(instanceID, (&nomadapi.QueryOptions{}).WithContext(ctx))
		if err != nil {
			return &infraprovision.DriverError{Msg: fmt.Sprintf("job info: %s", err)}
		}
		if job != nil && job.Status != nil && *job.Status == "dead" {
			return nil
		}
		if time.Now().After(deadline) {
			return &infraprovision.DriverError{Msg: fmt.Sprintf("job %s did not reach dead within %s", instanceID, drainTimeout)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainPollInterval):
		}
	}
}

// Destroy reads the tls_server_name Meta entry back while the job still
// fully exists, *then* deregisters with purge=true -- parity with
// awsdriver's own Destroy, which reads its EC2 tag before terminating for
// the same reason: avoid depending on whatever retention window the
// provider gives a torn-down resource's own metadata.
func (d *Driver) Destroy(ctx context.Context, instanceID string) (string, error) {
	job, _, err := d.jobs.Info(instanceID, (&nomadapi.QueryOptions{}).WithContext(ctx))
	if err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("job info: %s", err)}
	}
	var tlsServerName string
	if job != nil {
		tlsServerName = job.Meta[tlsServerNameMetaKey]
	}
	if _, _, err := d.jobs.Deregister(instanceID, true, (&nomadapi.WriteOptions{}).WithContext(ctx)); err != nil {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("deregister job: %s", err)}
	}
	return tlsServerName, nil
}
