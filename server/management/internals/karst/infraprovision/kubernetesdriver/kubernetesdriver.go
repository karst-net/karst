// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package kubernetesdriver is the infraprovision.Driver implementation
// backing a Kubernetes infrastructure connection (ADR-0067). Unlike
// awsdriver (a direct port of an existing Rust driver) or nomaddriver
// (dispatching a pre-registered job an operator already authored), there
// is no existing single-instance Kubernetes actuator to port from --
// bins/karst-scaler-k8s's own K8sDriver manages a StatefulSet's ordinal
// pods for the separate continuous pool autoscaler (ADR-0045 §7 Phase 2),
// a pool shape ADR-0067's "Alternatives rejected" already declined to
// force onto estavellealloc's one-named-allocation semantics a second time.
// This package instead creates one bare Pod per allocation directly,
// the same relationship awsdriver's RunInstances call has to AWS: Karst
// builds the resource from LaunchDefaults, rather than dispatching
// against something an operator pre-registered.
package kubernetesdriver

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// poolLabelKey/tlsServerNameAnnotationKey are this driver's own correlation
// scheme -- unlike awsdriver's tag keys, these do not need to match
// anything outside this package, since there is no sibling Rust actuator
// sharing the same Kubernetes cluster. A label (not an annotation) carries
// the allocation ID so Create can find a live pod by label selector; the
// TLS server name lives in an annotation because it can be longer and
// contain characters (dots) a label value does not reliably allow.
const (
	poolLabelKey               = "karst.io/pool"
	tlsServerNameAnnotationKey = "karst.io/tls-server-name"
	tlsServerNameSuffix        = "k8s.karst.internal"
)

// drainTimeout/drainPollInterval mirror awsdriver's own constants in
// spirit -- a pod's own termination (container runtime teardown, kubelet
// status propagation) is typically faster than an EC2 stop, but still not
// instant, and this must not hang estavellealloc's whole reconciliation tick.
const (
	drainTimeout      = 30 * time.Second
	drainPollInterval = 2 * time.Second
)

// LaunchDefaults is the Kubernetes Pod shape this driver actuates every
// Create against -- infraconnections converts its own Account fields into
// this before constructing a Driver, so this package never imports
// infraconnections (it holds credentials; this package must not).
// Namespace is not part of this struct: like AWS's region, it scopes the
// client itself (see New), not the launched resource's own shape.
// CPU/Memory are parsed with Kubernetes's own resource.Quantity syntax
// (e.g. "250m", "256Mi") and used as both the container's request and its
// limit -- Guaranteed QoS, the closest Kubernetes analog to AWS's fixed
// instance-type shape, which likewise offers no separate request/limit
// knob.
type LaunchDefaults struct {
	Image          string
	CPU            string
	Memory         string
	ServiceAccount string
}

// podsAPI is the handful of Pods calls this driver makes, narrowed so
// tests can supply a fake instead of a real client-go PodInterface -- the
// same "narrow interface, fake it" pattern awsdriver's ec2API and
// nomaddriver's jobsAPI already use. The *kubernetes.Clientset's own
// CoreV1().Pods(namespace) return value satisfies this directly.
type podsAPI interface {
	Create(ctx context.Context, pod *corev1.Pod, opts metav1.CreateOptions) (*corev1.Pod, error)
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Pod, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// Driver implements infraprovision.Driver against one namespace-scoped
// Pods client and one connection's own launch defaults.
type Driver struct {
	pods     podsAPI
	defaults LaunchDefaults
}

// New builds a Driver from a ready *kubernetes.Clientset -- infraconnections
// owns building that client (parsing the stored kubeconfig) from its own
// decrypted secret; this package only ever actuates against one already
// configured, scoped to namespace up front.
func New(client *kubernetes.Clientset, namespace string, defaults LaunchDefaults) *Driver {
	return &Driver{pods: client.CoreV1().Pods(namespace), defaults: defaults}
}

var _ infraprovision.Driver = (*Driver)(nil)

// podName is deterministic from allocationID. Unlike awsdriver/nomaddriver,
// where the instance/job ID is provider-generated and found back by
// listing and filtering on a tag/meta value, a Kubernetes Pod's name is
// caller-chosen -- so this driver skips the list-then-filter dance
// entirely and just reads the name it would have created. Embedding
// allocationID directly is safe: it is always an xid
// (estavellealloc.Store.Create's xid.New().String()), lowercase alphanumeric
// and well within the 253-character DNS-subdomain limit.
func podName(allocationID string) string {
	return "karst-estavelle-" + allocationID
}

func (d *Driver) buildPod(name, allocationID, tlsServerName string, req infraprovision.CreateRequest) (*corev1.Pod, error) {
	var resources corev1.ResourceRequirements
	if d.defaults.CPU != "" || d.defaults.Memory != "" {
		list := corev1.ResourceList{}
		if d.defaults.CPU != "" {
			q, err := resource.ParseQuantity(d.defaults.CPU)
			if err != nil {
				return nil, fmt.Errorf("parse cpu %q: %w", d.defaults.CPU, err)
			}
			list[corev1.ResourceCPU] = q
		}
		if d.defaults.Memory != "" {
			q, err := resource.ParseQuantity(d.defaults.Memory)
			if err != nil {
				return nil, fmt.Errorf("parse memory %q: %w", d.defaults.Memory, err)
			}
			list[corev1.ResourceMemory] = q
		}
		resources.Requests, resources.Limits = list, list
	}
	// The three KARST_* env vars are this driver's own enroll-bundle
	// convention, the Kubernetes analog of awsdriver's UserData TOML and
	// nomaddriver's dispatch Meta: there is no pre-existing image to stay
	// wire-compatible with (see the package doc comment), so a prebuilt
	// karst-relay container image's own entrypoint is expected to read
	// these three and call `karst-relay enroll` itself, the same
	// responsibility an AWS AMI's cloud-init script or a Nomad job
	// template already carries for the other two drivers.
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{poolLabelKey: allocationID},
			Annotations: map[string]string{tlsServerNameAnnotationKey: tlsServerName},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:      corev1.RestartPolicyNever,
			ServiceAccountName: d.defaults.ServiceAccount,
			Containers: []corev1.Container{{
				Name:  "karst-relay",
				Image: d.defaults.Image,
				Env: []corev1.EnvVar{
					{Name: "KARST_CONTROL_API_BASE", Value: req.ControlAPIBase},
					{Name: "KARST_ENROLL_TOKEN", Value: req.Token},
					{Name: "KARST_TLS_SERVER_NAME", Value: tlsServerName},
				},
				Resources: resources,
			}},
		},
	}, nil
}

// Create looks up podName(allocationID) directly -- a crash or restart
// between a successful Create and the caller's own record of it must not
// launch a second pod for the same allocation on retry, the same
// crash-safety awsdriver's describeLiveInstanceByPool and nomaddriver's
// describeLiveByAllocation provide by listing, which this driver gets for
// free from a deterministic name instead.
func (d *Driver) Create(ctx context.Context, allocationID string, req infraprovision.CreateRequest) (infraprovision.Instance, error) {
	name := podName(allocationID)
	if existing, err := d.pods.Get(ctx, name, metav1.GetOptions{}); err == nil {
		return infraprovision.Instance{ID: existing.Name, TLSServerName: existing.Annotations[tlsServerNameAnnotationKey]}, nil
	} else if !k8serrors.IsNotFound(err) {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("get pod: %s", err)}
	}
	tlsServerName := infraprovision.TLSServerNameFor(allocationID, req.Token, tlsServerNameSuffix)
	pod, err := d.buildPod(name, allocationID, tlsServerName, req)
	if err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: err.Error()}
	}
	created, err := d.pods.Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return infraprovision.Instance{}, &infraprovision.DriverError{Msg: fmt.Sprintf("create pod: %s", err)}
	}
	return infraprovision.Instance{ID: created.Name, TLSServerName: tlsServerName}, nil
}

// TLSServerName reads back the pod's own annotation -- nothing in this
// process persists it itself (the token it was derived from is discarded
// right after Create returns), so the cluster, via this annotation, is the
// only durable store for it, surviving a control-server restart. A pod
// that no longer exists returns "", nil ("not yet"/"gone"), matching the
// interface's own documented contract rather than an error -- a caller
// mid-Drain/Destroy may legitimately see this.
func (d *Driver) TLSServerName(ctx context.Context, instanceID string) (string, error) {
	pod, err := d.pods.Get(ctx, instanceID, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return "", nil
		}
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("get pod: %s", err)}
	}
	return pod.Annotations[tlsServerNameAnnotationKey], nil
}

// Drain: delete (default grace period sends SIGTERM, which karst-relay's
// own shutdown handling already uses to flush and announce a restart) then
// poll until the pod is actually gone or drainTimeout elapses.
func (d *Driver) Drain(ctx context.Context, instanceID string) error {
	if err := d.pods.Delete(ctx, instanceID, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
		return &infraprovision.DriverError{Msg: fmt.Sprintf("delete pod: %s", err)}
	}
	deadline := time.Now().Add(drainTimeout)
	for {
		_, err := d.pods.Get(ctx, instanceID, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return nil
			}
			return &infraprovision.DriverError{Msg: fmt.Sprintf("get pod: %s", err)}
		}
		if time.Now().After(deadline) {
			return &infraprovision.DriverError{Msg: fmt.Sprintf("pod %s did not terminate within %s", instanceID, drainTimeout)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainPollInterval):
		}
	}
}

// Destroy reads the tls-server-name annotation back while the pod still
// fully exists, *then* deletes -- the same read-before-terminate ordering
// awsdriver's Destroy and nomaddriver's Destroy both use, so a caller can
// still deenroll the matching estavellereg row by name after this returns.
func (d *Driver) Destroy(ctx context.Context, instanceID string) (string, error) {
	tlsServerName, err := d.TLSServerName(ctx, instanceID)
	if err != nil {
		return "", err
	}
	if err := d.pods.Delete(ctx, instanceID, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
		return "", &infraprovision.DriverError{Msg: fmt.Sprintf("delete pod: %s", err)}
	}
	return tlsServerName, nil
}
