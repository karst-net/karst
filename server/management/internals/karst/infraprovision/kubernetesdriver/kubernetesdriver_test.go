// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package kubernetesdriver

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/netbirdio/netbird/management/internals/karst/infraprovision"
)

// fakePods is a hand-rolled, in-memory stand-in for the handful of Pods
// calls this driver makes -- satisfies podsAPI, so tests never need a real
// cluster.
type fakePods struct {
	pods        map[string]*corev1.Pod
	createErr   error
	createCalls int
}

func newFakePods() *fakePods { return &fakePods{pods: map[string]*corev1.Pod{}} }

func notFound(name string) error {
	return k8serrors.NewNotFound(schema.GroupResource{Resource: "pods"}, name)
}

func (f *fakePods) Create(_ context.Context, pod *corev1.Pod, _ metav1.CreateOptions) (*corev1.Pod, error) {
	f.createCalls++
	if f.createErr != nil {
		return nil, f.createErr
	}
	if _, exists := f.pods[pod.Name]; exists {
		return nil, k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "pods"}, pod.Name)
	}
	f.pods[pod.Name] = pod
	return pod, nil
}

func (f *fakePods) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.Pod, error) {
	pod, ok := f.pods[name]
	if !ok {
		return nil, notFound(name)
	}
	return pod, nil
}

func (f *fakePods) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	if _, ok := f.pods[name]; !ok {
		return notFound(name)
	}
	delete(f.pods, name)
	return nil
}

func testDriver(pods podsAPI) *Driver {
	return &Driver{pods: pods, defaults: LaunchDefaults{Image: "ghcr.io/karst-net/karst-relay:dev", CPU: "250m", Memory: "256Mi"}}
}

func TestCreateLaunchesOnceAndFindsExistingOnRetry(t *testing.T) {
	fake := newFakePods()
	d := testDriver(fake)
	ctx := context.Background()
	req := infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-1"}

	first, err := d.Create(ctx, "alloc1", req)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if first.ID == "" || first.TLSServerName == "" {
		t.Fatalf("got %+v, want a populated instance", first)
	}
	if fake.createCalls != 1 {
		t.Fatalf("got %d Create calls, want exactly 1", fake.createCalls)
	}
	if got := fake.pods[first.ID].Labels[poolLabelKey]; got != "alloc1" {
		t.Fatalf("got pool label %q, want the allocation ID", got)
	}

	second, err := d.Create(ctx, "alloc1", req)
	if err != nil {
		t.Fatalf("second create (retry): %v", err)
	}
	if second != first {
		t.Fatalf("got %+v on retry, want the same already-live instance %+v", second, first)
	}
	if fake.createCalls != 1 {
		t.Fatalf("got %d Create calls after a retry, want still exactly 1 (find-before-create)", fake.createCalls)
	}
}

func TestDestroyReadsAnnotationBeforeDeleting(t *testing.T) {
	fake := newFakePods()
	d := testDriver(fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc2", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-2"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	name, err := d.Destroy(ctx, created.ID)
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if name != created.TLSServerName {
		t.Fatalf("got tls server name %q, want %q", name, created.TLSServerName)
	}
	if _, ok := fake.pods[created.ID]; ok {
		t.Fatalf("pod %s still present after Destroy", created.ID)
	}
}

func TestDrainDeletesAndWaitsForDisappearance(t *testing.T) {
	fake := newFakePods()
	d := testDriver(fake)
	ctx := context.Background()

	created, err := d.Create(ctx, "alloc3", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-3"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.Drain(ctx, created.ID); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if _, ok := fake.pods[created.ID]; ok {
		t.Fatalf("pod %s still present after Drain", created.ID)
	}
}

func TestCreatePropagatesACreateFailure(t *testing.T) {
	fake := newFakePods()
	fake.createErr = fmt.Errorf("admission webhook denied the request")
	d := testDriver(fake)

	if _, err := d.Create(context.Background(), "alloc4", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-4"}); err == nil {
		t.Fatal("got nil error, want the underlying Create failure surfaced")
	}
}

func TestTLSServerNameOfAnUnknownPodIsNotAnError(t *testing.T) {
	d := testDriver(newFakePods())
	name, err := d.TLSServerName(context.Background(), "karst-estavelle-unknown")
	if err != nil {
		t.Fatalf("got error %v, want nil (not-yet-discoverable is not a failure)", err)
	}
	if name != "" {
		t.Fatalf("got %q, want empty", name)
	}
}

func TestCreateRejectsAnUnparseableResourceQuantity(t *testing.T) {
	fake := newFakePods()
	d := &Driver{pods: fake, defaults: LaunchDefaults{Image: "ghcr.io/karst-net/karst-relay:dev", CPU: "not-a-quantity"}}
	if _, err := d.Create(context.Background(), "alloc5", infraprovision.CreateRequest{ControlAPIBase: "https://control.example", Token: "tok-5"}); err == nil {
		t.Fatal("got nil error, want the bad cpu quantity surfaced")
	}
	if fake.createCalls != 0 {
		t.Fatalf("got %d Create calls, want 0 (parsing fails before the API call)", fake.createCalls)
	}
}
