// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package infraconnections

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/netbirdio/netbird/management/internals/karst/cloudcatalog"
)

// kubernetesSecret is the admin-entered credential shape for Type
// "kubernetes" -- a pasted kubeconfig, the same "paste the exact file
// contents" UX this package already uses for a GCP service account key.
//
// Only the kubeconfig's current-context cluster/user/namespace is used;
// every other context in a multi-context kubeconfig is ignored. A
// kubeconfig whose user block authenticates via an exec plugin (e.g. a
// cloud provider's own "get-token" credential helper, as EKS/GKE/AKS's
// generated kubeconfigs commonly do) is accepted at validation time -- it
// is not rejected here -- but may fail later at Discover if the plugin
// binary is not present in the management server's environment or the
// token it mints has since expired with no refresh path configured; this
// is a known Phase 1 limitation, not a bug.
type kubernetesSecret struct {
	Kubeconfig string `json:"kubeconfig"`
}

func validateKubernetesSecret(raw []byte) error {
	var s kubernetesSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("kubernetes secret: %w", err)
	}
	if s.Kubeconfig == "" {
		return fmt.Errorf("kubernetes secret: kubeconfig is required")
	}
	cfg, err := clientcmd.Load([]byte(s.Kubeconfig))
	if err != nil {
		return fmt.Errorf("kubernetes secret: invalid kubeconfig: %w", err)
	}
	if cfg.CurrentContext == "" {
		return fmt.Errorf("kubernetes secret: kubeconfig has no current-context")
	}
	return nil
}

// discoverKubernetes proves the stored kubeconfig is reachable
// (Discovery().ServerVersion()) and lists the namespaces the credential's
// RBAC grant can see -- the "permissions" surfaced to the operator. This is
// discovery-only: no workload, secret, configmap, or pod access, and no
// watch/reconcile loop. ModeReadWrite carries no different behavior than
// ModeReadOnly here, the same unbuilt-Phase-2 posture as the AWS/Azure/GCP
// credentials (see the package doc comment's ADR-0045 §6 addenda).
func discoverKubernetes(ctx context.Context, rawSecret string) ([]DiscoveredResource, error) {
	var s kubernetesSecret
	if err := json.Unmarshal([]byte(rawSecret), &s); err != nil {
		return nil, fmt.Errorf("kubernetes secret: %w", err)
	}
	restCfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(s.Kubeconfig))
	if err != nil {
		return nil, fmt.Errorf("kubernetes: build config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: build client: %w", err)
	}
	if _, err := clientset.Discovery().ServerVersion(); err != nil {
		return nil, fmt.Errorf("kubernetes: server version (reachability check): %w", err)
	}
	list, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("kubernetes: list namespaces: %w", err)
	}
	out := make([]DiscoveredResource, 0, len(list.Items))
	for _, ns := range list.Items {
		out = append(out, DiscoveredResource{Code: ns.Name, Kind: cloudcatalog.KindNamespace})
	}
	return out, nil
}
