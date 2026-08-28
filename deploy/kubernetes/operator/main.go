// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// karst-operator is deliberately small and uses the Kubernetes REST API
// directly. It has no transitive controller framework to keep in the image;
// its RBAC scope is limited to KarstNode resources and the DaemonSets it owns.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	pollInterval      = 15 * time.Second
)

type karstNodeList struct {
	Items []karstNode `json:"items"`
}

type karstNode struct {
	Metadata struct {
		Name              string `json:"name"`
		Namespace         string `json:"namespace"`
		UID               string `json:"uid"`
		DeletionTimestamp string `json:"deletionTimestamp"`
	} `json:"metadata"`
	Spec struct {
		Image        string            `json:"image"`
		ConfigSecret configSecret      `json:"configSecret"`
		NodeSelector map[string]string `json:"nodeSelector"`
	} `json:"spec"`
}

type configSecret struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type kubeClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func main() {
	namespace := os.Getenv("WATCH_NAMESPACE")
	if namespace == "" {
		log.Fatal("WATCH_NAMESPACE must name the namespace to reconcile")
	}
	client, err := inClusterClient()
	if err != nil {
		log.Fatalf("configure Kubernetes client: %v", err)
	}

	for {
		if err := reconcileAll(context.Background(), client, namespace); err != nil {
			log.Printf("reconciliation failed: %v", err)
		}
		time.Sleep(pollInterval)
	}
}

func inClusterClient() (*kubeClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if host == "" || port == "" {
		return nil, fmt.Errorf("Kubernetes service environment is unavailable")
	}
	token, err := os.ReadFile(filepath.Join(serviceAccountDir, "token"))
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("service-account CA contains no certificates")
	}
	return &kubeClient{
		baseURL: "https://" + host + ":" + port,
		token:   strings.TrimSpace(string(token)),
		http:    &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}},
	}, nil
}

func reconcileAll(ctx context.Context, client *kubeClient, namespace string) error {
	var list karstNodeList
	path := "/apis/karst.io/v1alpha1/namespaces/" + namespace + "/karstnodes"
	if err := client.request(ctx, http.MethodGet, path, nil, &list); err != nil {
		return err
	}
	for _, node := range list.Items {
		if node.Metadata.DeletionTimestamp != "" {
			continue
		}
		if err := validate(node); err != nil {
			log.Printf("KarstNode %s: %v", node.Metadata.Name, err)
			continue
		}
		if err := reconcileDaemonSet(ctx, client, node); err != nil {
			log.Printf("KarstNode %s: %v", node.Metadata.Name, err)
		}
	}
	return nil
}

func validate(node karstNode) error {
	if node.Metadata.Name == "" || node.Spec.Image == "" || node.Spec.ConfigSecret.Name == "" {
		return fmt.Errorf("spec.image and spec.configSecret.name are required")
	}
	return nil
}

func reconcileDaemonSet(ctx context.Context, client *kubeClient, node karstNode) error {
	body, err := json.Marshal(daemonSet(node))
	if err != nil {
		return err
	}
	path := "/apis/apps/v1/namespaces/" + node.Metadata.Namespace + "/daemonsets/" + node.Metadata.Name
	var existing map[string]any
	err = client.request(ctx, http.MethodGet, path, nil, &existing)
	if isNotFound(err) {
		path = "/apis/apps/v1/namespaces/" + node.Metadata.Namespace + "/daemonsets"
		var ignored json.RawMessage
		return client.request(ctx, http.MethodPost, path, body, &ignored)
	}
	if err != nil {
		return err
	}
	metadata, ok := existing["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("existing DaemonSet has no metadata")
	}
	resourceVersion, ok := metadata["resourceVersion"].(string)
	if !ok || resourceVersion == "" {
		return fmt.Errorf("existing DaemonSet has no resourceVersion")
	}
	desired := daemonSet(node)
	desired["metadata"].(map[string]any)["resourceVersion"] = resourceVersion
	body, err = json.Marshal(desired)
	if err != nil {
		return err
	}
	var ignored json.RawMessage
	return client.request(ctx, http.MethodPut, path, body, &ignored)
}

// daemonSet is deliberately constructed rather than templated: all
// privilege-bearing fields are reviewable in one place.
func daemonSet(node karstNode) map[string]any {
	key := node.Spec.ConfigSecret.Key
	if key == "" {
		key = "karstd.toml"
	}
	labels := map[string]any{"app.kubernetes.io/name": "karstd", "app.kubernetes.io/instance": node.Metadata.Name}
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "DaemonSet",
		"metadata": map[string]any{"name": node.Metadata.Name, "namespace": node.Metadata.Namespace, "labels": labels,
			"ownerReferences": []any{map[string]any{"apiVersion": "karst.io/v1alpha1", "kind": "KarstNode", "name": node.Metadata.Name, "uid": node.Metadata.UID, "controller": true}}},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": labels},
			"template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{
				"hostNetwork": true, "dnsPolicy": "ClusterFirstWithHostNet", "nodeSelector": node.Spec.NodeSelector,
				"containers": []any{map[string]any{
					"name": "karstd", "image": node.Spec.Image, "imagePullPolicy": "IfNotPresent",
					"args": []any{"--config", "/etc/karst/" + key},
					"securityContext": map[string]any{"privileged": true, "allowPrivilegeEscalation": true,
						"capabilities": map[string]any{"add": []any{"NET_ADMIN"}}},
					"volumeMounts": []any{map[string]any{"name": "config", "mountPath": "/etc/karst", "readOnly": true}, map[string]any{"name": "tun", "mountPath": "/dev/net/tun"}},
				}},
				"volumes": []any{map[string]any{"name": "config", "secret": map[string]any{"secretName": node.Spec.ConfigSecret.Name, "defaultMode": 256}}, map[string]any{"name": "tun", "hostPath": map[string]any{"path": "/dev/net/tun", "type": "CharDevice"}}},
			}},
		},
	}
}

func (c *kubeClient) request(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return &apiError{status: response.StatusCode, message: strings.TrimSpace(string(message))}
	}
	if out != nil {
		return json.NewDecoder(response.Body).Decode(out)
	}
	return nil
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("Kubernetes API returned %d: %s", e.status, e.message)
}

func isNotFound(err error) bool {
	e, ok := err.(*apiError)
	return ok && e.status == http.StatusNotFound
}
