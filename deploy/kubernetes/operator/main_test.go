// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

package main

import "testing"

func TestDaemonSetIsHostNetworkedAndHasTunPrivileges(t *testing.T) {
	var node karstNode
	node.Metadata.Name = "mesh"
	node.Metadata.Namespace = "karst-system"
	node.Metadata.UID = "a-uid"
	node.Spec.Image = "registry.example/karstd:test"
	node.Spec.ConfigSecret = configSecret{Name: "mesh-secret"}

	actual := daemonSet(node)
	spec := actual["spec"].(map[string]any)
	pod := spec["template"].(map[string]any)["spec"].(map[string]any)
	if pod["hostNetwork"] != true {
		t.Fatal("DaemonSet must share the host network namespace")
	}
	container := pod["containers"].([]any)[0].(map[string]any)
	security := container["securityContext"].(map[string]any)
	if security["privileged"] != true {
		t.Fatal("karstd must be privileged")
	}
	capabilities := security["capabilities"].(map[string]any)["add"].([]any)
	if len(capabilities) != 1 || capabilities[0] != "NET_ADMIN" {
		t.Fatalf("unexpected added capabilities: %#v", capabilities)
	}
	volumes := pod["volumes"].([]any)
	if volumes[1].(map[string]any)["hostPath"].(map[string]any)["path"] != "/dev/net/tun" {
		t.Fatal("DaemonSet must mount /dev/net/tun")
	}
	if volumes[0].(map[string]any)["secret"].(map[string]any)["defaultMode"] != 256 {
		t.Fatal("configuration Secret must have mode 0400")
	}
}
