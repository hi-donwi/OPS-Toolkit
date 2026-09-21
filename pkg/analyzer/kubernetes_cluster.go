package analyzer

import (
	"fmt"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// -----------------------------------------------------------------------------
// K8S-NOD-001 — node conditions
// -----------------------------------------------------------------------------

// pressureConditions map a node condition type to what it means when True.
var pressureConditions = map[string]string{
	"MemoryPressure":     "Available memory on the node is below the kubelet's eviction threshold; the kubelet has started evicting pods.",
	"DiskPressure":       "Free disk or inodes on the node are below the eviction threshold; the kubelet is garbage-collecting images and evicting pods.",
	"PIDPressure":        "The node is running out of process IDs; new containers cannot fork.",
	"NetworkUnavailable": "The node's network is not correctly configured; pods on it cannot reach the cluster network.",
}

func evaluateNodes(nodes []node) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, n := range nodes {
		name := n.Metadata.Name

		for _, cond := range n.Status.Conditions {
			// Ready is inverted relative to the pressure conditions: trouble is
			// Ready != True, whereas pressure conditions signal trouble at True.
			if cond.Type == "Ready" {
				if cond.Status == "True" {
					continue
				}
				findings = append(findings, model.Finding{
					ID:          "K8S-NOD-001",
					Title:       fmt.Sprintf("Node Not Ready: %s", name),
					TargetType:  model.TargetKubernetes,
					Category:    "Node Health",
					Resource:    fmt.Sprintf("node/%s", name),
					Severity:    model.SeverityCritical,
					Symptom:     fmt.Sprintf("Node Ready condition is %q (reason: %s).", cond.Status, cond.Reason),
					RootCause:   "The kubelet has stopped reporting healthy status — the kubelet or container runtime is down, or the node lost contact with the control plane. Its pods will be evicted once the toleration window expires.",
					LogEvidence: cond.Message,
					RemedySteps: []string{
						fmt.Sprintf("Read the full condition history: kubectl describe node %s", name),
						"On the node, check the kubelet and runtime: systemctl status kubelet containerd",
					},
					Metadata: map[string]string{"reason": cond.Reason},
				})
				continue
			}

			explanation, tracked := pressureConditions[cond.Type]
			if !tracked || cond.Status != "True" {
				continue
			}

			findings = append(findings, model.Finding{
				ID:          "K8S-NOD-002",
				Title:       fmt.Sprintf("Node Under %s: %s", cond.Type, name),
				TargetType:  model.TargetKubernetes,
				Category:    "Node Resource Pressure",
				Resource:    fmt.Sprintf("node/%s", name),
				Severity:    model.SeverityCritical,
				Symptom:     fmt.Sprintf("Node reports %s = True (reason: %s).", cond.Type, cond.Reason),
				RootCause:   explanation,
				LogEvidence: cond.Message,
				RemedySteps: []string{
					fmt.Sprintf("Inspect node capacity and allocation: kubectl describe node %s", name),
					"Reduce overcommit by setting accurate resource requests, or add capacity to the pool",
				},
				Metadata: map[string]string{"condition": cond.Type},
			})
		}
	}

	return findings
}

// -----------------------------------------------------------------------------
// K8S-PVC-001 — unbound persistent volume claims
// -----------------------------------------------------------------------------

func evaluatePVCs(items []pvc) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, c := range items {
		if c.Status.Phase != "Pending" && c.Status.Phase != "Lost" {
			continue
		}

		ns, name := c.Metadata.Namespace, c.Metadata.Name
		storageClass := "(default)"
		if c.Spec.StorageClassName != nil && *c.Spec.StorageClassName != "" {
			storageClass = *c.Spec.StorageClassName
		}

		severity := model.SeverityWarning
		rootCause := "No PersistentVolume satisfies the claim: the StorageClass does not exist, its provisioner is not running, or no static PV matches the requested size and access mode."
		if c.Status.Phase == "Lost" {
			severity = model.SeverityCritical
			rootCause = "The bound PersistentVolume no longer exists. Any data on it is unreachable and the workload cannot start."
		}

		findings = append(findings, model.Finding{
			ID:         "K8S-PVC-001",
			Title:      fmt.Sprintf("PersistentVolumeClaim %s: %s/%s", c.Status.Phase, ns, name),
			TargetType: model.TargetKubernetes,
			Category:   "Storage Provisioning",
			Resource:   fmt.Sprintf("pvc/%s", name),
			Namespace:  ns,
			Severity:   severity,
			Symptom:    fmt.Sprintf("Claim is in %s phase using StorageClass %q. Pods mounting it stay Pending.", c.Status.Phase, storageClass),
			RootCause:  rootCause,
			RemedySteps: []string{
				fmt.Sprintf("Read the provisioning events: kubectl describe pvc %s -n %s", name, ns),
				"Confirm the StorageClass exists and a default is set: kubectl get storageclass",
				"Verify the CSI provisioner pods are running in kube-system",
			},
			Metadata: map[string]string{"storage_class": storageClass, "phase": c.Status.Phase},
		})
	}

	return findings
}
