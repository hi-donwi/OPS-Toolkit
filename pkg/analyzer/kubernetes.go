package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// k8sTimeout bounds each kubectl call. An unreachable API server otherwise
// blocks the whole diagnostic run behind kubectl's own long default.
const k8sTimeout = 25 * time.Second

// -----------------------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------------------

// evaluateKubernetes runs every K8S-* rule.
func (e *Engine) evaluateKubernetes(ctx context.Context, namespace string) []model.Finding {
	if !e.env.HasKubernetes || !e.run.Available("kubectl") {
		return nil
	}

	scope := []string{"--all-namespaces"}
	if namespace != "" {
		scope = []string{"-n", namespace}
	}

	findings := make([]model.Finding, 0, 16)
	var collectionErr error
	reachable := false

	if raw, err := e.kubectlJSON(ctx, "pods", scope); err == nil {
		reachable = true
		var list podList
		if err := json.Unmarshal(raw, &list); err == nil {
			findings = append(findings, evaluatePods(list.Items)...)
		} else {
			collectionErr = errors.Join(collectionErr, err)
		}
	} else {
		collectionErr = errors.Join(collectionErr, err)
	}

	if raw, err := e.kubectlJSON(ctx, "endpoints", scope); err == nil {
		reachable = true
		var list endpointsList
		if err := json.Unmarshal(raw, &list); err == nil {
			findings = append(findings, evaluateEndpoints(list.Items)...)
		} else {
			collectionErr = errors.Join(collectionErr, err)
		}
	} else {
		collectionErr = errors.Join(collectionErr, err)
	}

	if raw, err := e.kubectlJSON(ctx, "persistentvolumeclaims", scope); err == nil {
		reachable = true
		var list pvcList
		if err := json.Unmarshal(raw, &list); err == nil {
			findings = append(findings, evaluatePVCs(list.Items)...)
		} else {
			collectionErr = errors.Join(collectionErr, err)
		}
	} else {
		collectionErr = errors.Join(collectionErr, err)
	}

	// Nodes are cluster-scoped; a namespace filter does not apply.
	if raw, err := e.kubectlJSON(ctx, "nodes", nil); err == nil {
		reachable = true
		var list nodeList
		if err := json.Unmarshal(raw, &list); err == nil {
			findings = append(findings, evaluateNodes(list.Items)...)
		} else {
			collectionErr = errors.Join(collectionErr, err)
		}
	} else {
		collectionErr = errors.Join(collectionErr, err)
	}

	findings = append(findings, e.checkIngress(ctx, scope)...)

	dnsPods, dnsFound := e.queryClusterDNSPods(ctx)
	if dnsFound {
		findings = append(findings, evaluateClusterDNS(dnsPods)...)
	} else {
		collectionErr = errors.Join(collectionErr, fmt.Errorf("CoreDNS status unavailable"))
	}

	if !reachable {
		return []model.Finding{{
			ID:         "K8S-API-001",
			Title:      "Kubernetes API Server Unreachable",
			TargetType: model.TargetKubernetes,
			Category:   "Cluster Connectivity",
			Resource:   "k8s:apiserver",
			Severity:   model.SeverityWarning,
			Metadata:   map[string]string{"collection_error": "true"},
			Symptom:    "A kubeconfig is present but no Kubernetes resource could be listed.",
			RootCause:  "The current context points at an unreachable or unauthorized API server — a stale context, an expired credential, or no network path to the control plane.",
			RemedySteps: []string{
				"Confirm the active context: kubectl config current-context",
				"Test connectivity and authorization: kubectl auth can-i list pods --all-namespaces",
			},
		}}
	}

	if collectionErr != nil {
		findings = append(findings, collectionUnavailable("K8S-COL-001", model.TargetKubernetes, "k8s:resources", collectionErr))
	}
	if len(findings) == 0 {
		findings = append(findings, model.Finding{
			ID:         "K8S-ALL-001",
			Title:      "Kubernetes Workloads & Services Healthy",
			TargetType: model.TargetKubernetes,
			Category:   "Cluster Health",
			Resource:   "k8s:workloads",
			Severity:   model.SeverityPass,
			Symptom:    "No crash-looping or OOMKilled pods, orphan services, pending volumes, or degraded nodes found.",
		})
	}

	return findings
}

// kubectlJSON lists a resource kind as JSON.
func (e *Engine) kubectlJSON(ctx context.Context, kind string, scope []string) ([]byte, error) {
	args := append([]string{"get", kind}, scope...)
	args = append(args, "-o", "json")
	raw, err := e.run.Run(ctx, k8sTimeout, "kubectl", args...)
	if err != nil {
		return nil, err
	}
	var list struct {
		Items json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil || len(list.Items) == 0 || list.Items[0] != '[' {
		return nil, fmt.Errorf("kubectl returned an invalid %s list", kind)
	}
	return raw, nil
}

// queryClusterDNSPods tries standard and distribution-specific CoreDNS labels
// in kube-system before concluding DNS pods are missing.
func (e *Engine) queryClusterDNSPods(ctx context.Context) ([]pod, bool) {
	labels := []string{
		"k8s-app=kube-dns",
		"app.kubernetes.io/name=coredns",
		"k8s-app=coredns",
		"app.kubernetes.io/name=rke2-coredns",
	}

	for _, l := range labels {
		raw, err := e.kubectlJSON(ctx, "pods", []string{"-n", "kube-system", "-l", l})
		if err != nil {
			continue
		}
		var list podList
		if json.Unmarshal(raw, &list) == nil {
			if len(list.Items) > 0 {
				return list.Items, true
			}
		}
	}

	// If no labeled pods found, try the default "k8s-app=kube-dns" one last time
	// to see if the query at least succeeded (e.g. producing 0 pods for evaluateClusterDNS)
	if raw, err := e.kubectlJSON(ctx, "pods", []string{"-n", "kube-system", "-l", "k8s-app=kube-dns"}); err == nil {
		var list podList
		if json.Unmarshal(raw, &list) == nil {
			return list.Items, true
		}
	}

	return nil, false
}
