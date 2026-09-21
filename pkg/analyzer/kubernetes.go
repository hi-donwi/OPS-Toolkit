package analyzer

import (
	"context"
	"encoding/json"
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
	reachable := false

	if raw, err := e.kubectlJSON(ctx, "pods", scope); err == nil {
		reachable = true
		var list podList
		if json.Unmarshal(raw, &list) == nil {
			findings = append(findings, evaluatePods(list.Items)...)
		}
	}

	if raw, err := e.kubectlJSON(ctx, "endpoints", scope); err == nil {
		reachable = true
		var list endpointsList
		if json.Unmarshal(raw, &list) == nil {
			findings = append(findings, evaluateEndpoints(list.Items)...)
		}
	}

	if raw, err := e.kubectlJSON(ctx, "persistentvolumeclaims", scope); err == nil {
		reachable = true
		var list pvcList
		if json.Unmarshal(raw, &list) == nil {
			findings = append(findings, evaluatePVCs(list.Items)...)
		}
	}

	// Nodes are cluster-scoped; a namespace filter does not apply.
	if raw, err := e.kubectlJSON(ctx, "nodes", nil); err == nil {
		reachable = true
		var list nodeList
		if json.Unmarshal(raw, &list) == nil {
			findings = append(findings, evaluateNodes(list.Items)...)
		}
	}

	findings = append(findings, e.checkIngress(ctx, scope)...)

	dnsPods, dnsFound := e.queryClusterDNSPods(ctx)
	if dnsFound {
		findings = append(findings, evaluateClusterDNS(dnsPods)...)
	}

	if !reachable {
		return []model.Finding{{
			ID:         "K8S-API-001",
			Title:      "Kubernetes API Server Unreachable",
			TargetType: model.TargetKubernetes,
			Category:   "Cluster Connectivity",
			Resource:   "k8s:apiserver",
			Severity:   model.SeverityWarning,
			Symptom:    "A kubeconfig is present but no Kubernetes resource could be listed.",
			RootCause:  "The current context points at an unreachable or unauthorized API server — a stale context, an expired credential, or no network path to the control plane.",
			RemedySteps: []string{
				"Confirm the active context: kubectl config current-context",
				"Test connectivity and authorization: kubectl auth can-i list pods --all-namespaces",
			},
		}}
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
	return e.run.Run(ctx, k8sTimeout, "kubectl", args...)
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
