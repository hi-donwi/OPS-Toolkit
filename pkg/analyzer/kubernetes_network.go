package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// -----------------------------------------------------------------------------
// K8S-SVC-001 — services with no ready endpoints
// -----------------------------------------------------------------------------

// evaluateEndpoints finds services routing to nothing. This replaces a jsonpath
// `{len .subsets}` query, which kubectl rejects outright ("unrecognized
// identifier len"), meaning the check never ran.
func evaluateEndpoints(items []endpoints) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, ep := range items {
		ns, name := ep.Metadata.Namespace, ep.Metadata.Name

		// The default kubernetes API service has no pod backends by design.
		if name == "kubernetes" && ns == "default" {
			continue
		}
		if ep.ReadyAddresses() > 0 {
			continue
		}

		notReady := ep.NotReadyAddresses()

		// Pods exist but fail readiness — a different fault from no pods at all,
		// and the distinction decides whether you debug probes or selectors.
		if notReady > 0 {
			findings = append(findings, model.Finding{
				ID:         "K8S-SVC-002",
				Title:      fmt.Sprintf("Service Has No Ready Endpoints: %s/%s", ns, name),
				TargetType: model.TargetKubernetes,
				Category:   "Network Routing",
				Resource:   fmt.Sprintf("service/%s", name),
				Namespace:  ns,
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("All %d backing pod(s) are failing their readiness probe; the service is routing to nothing.", notReady),
				RootCause:  "Pods are matched by the selector but none pass readiness, so kube-proxy has removed every backend. Requests get connection refused or 503.",
				RemedySteps: []string{
					fmt.Sprintf("Find which pods are not ready: kubectl get pods -n %s -o wide", ns),
					"Verify the readiness probe path, port, and timeout against the application's actual startup behaviour",
				},
				Metadata: map[string]string{"not_ready": strconv.Itoa(notReady)},
			})
			continue
		}

		findings = append(findings, model.Finding{
			ID:         "K8S-SVC-001",
			Title:      fmt.Sprintf("Orphan Service (Zero Endpoints): %s/%s", ns, name),
			TargetType: model.TargetKubernetes,
			Category:   "Network Routing",
			Resource:   fmt.Sprintf("service/%s", name),
			Namespace:  ns,
			Severity:   model.SeverityWarning,
			Symptom:    "Service has no target pod endpoints; requests will fail with connection refused or 503.",
			RootCause:  "The Service's spec.selector matches no pod labels, or the Deployment behind it has zero available replicas.",
			RemedySteps: []string{
				fmt.Sprintf("Read the selector the service expects: kubectl get svc %s -n %s -o jsonpath='{.spec.selector}'", name, ns),
				fmt.Sprintf("Compare against the labels pods actually carry: kubectl get pods -n %s --show-labels", ns),
			},
		})
	}

	return findings
}

// -----------------------------------------------------------------------------
// K8S-DNS-001 — cluster DNS health
// -----------------------------------------------------------------------------

// evaluateClusterDNS checks CoreDNS/kube-dns. Cluster DNS is a shared
// dependency: when it degrades, every service-to-service call in the cluster
// starts failing intermittently, which is rarely diagnosed as a DNS problem.
func evaluateClusterDNS(pods []pod) []model.Finding {
	if len(pods) == 0 {
		return []model.Finding{{
			ID:         "K8S-DNS-001",
			Title:      "Cluster DNS Pods Not Found",
			TargetType: model.TargetKubernetes,
			Category:   "Cluster DNS",
			Resource:   "deployment/coredns",
			Namespace:  "kube-system",
			Severity:   model.SeverityCritical,
			Symptom:    "No pods matching k8s-app=kube-dns are present in kube-system.",
			RootCause:  "CoreDNS is not deployed or its labels differ from the standard. Without cluster DNS, every in-cluster service name fails to resolve.",
			RemedySteps: []string{
				"Check the deployment: kubectl get deployment -n kube-system coredns",
				"Confirm the label selector matches your distribution's DNS add-on",
			},
		}}
	}

	ready, total := 0, len(pods)
	restarts := 0
	for _, p := range pods {
		allReady := len(p.Status.ContainerStatuses) > 0
		for _, cs := range p.Status.ContainerStatuses {
			if !cs.Ready {
				allReady = false
			}
			restarts += cs.RestartCount
		}
		if allReady {
			ready++
		}
	}

	switch {
	case ready == 0:
		return []model.Finding{{
			ID:         "K8S-DNS-001",
			Title:      "Cluster DNS Fully Unavailable",
			TargetType: model.TargetKubernetes,
			Category:   "Cluster DNS",
			Resource:   "deployment/coredns",
			Namespace:  "kube-system",
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("None of the %d CoreDNS pods are ready.", total),
			RootCause:  "Every DNS replica is down, so no pod in the cluster can resolve a service name. Expect cluster-wide connection failures.",
			RemedySteps: []string{
				"Inspect the DNS pods: kubectl get pods -n kube-system -l k8s-app=kube-dns",
				"Read the CoreDNS logs for a Corefile or upstream error: kubectl logs -n kube-system -l k8s-app=kube-dns --tail 50",
			},
		}}
	case ready < total:
		return []model.Finding{{
			ID:         "K8S-DNS-001",
			Title:      "Cluster DNS Partially Degraded",
			TargetType: model.TargetKubernetes,
			Category:   "Cluster DNS",
			Resource:   "deployment/coredns",
			Namespace:  "kube-system",
			Severity:   model.SeverityWarning,
			Symptom:    fmt.Sprintf("Only %d of %d CoreDNS pods are ready (%d total container restarts).", ready, total, restarts),
			RootCause:  "Some DNS replicas are unhealthy, reducing headroom and causing intermittent resolution timeouts under load.",
			RemedySteps: []string{
				"Check the unready replicas: kubectl describe pods -n kube-system -l k8s-app=kube-dns",
				"Confirm CoreDNS has adequate memory limits for the cluster's query volume",
			},
		}}
	default:
		return []model.Finding{{
			ID:         "K8S-DNS-001",
			Title:      "Cluster DNS Healthy",
			TargetType: model.TargetKubernetes,
			Category:   "Cluster DNS",
			Resource:   "deployment/coredns",
			Namespace:  "kube-system",
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("All %d CoreDNS pods are ready.", total),
		}}
	}
}

// joinNames renders a container name list for a finding message.
func joinNames(names []string) string { return strings.Join(names, ", ") }

// -----------------------------------------------------------------------------
// K8S-ING-001 — ingress routing to nothing
// -----------------------------------------------------------------------------

// checkIngress implements K8S-ING-001.
func (e *Engine) checkIngress(ctx context.Context, scope []string) []model.Finding {
	raw, err := e.kubectlJSON(ctx, "ingress", scope)
	if err != nil {
		return nil
	}

	var ingresses ingressList
	if json.Unmarshal(raw, &ingresses) != nil || len(ingresses.Items) == 0 {
		return nil
	}

	// Namespaced key sets, because a Service in another namespace does not
	// satisfy an Ingress backend reference.
	var services map[string]bool
	if raw, err := e.kubectlJSON(ctx, "services", scope); err == nil {
		var list serviceList
		if json.Unmarshal(raw, &list) == nil {
			services = make(map[string]bool)
			for _, s := range list.Items {
				services[s.Metadata.Namespace+"/"+s.Metadata.Name] = true
			}
		}
	}

	var secrets map[string]bool
	if raw, err := e.kubectlJSON(ctx, "secrets", scope); err == nil {
		var list secretList
		if json.Unmarshal(raw, &list) == nil {
			secrets = make(map[string]bool)
			for _, s := range list.Items {
				secrets[s.Metadata.Namespace+"/"+s.Metadata.Name] = true
			}
		}
	}

	return evaluateIngress(ingresses.Items, services, secrets)
}

// evaluateIngress finds ingress rules pointing at services or TLS secrets that
// do not exist. Kubernetes accepts these manifests without complaint, so the
// only symptom is a 503 from the ingress controller at request time.
func evaluateIngress(ingresses []ingress, services, secrets map[string]bool) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, ing := range ingresses {
		ns, name := ing.Metadata.Namespace, ing.Metadata.Name

		missingBackends := make([]string, 0)
		if services != nil {
			for _, svc := range ing.BackendServices() {
				if !services[ns+"/"+svc] {
					missingBackends = append(missingBackends, svc)
				}
			}
		}

		if len(missingBackends) > 0 {
			findings = append(findings, model.Finding{
				ID:         "K8S-ING-001",
				Title:      fmt.Sprintf("Ingress References Missing Service: %s/%s", ns, name),
				TargetType: model.TargetKubernetes,
				Category:   "Ingress Routing",
				Resource:   fmt.Sprintf("ingress/%s", name),
				Namespace:  ns,
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("Backend service(s) %s do not exist in namespace %s.", joinNames(missingBackends), ns),
				RootCause:  "The API server does not validate ingress backend references, so a renamed or deleted Service leaves the manifest valid while the controller returns 503 for every matching request.",
				RemedySteps: []string{
					fmt.Sprintf("Compare the referenced names against reality: kubectl get svc -n %s", ns),
					fmt.Sprintf("Inspect the controller's view of the backends: kubectl describe ingress %s -n %s", name, ns),
				},
				Metadata: map[string]string{"missing_services": joinNames(missingBackends)},
			})
		}

		// An empty secretName means the controller falls back to its default
		// certificate, which is a deliberate configuration rather than a fault.
		// When secrets == nil, listing secrets was denied (RBAC) or failed, so we
		// skip false-positive flags rather than reporting all TLS secrets as missing.
		if secrets != nil {
			for _, tls := range ing.Spec.TLS {
				if tls.SecretName == "" || secrets[ns+"/"+tls.SecretName] {
					continue
				}
				findings = append(findings, model.Finding{
					ID:         "K8S-ING-002",
					Title:      fmt.Sprintf("Ingress TLS Secret Missing: %s/%s", ns, name),
					TargetType: model.TargetKubernetes,
					Category:   "Ingress TLS",
					Resource:   fmt.Sprintf("ingress/%s", name),
					Namespace:  ns,
					Severity:   model.SeverityCritical,
					Symptom:    fmt.Sprintf("TLS secret %q referenced for host(s) %s does not exist.", tls.SecretName, joinNames(tls.Hosts)),
					RootCause:  "The certificate Secret was never created, or cert-manager failed to issue it. The controller serves its default self-signed certificate instead, so clients see a certificate name mismatch.",
					RemedySteps: []string{
						fmt.Sprintf("Check whether cert-manager issued the certificate: kubectl get certificate,certificaterequest -n %s", ns),
						fmt.Sprintf("Confirm the secret name matches the manifest: kubectl get secret %s -n %s", tls.SecretName, ns),
					},
					Metadata: map[string]string{"secret": tls.SecretName},
				})
			}
		}
	}

	return findings
}
