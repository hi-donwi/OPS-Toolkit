package analyzer

import (
	"encoding/json"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// decodePods is a test helper that parses a pod list fixture.
func decodePods(t *testing.T, raw string) []pod {
	t.Helper()
	var list podList
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}
	return list.Items
}

func findByID(findings []model.Finding, id string) (model.Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

func TestEvaluatePodsCrashLoopUsesLastState(t *testing.T) {
	// A crash-looping container's current state is only "waiting"; the exit
	// reason that explains it lives in lastState.
	pods := decodePods(t, `{"items":[{
	  "metadata":{"namespace":"prod","name":"api-7d8"},
	  "status":{"phase":"Running","containerStatuses":[{
	    "name":"api","restartCount":9,
	    "state":{"waiting":{"reason":"CrashLoopBackOff","message":"back-off 5m0s"}},
	    "lastState":{"terminated":{"reason":"Error","exitCode":1,"message":"panic: nil map"}}
	  }]}
	}]}`)

	findings := evaluatePods(pods)

	f, ok := findByID(findings, "K8S-POD-001")
	if !ok {
		t.Fatal("expected K8S-POD-001 for a CrashLoopBackOff pod")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL", f.Severity)
	}
	if f.Namespace != "prod" {
		t.Errorf("namespace = %q, want prod", f.Namespace)
	}
	if f.LogEvidence != "panic: nil map" {
		t.Errorf("LogEvidence = %q, want the lastState termination message", f.LogEvidence)
	}
	if f.Metadata["restart_count"] != "9" {
		t.Errorf("restart_count = %q, want 9", f.Metadata["restart_count"])
	}
}

func TestEvaluatePodsDetectsOOMKilledWhileBackingOff(t *testing.T) {
	// The pod is in CrashLoopBackOff *because* it was OOMKilled. Both matter:
	// the loop is the symptom, the OOM is the cause.
	pods := decodePods(t, `{"items":[{
	  "metadata":{"namespace":"prod","name":"worker-1"},
	  "status":{"phase":"Running","containerStatuses":[{
	    "name":"worker","restartCount":4,
	    "state":{"waiting":{"reason":"CrashLoopBackOff"}},
	    "lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}
	  }]}
	}]}`)

	findings := evaluatePods(pods)

	if _, ok := findByID(findings, "K8S-POD-001"); !ok {
		t.Error("expected the CrashLoopBackOff finding")
	}
	oom, ok := findByID(findings, "K8S-POD-002")
	if !ok {
		t.Fatal("expected K8S-POD-002 (OOMKilled) alongside the crash loop")
	}
	if oom.Metadata["exit_code"] != "137" {
		t.Errorf("exit_code = %q, want 137", oom.Metadata["exit_code"])
	}
}

func TestEvaluatePodsImagePullAndConfigErrors(t *testing.T) {
	pods := decodePods(t, `{"items":[
	  {"metadata":{"namespace":"a","name":"p1"},"status":{"phase":"Pending","containerStatuses":[
	    {"name":"c","state":{"waiting":{"reason":"ImagePullBackOff","message":"manifest unknown"}}}]}},
	  {"metadata":{"namespace":"a","name":"p2"},"status":{"phase":"Pending","containerStatuses":[
	    {"name":"c","state":{"waiting":{"reason":"CreateContainerConfigError","message":"secret \"db\" not found"}}}]}}
	]}`)

	findings := evaluatePods(pods)

	pull, ok := findByID(findings, "K8S-POD-003")
	if !ok {
		t.Fatal("expected K8S-POD-003 for ImagePullBackOff")
	}
	if pull.LogEvidence != "manifest unknown" {
		t.Errorf("LogEvidence = %q", pull.LogEvidence)
	}
	if _, ok := findByID(findings, "K8S-POD-006"); !ok {
		t.Error("expected K8S-POD-006 for CreateContainerConfigError")
	}
}

func TestEvaluatePodsIgnoresContainerCreating(t *testing.T) {
	// A pod the kubelet is actively starting is not "stuck pending".
	pods := decodePods(t, `{"items":[{
	  "metadata":{"namespace":"a","name":"starting"},
	  "status":{"phase":"Pending","containerStatuses":[
	    {"name":"c","state":{"waiting":{"reason":"ContainerCreating"}}}]}
	}]}`)

	if _, ok := findByID(evaluatePods(pods), "K8S-POD-004"); ok {
		t.Error("ContainerCreating must not be reported as stuck Pending")
	}
}

func TestEvaluatePodsDetectsUnschedulable(t *testing.T) {
	pods := decodePods(t, `{"items":[{
	  "metadata":{"namespace":"a","name":"unscheduled"},
	  "status":{"phase":"Pending","containerStatuses":[]}
	}]}`)

	f, ok := findByID(evaluatePods(pods), "K8S-POD-004")
	if !ok {
		t.Fatal("expected K8S-POD-004 for an unscheduled pod")
	}
	if f.Severity != model.SeverityWarning {
		t.Errorf("severity = %s, want WARNING", f.Severity)
	}
}

func TestEvaluatePodsDetectsEviction(t *testing.T) {
	pods := decodePods(t, `{"items":[{
	  "metadata":{"namespace":"a","name":"evicted-1"},
	  "spec":{"nodeName":"node-3"},
	  "status":{"phase":"Failed","reason":"Evicted","message":"The node was low on resource: ephemeral-storage."}
	}]}`)

	f, ok := findByID(evaluatePods(pods), "K8S-POD-005")
	if !ok {
		t.Fatal("expected K8S-POD-005 for an evicted pod")
	}
	if f.QuickFixCmd == "" {
		t.Error("an evicted pod should carry a cleanup quick-fix")
	}
}

func TestEvaluatePodsHealthyProducesNoFindings(t *testing.T) {
	pods := decodePods(t, `{"items":[{
	  "metadata":{"namespace":"prod","name":"healthy"},
	  "status":{"phase":"Running","containerStatuses":[
	    {"name":"c","ready":true,"restartCount":0,"state":{"running":{}}}]}
	}]}`)

	if findings := evaluatePods(pods); len(findings) != 0 {
		t.Errorf("healthy pod produced %d findings: %+v", len(findings), findings)
	}
}

func TestEvaluateEndpointsDistinguishesOrphanFromNotReady(t *testing.T) {
	// This is the check that a `{len .subsets}` jsonpath query silently
	// disabled: kubectl rejects `len` with "unrecognized identifier".
	var list endpointsList
	raw := `{"items":[
	  {"metadata":{"namespace":"default","name":"kubernetes"},"subsets":[]},
	  {"metadata":{"namespace":"prod","name":"orphan-svc"},"subsets":[]},
	  {"metadata":{"namespace":"prod","name":"unready-svc"},"subsets":[
	    {"notReadyAddresses":[{"ip":"10.0.0.1"},{"ip":"10.0.0.2"}]}]},
	  {"metadata":{"namespace":"prod","name":"healthy-svc"},"subsets":[
	    {"addresses":[{"ip":"10.0.0.3"}]}]}
	]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	findings := evaluateEndpoints(list.Items)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (default/kubernetes and the healthy service are exempt)", len(findings))
	}

	orphan, ok := findByID(findings, "K8S-SVC-001")
	if !ok {
		t.Fatal("expected K8S-SVC-001 for the service with no backends at all")
	}
	if orphan.Severity != model.SeverityWarning {
		t.Errorf("orphan severity = %s, want WARNING", orphan.Severity)
	}

	unready, ok := findByID(findings, "K8S-SVC-002")
	if !ok {
		t.Fatal("expected K8S-SVC-002 for the service whose pods all fail readiness")
	}
	if unready.Severity != model.SeverityCritical {
		t.Errorf("unready severity = %s, want CRITICAL — pods exist but serve nothing", unready.Severity)
	}
	if unready.Metadata["not_ready"] != "2" {
		t.Errorf("not_ready = %q, want 2", unready.Metadata["not_ready"])
	}
}

func TestEvaluateNodes(t *testing.T) {
	var list nodeList
	raw := `{"items":[
	  {"metadata":{"name":"node-1"},"status":{"conditions":[
	    {"type":"Ready","status":"True"},{"type":"MemoryPressure","status":"False"}]}},
	  {"metadata":{"name":"node-2"},"status":{"conditions":[
	    {"type":"Ready","status":"Unknown","reason":"NodeStatusUnknown","message":"Kubelet stopped posting node status."}]}},
	  {"metadata":{"name":"node-3"},"status":{"conditions":[
	    {"type":"Ready","status":"True"},{"type":"DiskPressure","status":"True","reason":"KubeletHasDiskPressure"}]}}
	]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	findings := evaluateNodes(list.Items)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (node-1 is healthy)", len(findings))
	}
	if _, ok := findByID(findings, "K8S-NOD-001"); !ok {
		t.Error("expected K8S-NOD-001 for the NotReady node")
	}

	pressure, ok := findByID(findings, "K8S-NOD-002")
	if !ok {
		t.Fatal("expected K8S-NOD-002 for DiskPressure")
	}
	if pressure.Metadata["condition"] != "DiskPressure" {
		t.Errorf("condition = %q", pressure.Metadata["condition"])
	}
}

func TestEvaluatePVCs(t *testing.T) {
	var list pvcList
	raw := `{"items":[
	  {"metadata":{"namespace":"a","name":"bound"},"status":{"phase":"Bound"}},
	  {"metadata":{"namespace":"a","name":"pending"},"spec":{"storageClassName":"fast-ssd"},"status":{"phase":"Pending"}},
	  {"metadata":{"namespace":"a","name":"lost"},"status":{"phase":"Lost"}}
	]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	findings := evaluatePVCs(list.Items)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (Bound is healthy)", len(findings))
	}

	var sawPendingWarning, sawLostCritical bool
	for _, f := range findings {
		if f.Metadata["phase"] == "Pending" && f.Severity == model.SeverityWarning {
			sawPendingWarning = true
			if f.Metadata["storage_class"] != "fast-ssd" {
				t.Errorf("storage_class = %q", f.Metadata["storage_class"])
			}
		}
		// A Lost PV means data is already unreachable, which outranks a claim
		// that has simply not been provisioned yet.
		if f.Metadata["phase"] == "Lost" && f.Severity == model.SeverityCritical {
			sawLostCritical = true
		}
	}
	if !sawPendingWarning || !sawLostCritical {
		t.Errorf("severity mapping wrong: pending=%v lost=%v", sawPendingWarning, sawLostCritical)
	}
}

func TestEvaluateClusterDNS(t *testing.T) {
	ready := decodePods(t, `{"items":[
	  {"metadata":{"namespace":"kube-system","name":"coredns-1"},"status":{"containerStatuses":[{"name":"coredns","ready":true}]}},
	  {"metadata":{"namespace":"kube-system","name":"coredns-2"},"status":{"containerStatuses":[{"name":"coredns","ready":true}]}}
	]}`)
	if f := evaluateClusterDNS(ready); f[0].Severity != model.SeverityPass {
		t.Errorf("all-ready CoreDNS = %s, want PASS", f[0].Severity)
	}

	degraded := decodePods(t, `{"items":[
	  {"metadata":{"namespace":"kube-system","name":"coredns-1"},"status":{"containerStatuses":[{"name":"coredns","ready":true}]}},
	  {"metadata":{"namespace":"kube-system","name":"coredns-2"},"status":{"containerStatuses":[{"name":"coredns","ready":false,"restartCount":3}]}}
	]}`)
	if f := evaluateClusterDNS(degraded); f[0].Severity != model.SeverityWarning {
		t.Errorf("partially degraded CoreDNS = %s, want WARNING", f[0].Severity)
	}

	down := decodePods(t, `{"items":[
	  {"metadata":{"namespace":"kube-system","name":"coredns-1"},"status":{"containerStatuses":[{"name":"coredns","ready":false}]}}
	]}`)
	if f := evaluateClusterDNS(down); f[0].Severity != model.SeverityCritical {
		t.Errorf("fully down CoreDNS = %s, want CRITICAL", f[0].Severity)
	}

	if f := evaluateClusterDNS(nil); f[0].Severity != model.SeverityCritical {
		t.Errorf("missing CoreDNS = %s, want CRITICAL", f[0].Severity)
	}
}

func TestEvaluateIngressDetectsMissingBackend(t *testing.T) {
	var list ingressList
	raw := `{"items":[
	  {"metadata":{"namespace":"prod","name":"web"},"spec":{
	    "rules":[{"host":"app.example.com","http":{"paths":[
	      {"path":"/","backend":{"service":{"name":"web-svc"}}},
	      {"path":"/api","backend":{"service":{"name":"api-svc"}}}]}}]}}
	]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	// web-svc exists, api-svc does not. Kubernetes accepts this manifest
	// silently; the only symptom is a 503 at request time.
	services := map[string]bool{"prod/web-svc": true}

	findings := evaluateIngress(list.Items, services, nil)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != "K8S-ING-001" {
		t.Errorf("ID = %s, want K8S-ING-001", findings[0].ID)
	}
	if findings[0].Metadata["missing_services"] != "api-svc" {
		t.Errorf("missing_services = %q, want api-svc", findings[0].Metadata["missing_services"])
	}
}

func TestEvaluateIngressIsNamespaceScoped(t *testing.T) {
	var list ingressList
	raw := `{"items":[{"metadata":{"namespace":"prod","name":"web"},"spec":{
	  "rules":[{"http":{"paths":[{"backend":{"service":{"name":"api"}}}]}}]}}]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}

	// A service of the same name in another namespace does not satisfy the
	// backend reference.
	findings := evaluateIngress(list.Items, map[string]bool{"staging/api": true}, nil)

	if len(findings) != 1 {
		t.Errorf("cross-namespace service must not satisfy the reference, got %d findings", len(findings))
	}
}

func TestEvaluateIngressDetectsMissingTLSSecret(t *testing.T) {
	var list ingressList
	raw := `{"items":[{"metadata":{"namespace":"prod","name":"web"},"spec":{
	  "tls":[{"hosts":["app.example.com"],"secretName":"app-tls"}],
	  "rules":[{"http":{"paths":[{"backend":{"service":{"name":"web-svc"}}}]}}]}}]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}

	findings := evaluateIngress(list.Items, map[string]bool{"prod/web-svc": true}, map[string]bool{})

	if len(findings) != 1 || findings[0].ID != "K8S-ING-002" {
		t.Fatalf("expected K8S-ING-002 for a missing TLS secret, got %+v", findings)
	}
}

func TestEvaluateIngressHealthy(t *testing.T) {
	var list ingressList
	raw := `{"items":[{"metadata":{"namespace":"prod","name":"web"},"spec":{
	  "tls":[{"hosts":["app.example.com"],"secretName":"app-tls"}],
	  "rules":[{"http":{"paths":[{"backend":{"service":{"name":"web-svc"}}}]}}]}}]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}

	findings := evaluateIngress(list.Items,
		map[string]bool{"prod/web-svc": true},
		map[string]bool{"prod/app-tls": true})

	if len(findings) != 0 {
		t.Errorf("a fully wired ingress produced %d findings: %+v", len(findings), findings)
	}
}

func TestEvaluateIngressIgnoresDefaultCertificate(t *testing.T) {
	var list ingressList
	// An empty secretName means "use the controller's default certificate",
	// which is a deliberate configuration, not a fault.
	raw := `{"items":[{"metadata":{"namespace":"prod","name":"web"},"spec":{
	  "tls":[{"hosts":["app.example.com"]}],"rules":[]}}]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}

	if findings := evaluateIngress(list.Items, nil, nil); len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}
