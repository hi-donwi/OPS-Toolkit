package analyzer

import (
	"fmt"
	"strconv"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// podRestartThreshold is the restart count above which a Running pod is treated
// as unstable even though it is not currently in CrashLoopBackOff.
const podRestartThreshold = 5

// -----------------------------------------------------------------------------
// K8S-POD-001..005 — workload health
// -----------------------------------------------------------------------------

// evaluatePods scores pod and container state. A single pod can trip several
// rules at once (crash-looping *and* OOMKilled), and each is reported, because
// the exit reason is what tells an operator whether to fix memory or config.
func evaluatePods(pods []pod) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, p := range pods {
		ns, name := p.Metadata.Namespace, p.Metadata.Name
		ref := fmt.Sprintf("pod/%s", name)

		// Evicted pods report at the pod level, not per container.
		if p.Status.Reason == "Evicted" {
			findings = append(findings, model.Finding{
				ID:          "K8S-POD-005",
				Title:       fmt.Sprintf("Pod Evicted: %s/%s", ns, name),
				TargetType:  model.TargetKubernetes,
				Category:    "Node Resource Pressure",
				Resource:    ref,
				Namespace:   ns,
				Severity:    model.SeverityWarning,
				Symptom:     fmt.Sprintf("Pod was evicted from node %s.", p.Spec.NodeName),
				RootCause:   "The kubelet reclaimed resources under node pressure (disk, memory, or PID). Eviction targets pods that exceed their requests first.",
				LogEvidence: p.Status.Message,
				RemedySteps: []string{
					fmt.Sprintf("Identify which resource was exhausted: kubectl describe node %s", p.Spec.NodeName),
					"Set realistic resource requests so the scheduler stops overcommitting the node",
					"Clear the accumulated evicted pods once the cause is fixed",
				},
				QuickFixCmd: fmt.Sprintf("kubectl delete pod %s -n %s", name, ns),
			})
			continue
		}

		for _, cs := range p.Status.ContainerStatuses {
			findings = append(findings, evaluateContainerStatus(ns, name, ref, cs)...)
		}

		for _, cs := range p.Status.InitContainerStatuses {
			initRef := fmt.Sprintf("%s (init:%s)", ref, cs.Name)
			findings = append(findings, evaluateContainerStatus(ns, name, initRef, cs)...)
		}

		// Pending with no container status at all means the scheduler never
		// placed the pod; ContainerCreating means it did and the kubelet is
		// still working, which is normal.
		if p.Status.Phase == "Pending" && !hasContainerCreating(p) {
			findings = append(findings, model.Finding{
				ID:         "K8S-POD-004",
				Title:      fmt.Sprintf("Pod Stuck in Pending State: %s/%s", ns, name),
				TargetType: model.TargetKubernetes,
				Category:   "Scheduling Failure",
				Resource:   ref,
				Namespace:  ns,
				Severity:   model.SeverityWarning,
				Symptom:    "Pod has not been scheduled onto any node.",
				RootCause:  "No node satisfies the pod: insufficient allocatable CPU or memory, an untolerated taint, an unsatisfiable affinity rule, or an unbound PersistentVolumeClaim.",
				RemedySteps: []string{
					fmt.Sprintf("Read the scheduler's rejection reason: kubectl describe pod %s -n %s", name, ns),
					"Compare the pod's resource requests against node allocatable: kubectl describe nodes | grep -A5 'Allocated resources'",
				},
			})
		}
	}

	return findings
}

// hasContainerCreating reports whether the kubelet is actively starting the pod.
func hasContainerCreating(p pod) bool {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "ContainerCreating" {
			return true
		}
	}
	for _, cs := range p.Status.InitContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "ContainerCreating" {
			return true
		}
	}
	return false
}

// evaluateContainerStatus scores one container's current and previous state.
//
// A single container can trip several rules at once — crash-looping *because*
// it was OOMKilled — and each is reported, because the exit reason is what tells
// an operator whether to fix memory or configuration.
func evaluateContainerStatus(ns, podName, ref string, cs containerStatus) []model.Finding {
	findings := make([]model.Finding, 0, 2)

	waiting := cs.State.Waiting

	// A crash-looping container's current state is only "waiting to restart".
	// The reason it died is recorded in lastState.
	terminated := cs.LastState.Terminated
	if terminated == nil {
		terminated = cs.State.Terminated
	}

	if waiting != nil {
		switch waiting.Reason {
		case "CrashLoopBackOff":
			findings = append(findings, crashLoopFinding(ns, podName, ref, cs, waiting, terminated))
		case "ImagePullBackOff", "ErrImagePull":
			findings = append(findings, imagePullFinding(ns, podName, ref, cs, waiting))
		case "CreateContainerConfigError":
			findings = append(findings, configErrorFinding(ns, podName, ref, cs, waiting))
		}
	}

	// Checked independently of the waiting reason: an OOM kill survives into
	// lastState while the container backs off, and is the actionable cause
	// behind a crash loop that would otherwise look like an application bug.
	if terminated != nil && terminated.Reason == "OOMKilled" {
		findings = append(findings, oomKilledFinding(ns, podName, ref, cs, terminated))
	}

	// A container that is currently up but has restarted many times never
	// enters CrashLoopBackOff, so it is invisible to the check above.
	if waiting == nil && cs.RestartCount > podRestartThreshold {
		findings = append(findings, restartChurnFinding(ns, podName, ref, cs))
	}

	return findings
}

func crashLoopFinding(ns, podName, ref string, cs containerStatus, waiting *stateWaiting, terminated *stateTerminated) model.Finding {
	evidence := waiting.Message
	exitDetail := ""
	if terminated != nil {
		exitDetail = fmt.Sprintf(" Last termination: %s (exit code %d).", terminated.Reason, terminated.ExitCode)
		if terminated.Message != "" {
			evidence = terminated.Message
		}
	}

	return model.Finding{
		ID:          "K8S-POD-001",
		Title:       fmt.Sprintf("Pod in CrashLoopBackOff: %s/%s", ns, podName),
		TargetType:  model.TargetKubernetes,
		Category:    "Workload Crash",
		Resource:    ref,
		Namespace:   ns,
		Severity:    model.SeverityCritical,
		Symptom:     fmt.Sprintf("Container %q has restarted %d times and is backing off.%s", cs.Name, cs.RestartCount, exitDetail),
		RootCause:   "The container exits shortly after start on every attempt — an unhandled startup exception, invalid configuration, a missing secret, or a dependency that is not yet reachable.",
		LogEvidence: evidence,
		RemedySteps: []string{
			fmt.Sprintf("Read the logs from the crashed generation: kubectl logs %s -n %s -c %s --previous --tail 100", podName, ns, cs.Name),
			fmt.Sprintf("Check the events for the failure sequence: kubectl describe pod %s -n %s", podName, ns),
		},
		Metadata: map[string]string{
			"container":     cs.Name,
			"restart_count": strconv.Itoa(cs.RestartCount),
		},
	}
}

func imagePullFinding(ns, podName, ref string, cs containerStatus, waiting *stateWaiting) model.Finding {
	return model.Finding{
		ID:          "K8S-POD-003",
		Title:       fmt.Sprintf("Pod Failed to Pull Image: %s/%s", ns, podName),
		TargetType:  model.TargetKubernetes,
		Category:    "Deployment Failure",
		Resource:    ref,
		Namespace:   ns,
		Severity:    model.SeverityCritical,
		Symptom:     fmt.Sprintf("Kubelet cannot pull the image for container %q.", cs.Name),
		RootCause:   "The image or tag does not exist, the registry is unreachable, or the namespace has no imagePullSecret for a private repository.",
		LogEvidence: waiting.Message,
		RemedySteps: []string{
			fmt.Sprintf("Read the exact registry error: kubectl describe pod %s -n %s", podName, ns),
			fmt.Sprintf("Verify a pull secret exists in this namespace: kubectl get secrets -n %s --field-selector type=kubernetes.io/dockerconfigjson", ns),
		},
		Metadata: map[string]string{"container": cs.Name},
	}
}

func configErrorFinding(ns, podName, ref string, cs containerStatus, waiting *stateWaiting) model.Finding {
	return model.Finding{
		ID:          "K8S-POD-006",
		Title:       fmt.Sprintf("Pod Configuration Error: %s/%s", ns, podName),
		TargetType:  model.TargetKubernetes,
		Category:    "Configuration Failure",
		Resource:    ref,
		Namespace:   ns,
		Severity:    model.SeverityCritical,
		Symptom:     fmt.Sprintf("Container %q cannot be created from its configuration.", cs.Name),
		RootCause:   "The pod references a ConfigMap, Secret, or key that does not exist in this namespace.",
		LogEvidence: waiting.Message,
		RemedySteps: []string{
			fmt.Sprintf("Identify the missing reference: kubectl describe pod %s -n %s", podName, ns),
			fmt.Sprintf("List what exists in the namespace: kubectl get configmap,secret -n %s", ns),
		},
		Metadata: map[string]string{"container": cs.Name},
	}
}

func oomKilledFinding(ns, podName, ref string, cs containerStatus, terminated *stateTerminated) model.Finding {
	return model.Finding{
		ID:         "K8S-POD-002",
		Title:      fmt.Sprintf("Pod Terminated (OOMKilled): %s/%s", ns, podName),
		TargetType: model.TargetKubernetes,
		Category:   "Resource Saturation",
		Resource:   ref,
		Namespace:  ns,
		Severity:   model.SeverityCritical,
		Symptom:    fmt.Sprintf("Container %q was killed with exit code %d after exceeding its memory limit.", cs.Name, terminated.ExitCode),
		RootCause:  "Container memory usage surpassed spec.resources.limits.memory, so the kernel cgroup OOM killer terminated it.",
		RemedySteps: []string{
			fmt.Sprintf("Measure the real working set before raising the limit: kubectl top pod %s -n %s", podName, ns),
			"Raise resources.limits.memory in the workload manifest to cover peak usage plus headroom",
			"For JVM workloads set -XX:MaxRAMPercentage so the heap respects the cgroup limit",
		},
		Metadata: map[string]string{
			"container": cs.Name,
			"exit_code": strconv.Itoa(terminated.ExitCode),
		},
	}
}

func restartChurnFinding(ns, podName, ref string, cs containerStatus) model.Finding {
	return model.Finding{
		ID:         "K8S-POD-007",
		Title:      fmt.Sprintf("Pod Restarting Repeatedly: %s/%s", ns, podName),
		TargetType: model.TargetKubernetes,
		Category:   "Workload Instability",
		Resource:   ref,
		Namespace:  ns,
		Severity:   model.SeverityWarning,
		Symptom:    fmt.Sprintf("Container %q is currently running but has restarted %d times.", cs.Name, cs.RestartCount),
		RootCause:  "The container recovers after each failure, so it never enters CrashLoopBackOff, but it is not staying up. Commonly a failing liveness probe or an intermittent dependency.",
		RemedySteps: []string{
			fmt.Sprintf("Read the previous generation's logs: kubectl logs %s -n %s -c %s --previous", podName, ns, cs.Name),
			"Check whether the liveness probe threshold is tighter than real startup and response time",
		},
		Metadata: map[string]string{
			"container":     cs.Name,
			"restart_count": strconv.Itoa(cs.RestartCount),
		},
	}
}
