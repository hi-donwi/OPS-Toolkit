package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// swarmService is one row of `docker service ls`.
type swarmService struct {
	ID       string
	Name     string
	Mode     string
	Replicas string
	Image    string
}

// ReplicaCounts parses the "running/desired" replica column. Global-mode
// services report the same shape, so one parser covers both.
func (s swarmService) ReplicaCounts() (running, desired int, ok bool) {
	parts := strings.Fields(s.Replicas)
	if len(parts) == 0 {
		return 0, 0, false
	}
	current, want, found := strings.Cut(parts[0], "/")
	if !found {
		return 0, 0, false
	}
	var err error
	if running, err = strconv.Atoi(current); err != nil {
		return 0, 0, false
	}
	if desired, err = strconv.Atoi(want); err != nil {
		return 0, 0, false
	}
	return running, desired, true
}

// parseSwarmServices parses tab-separated `docker service ls --format` rows.
func parseSwarmServices(output string) []swarmService {
	services := make([]swarmService, 0)

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		services = append(services, swarmService{
			ID:       fields[0],
			Name:     fields[1],
			Mode:     fields[2],
			Replicas: fields[3],
			Image:    fieldAt(fields, 4),
		})
	}

	return services
}

// swarmNode is one row of `docker node ls`.
type swarmNode struct {
	ID            string
	Hostname      string
	Status        string
	Availability  string
	ManagerStatus string
}

// parseSwarmNodes parses tab-separated `docker node ls --format` rows.
func parseSwarmNodes(output string) []swarmNode {
	nodes := make([]swarmNode, 0)

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		nodes = append(nodes, swarmNode{
			ID:            fields[0],
			Hostname:      fields[1],
			Status:        fields[2],
			Availability:  fields[3],
			ManagerStatus: fieldAt(fields, 4),
		})
	}

	return nodes
}

// fieldAt returns the field at idx, or "" when the row is short.
func fieldAt(fields []string, idx int) string {
	if idx < len(fields) {
		return fields[idx]
	}
	return ""
}

// evaluateSwarm runs every SWM-* rule.
func (e *Engine) evaluateSwarm(ctx context.Context) []model.Finding {
	if !e.env.IsDockerSwarm || !e.run.Available("docker") {
		return nil
	}

	findings := make([]model.Finding, 0, 8)

	svcOut, err := e.run.Run(ctx, 20*time.Second, "docker", "service", "ls",
		"--format", "{{.ID}}\t{{.Name}}\t{{.Mode}}\t{{.Replicas}}\t{{.Image}}")
	if err != nil && (strings.Contains(err.Error(), "not a swarm manager") || strings.Contains(string(svcOut), "not a swarm manager")) {
		return []model.Finding{{
			ID:         "SWM-WRK-001",
			Title:      "Docker Swarm Worker Node",
			TargetType: model.TargetSwarm,
			Category:   "Swarm Role",
			Resource:   "swarm:worker",
			Severity:   model.SeverityInfo,
			Symptom:    "This node is a Swarm worker node. Cluster-wide service and node state queries require a manager node.",
			RootCause:  "Worker nodes execute container tasks but do not participate in the Swarm Raft consensus store or manage cluster-wide service definitions.",
			RemedySteps: []string{
				"Run 'opskit diag swarm' from a Swarm manager node to inspect cluster services and task placements",
				"Run 'opskit diag docker' on this worker node to inspect its local running containers and health probes",
			},
		}}
	}
	if err == nil {
		for _, svc := range parseSwarmServices(string(svcOut)) {
			running, desired, ok := svc.ReplicaCounts()
			if !ok || desired == 0 || running >= desired {
				continue
			}

			// Only pay for the per-task drill-down on services that are
			// actually degraded.
			evidence, reason := e.inspectFailedTasks(ctx, svc.Name)
			findings = append(findings, buildReplicaFinding(svc, running, desired, evidence, reason))
		}
	}

	nodeOut, err := e.run.Run(ctx, 20*time.Second, "docker", "node", "ls",
		"--format", "{{.ID}}\t{{.Hostname}}\t{{.Status}}\t{{.Availability}}\t{{.ManagerStatus}}")
	if err == nil {
		findings = append(findings, evaluateSwarmNodes(parseSwarmNodes(string(nodeOut)))...)
	}

	if len(findings) == 0 {
		findings = append(findings, model.Finding{
			ID:         "SWM-ALL-001",
			Title:      "Docker Swarm Cluster Converged",
			TargetType: model.TargetSwarm,
			Category:   "Cluster Health",
			Resource:   "swarm:cluster",
			Severity:   model.SeverityPass,
			Symptom:    "All Swarm nodes are reachable and every service has converged to its desired replica count.",
		})
	}

	return findings
}

// inspectFailedTasks implements SWM-TSK-001: it reads the per-task error column
// for a degraded service and classifies why placement failed, which is the
// single most useful piece of information for a stuck deploy.
func (e *Engine) inspectFailedTasks(ctx context.Context, service string) (evidence, reason string) {
	out, err := e.run.Run(ctx, 20*time.Second, "docker", "service", "ps", service,
		"--no-trunc", "--format", "{{.ID}}\t{{.Node}}\t{{.DesiredState}}\t{{.CurrentState}}\t{{.Error}}")
	if err != nil {
		return "", ""
	}
	return classifyTaskFailure(string(out))
}

// classifyTaskFailure finds the first failing task row and maps its error text
// to a specific root cause.
func classifyTaskFailure(output string) (evidence, reason string) {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if !strings.Contains(line, "Rejected") && !strings.Contains(line, "Failed") &&
			!strings.Contains(line, "Pending") && !strings.Contains(line, "no suitable node") {
			continue
		}

		evidence = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		switch {
		case strings.Contains(lower, "insufficient memory"):
			return evidence, "No node has enough free memory to satisfy the service's resource reservation."
		case strings.Contains(lower, "insufficient cpu"):
			return evidence, "No node has enough unreserved CPU to satisfy the service's resource reservation."
		case strings.Contains(lower, "no suitable node"):
			return evidence, "Placement constraints or node labels exclude every node in the cluster."
		case strings.Contains(lower, "port") && strings.Contains(lower, "in use"):
			return evidence, "The published host port is already bound on the candidate nodes."
		case strings.Contains(lower, "no such image"), strings.Contains(lower, "pull access denied"),
			strings.Contains(lower, "manifest unknown"):
			return evidence, "The image tag does not exist in the registry, or the nodes lack pull credentials."
		case strings.Contains(lower, "mount"), strings.Contains(lower, "volume"):
			return evidence, "A required volume or bind mount is unavailable on the candidate nodes."
		default:
			return evidence, "Task placement was rejected by the scheduler; see the task error for detail."
		}
	}

	return "", ""
}

// buildReplicaFinding assembles the SWM-REP-001 finding for a degraded service.
func buildReplicaFinding(svc swarmService, running, desired int, evidence, reason string) model.Finding {
	if reason == "" {
		reason = "Task placement was rejected — typically insufficient node resources, a port conflict, or an unsatisfiable placement constraint."
	}

	return model.Finding{
		ID:          "SWM-REP-001",
		Title:       fmt.Sprintf("Swarm Service Replica Discrepancy: %s (%s)", svc.Name, svc.Replicas),
		TargetType:  model.TargetSwarm,
		Category:    "Service Convergence",
		Resource:    "service:" + svc.Name,
		Severity:    model.SeverityCritical,
		Symptom:     fmt.Sprintf("Service is running %d of %d desired replicas.", running, desired),
		RootCause:   reason,
		LogEvidence: evidence,
		RemedySteps: []string{
			fmt.Sprintf("Read the full task error: docker service ps %s --no-trunc", svc.Name),
			fmt.Sprintf("Inspect application logs across tasks: docker service logs --tail 50 %s", svc.Name),
			"Compare the service's resource reservations and constraints against actual node capacity",
		},
		QuickFixCmd: fmt.Sprintf("docker service update --force %s", svc.Name),
		Metadata: map[string]string{
			"running": strconv.Itoa(running),
			"desired": strconv.Itoa(desired),
			"image":   svc.Image,
		},
	}
}

// evaluateSwarmNodes scores node reachability and availability.
func evaluateSwarmNodes(nodes []swarmNode) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, n := range nodes {
		switch strings.ToLower(n.Status) {
		case "down", "unknown", "unreachable":
			findings = append(findings, model.Finding{
				ID:         "SWM-NOD-001",
				Title:      fmt.Sprintf("Swarm Node Unreachable: %s", n.Hostname),
				TargetType: model.TargetSwarm,
				Category:   "Cluster Node Down",
				Resource:   "node:" + n.Hostname,
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("Node %s is reporting status %q.", n.Hostname, n.Status),
				RootCause:  "The node lost its gossip connection to the managers — a network partition, a stopped daemon, or an offline host.",
				RemedySteps: []string{
					"Verify the engine is running on the node: systemctl status docker",
					"Confirm the Swarm ports are reachable: 2377/tcp (control), 7946/tcp+udp (gossip), 4789/udp (VXLAN)",
				},
				Metadata: map[string]string{"manager_status": n.ManagerStatus},
			})
		}

		if strings.EqualFold(n.Availability, "drain") {
			findings = append(findings, model.Finding{
				ID:          "SWM-NOD-002",
				Title:       fmt.Sprintf("Swarm Node in Drain State: %s", n.Hostname),
				TargetType:  model.TargetSwarm,
				Category:    "Node Availability",
				Resource:    "node:" + n.Hostname,
				Severity:    model.SeverityInfo,
				Symptom:     fmt.Sprintf("Node %s is marked Drain; the scheduler will place no new tasks on it.", n.Hostname),
				RootCause:   "The node was drained for maintenance. If this was not intentional, cluster capacity is silently reduced.",
				RemedySteps: []string{fmt.Sprintf("Return the node to service when maintenance is complete: docker node update --availability active %s", n.Hostname)},
			})
		}
	}

	return findings
}
