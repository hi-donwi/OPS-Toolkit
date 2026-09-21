package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// restartLoopThreshold is the restart count above which a container is treated
// as crash-looping rather than merely having been restarted.
const restartLoopThreshold = 5

// dockerPS is one row of `docker ps` output.
type dockerPS struct {
	ID      string
	Name    string
	Status  string
	Image   string
	RunFor  string
	Command string
}

// parseDockerPS parses tab-separated `docker ps --format` rows. Docker emits a
// fixed column count, but a truncated or mid-write read can deliver fewer, so
// every column beyond the first is optional rather than indexed blindly.
func parseDockerPS(output string) []dockerPS {
	rows := make([]dockerPS, 0)

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}

		row := dockerPS{ID: fields[0], Name: fields[1]}
		if len(fields) > 2 {
			row.Status = fields[2]
		}
		if len(fields) > 3 {
			row.Image = fields[3]
		}
		if len(fields) > 4 {
			row.RunFor = fields[4]
		}
		rows = append(rows, row)
	}

	return rows
}

// exitCodeFromStatus extracts N from a `Exited (N) 3 minutes ago` status string.
func exitCodeFromStatus(status string) (int, bool) {
	open := strings.Index(status, "(")
	if open < 0 || !strings.HasPrefix(strings.TrimSpace(status), "Exited") {
		return 0, false
	}
	close := strings.Index(status[open:], ")")
	if close < 0 {
		return 0, false
	}
	code, err := strconv.Atoi(strings.TrimSpace(status[open+1 : open+close]))
	if err != nil {
		return 0, false
	}
	return code, true
}

// evaluateDocker runs every DOC-* rule.
func (e *Engine) evaluateDocker(ctx context.Context) []model.Finding {
	if !e.env.HasDocker || !e.run.Available("docker") {
		return nil
	}

	findings := make([]model.Finding, 0, 8)

	exited, err := e.run.Run(ctx, 15*time.Second, "docker", "ps", "-a",
		"--filter", "status=exited",
		"--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}")
	if err == nil {
		findings = append(findings, evaluateExitedContainers(parseDockerPS(string(exited)))...)
	}

	unhealthy, err := e.run.Run(ctx, 15*time.Second, "docker", "ps",
		"--filter", "health=unhealthy",
		"--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}")
	if err == nil {
		findings = append(findings, evaluateUnhealthyContainers(parseDockerPS(string(unhealthy)))...)
	}

	findings = append(findings, e.checkRestartLoops(ctx)...)
	findings = append(findings, e.checkDockerDiskFootprint(ctx)...)

	if len(findings) == 0 {
		findings = append(findings, model.Finding{
			ID:         "DOC-ALL-001",
			Title:      "Docker Containers Operating Normally",
			TargetType: model.TargetDocker,
			Category:   "Container Health",
			Resource:   "docker:engine",
			Severity:   model.SeverityPass,
			Symptom:    "No crashed, OOMKilled, restart-looping, or unhealthy containers detected.",
		})
	}

	return findings
}

// evaluateExitedContainers scores containers by their exit code. The codes are
// the standard 128+signal encoding, so 137 is SIGKILL (almost always the cgroup
// OOM killer) and 139 is SIGSEGV.
func evaluateExitedContainers(rows []dockerPS) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, c := range rows {
		code, ok := exitCodeFromStatus(c.Status)
		if !ok || code == 0 {
			continue
		}

		meta := map[string]string{"container_id": c.ID, "exit_code": strconv.Itoa(code)}
		if c.Image != "" {
			meta["image"] = c.Image
		}

		switch code {
		case 137:
			findings = append(findings, model.Finding{
				ID:         "DOC-EXT-137",
				Title:      fmt.Sprintf("Docker Container OOMKilled: %s", c.Name),
				TargetType: model.TargetDocker,
				Category:   "Crash & Resource Saturation",
				Resource:   "container:" + c.Name,
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("Container terminated with exit code 137 (SIGKILL / OOMKilled). Image: %s", c.Image),
				RootCause:  "The container process exceeded its cgroup memory limit, or the host kernel OOM killer reclaimed it.",
				RemedySteps: []string{
					fmt.Sprintf("Confirm the kill was OOM rather than a manual stop: docker inspect --format '{{.State.OOMKilled}}' %s", c.ID),
					fmt.Sprintf("Raise the limit once you know the true working set: docker update --memory <limit> %s", c.ID),
					fmt.Sprintf("Read the last output before death: docker logs --tail 50 %s", c.ID),
				},
				QuickFixCmd: fmt.Sprintf("docker start %s", c.ID),
				Metadata:    meta,
			})
		case 139:
			findings = append(findings, model.Finding{
				ID:         "DOC-EXT-139",
				Title:      fmt.Sprintf("Docker Container Segmentation Fault: %s", c.Name),
				TargetType: model.TargetDocker,
				Category:   "Process Crash",
				Resource:   "container:" + c.Name,
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("Container crashed with exit code 139 (SIGSEGV). Image: %s", c.Image),
				RootCause:  "A native memory access violation, or a binary linked against a libc the base image does not provide (the classic glibc binary on an Alpine/musl image).",
				RemedySteps: []string{
					fmt.Sprintf("Check the crash output: docker logs --tail 50 %s", c.ID),
					"Verify the base image libc matches what the binary was compiled against",
				},
				Metadata: meta,
			})
		case 127:
			findings = append(findings, model.Finding{
				ID:         "DOC-EXT-127",
				Title:      fmt.Sprintf("Docker Container Entrypoint Not Found: %s", c.Name),
				TargetType: model.TargetDocker,
				Category:   "Configuration Failure",
				Resource:   "container:" + c.Name,
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("Container exited with code 127 (command not found). Image: %s", c.Image),
				RootCause:  "The ENTRYPOINT or CMD binary does not exist in the image, is not on PATH, or the script has CRLF line endings that break its shebang.",
				RemedySteps: []string{
					fmt.Sprintf("List what the image actually ships: docker run --rm --entrypoint sh %s -c 'ls -l /'", c.Image),
					"Confirm the entrypoint script is executable and uses LF line endings",
				},
				Metadata: meta,
			})
		default:
			findings = append(findings, model.Finding{
				ID:         "DOC-EXT-ERR",
				Title:      fmt.Sprintf("Docker Container Abrupt Exit: %s", c.Name),
				TargetType: model.TargetDocker,
				Category:   "Service Downtime",
				Resource:   "container:" + c.Name,
				Severity:   model.SeverityWarning,
				Symptom:    fmt.Sprintf("Container exited unexpectedly with code %d: %s", code, c.Status),
				RootCause:  "The application terminated with a non-zero status — an unhandled exception, a failed health dependency, or missing configuration.",
				RemedySteps: []string{
					fmt.Sprintf("Inspect the container logs: docker logs --tail 50 %s", c.ID),
				},
				QuickFixCmd: fmt.Sprintf("docker restart %s", c.ID),
				Metadata:    meta,
			})
		}
	}

	return findings
}

// evaluateUnhealthyContainers scores containers failing their HEALTHCHECK.
func evaluateUnhealthyContainers(rows []dockerPS) []model.Finding {
	findings := make([]model.Finding, 0, len(rows))

	for _, c := range rows {
		findings = append(findings, model.Finding{
			ID:         "DOC-HLT-001",
			Title:      fmt.Sprintf("Docker Container Healthcheck Failing: %s", c.Name),
			TargetType: model.TargetDocker,
			Category:   "Health Probe Failure",
			Resource:   "container:" + c.Name,
			Severity:   model.SeverityWarning,
			Symptom:    fmt.Sprintf("Container is reporting UNHEALTHY to the Docker daemon (%s).", c.Status),
			RootCause:  "The image's HEALTHCHECK command returned non-zero for more consecutive attempts than its configured retries.",
			RemedySteps: []string{
				fmt.Sprintf("Read the recorded probe output: docker inspect --format '{{json .State.Health}}' %s", c.ID),
				"Confirm the probe targets a real readiness endpoint and its timeout exceeds normal response time",
			},
			Metadata: map[string]string{"container_id": c.ID},
		})
	}

	return findings
}

// checkRestartLoops implements DOC-RES-001: containers that are nominally up but
// are being restarted repeatedly by the daemon's restart policy. These never
// appear in `status=exited`, so a crash loop is otherwise invisible.
func (e *Engine) checkRestartLoops(ctx context.Context) []model.Finding {
	out, err := e.run.Run(ctx, 15*time.Second, "docker", "ps", "-a",
		"--format", "{{.ID}}\t{{.Names}}")
	if err != nil {
		return nil
	}

	rows := parseDockerPS(string(out))
	if len(rows) == 0 {
		return nil
	}

	// Try batching all container IDs in a single inspect command
	ids := make([]string, 0, len(rows))
	for _, c := range rows {
		ids = append(ids, c.ID)
	}

	inspectArgs := append([]string{"inspect", "--format", "{{.RestartCount}}\t{{.State.Status}}\t{{.HostConfig.RestartPolicy.Name}}"}, ids...)
	batchOut, err := e.run.Run(ctx, 15*time.Second, "docker", inspectArgs...)
	if err == nil {
		inspectLines := strings.Split(strings.TrimSpace(string(batchOut)), "\n")
		if len(inspectLines) == len(rows) {
			findings := make([]model.Finding, 0)
			for i, c := range rows {
				if f, ok := evaluateRestartLoop(c, inspectLines[i]); ok {
					findings = append(findings, f)
				}
			}
			return findings
		}
	}

	// Fallback to per-container inspect if batch command failed or lines mismatch
	findings := make([]model.Finding, 0)
	for _, c := range rows {
		inspect, err := e.run.Run(ctx, 10*time.Second, "docker", "inspect",
			"--format", "{{.RestartCount}}\t{{.State.Status}}\t{{.HostConfig.RestartPolicy.Name}}", c.ID)
		if err != nil {
			continue
		}

		if f, ok := evaluateRestartLoop(c, string(inspect)); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

// evaluateRestartLoop scores a single container's restart history.
func evaluateRestartLoop(c dockerPS, inspectOutput string) (model.Finding, bool) {
	fields := strings.Split(strings.TrimSpace(inspectOutput), "\t")
	if len(fields) < 1 {
		return model.Finding{}, false
	}

	count, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil || count <= restartLoopThreshold {
		return model.Finding{}, false
	}

	state := "unknown"
	if len(fields) > 1 {
		state = strings.TrimSpace(fields[1])
	}
	policy := "unknown"
	if len(fields) > 2 {
		policy = strings.TrimSpace(fields[2])
	}

	return model.Finding{
		ID:         "DOC-RES-001",
		Title:      fmt.Sprintf("Docker Container Restart Loop: %s", c.Name),
		TargetType: model.TargetDocker,
		Category:   "Crash Loop",
		Resource:   "container:" + c.Name,
		Severity:   model.SeverityCritical,
		Symptom:    fmt.Sprintf("Container has been restarted %d times (current state: %s, restart policy: %s).", count, state, policy),
		RootCause:  "The process keeps terminating and the restart policy keeps reviving it. The restart policy is masking a persistent startup failure rather than fixing it.",
		RemedySteps: []string{
			fmt.Sprintf("Read the logs from the failed generation: docker logs --tail 100 %s", c.ID),
			fmt.Sprintf("Check the last exit code and OOM flag: docker inspect --format '{{.State.ExitCode}} {{.State.OOMKilled}}' %s", c.ID),
			"Fix the startup failure, then restore the restart policy — do not raise the retry limit",
		},
		Metadata: map[string]string{
			"container_id":  c.ID,
			"restart_count": strconv.Itoa(count),
		},
	}, true
}

// -----------------------------------------------------------------------------
// DOC-DSK-001 — Docker's share of the root filesystem
// -----------------------------------------------------------------------------

// dockerDiskUsage is the parsed output of `docker system df`.
type dockerDiskUsage struct {
	Images      uint64
	Containers  uint64
	Volumes     uint64
	BuildCache  uint64
	Reclaimable uint64
}

// Total reports the bytes Docker occupies across all object types.
func (d dockerDiskUsage) Total() uint64 {
	return d.Images + d.Containers + d.Volumes + d.BuildCache
}

// dockerDiskThreshold is the share of the filesystem above which Docker's own
// footprint is worth reporting.
const dockerDiskThreshold = 0.50

// parseDockerSystemDF parses `docker system df --format "{{.Type}}\t{{.Size}}\t{{.Reclaimable}}"`.
func parseDockerSystemDF(output string) dockerDiskUsage {
	var usage dockerDiskUsage

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}

		size := parseDockerSize(fields[1])
		switch strings.TrimSpace(fields[0]) {
		case "Images":
			usage.Images = size
		case "Containers":
			usage.Containers = size
		case "Local Volumes":
			usage.Volumes = size
		case "Build Cache":
			usage.BuildCache = size
		}

		if len(fields) > 2 {
			// The reclaimable column reads like "12.4GB (76%)"; only the size
			// leads, so the percentage suffix is discarded.
			usage.Reclaimable += parseDockerSize(strings.Fields(fields[2])[0])
		}
	}

	return usage
}

// parseDockerSize converts a Docker-formatted size ("1.234GB", "512kB", "0B")
// into bytes. Docker uses decimal SI units in this output, not binary ones.
func parseDockerSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	multipliers := []struct {
		suffix string
		factor float64
	}{
		{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"kB", 1e3}, {"KB", 1e3}, {"B", 1},
	}

	for _, m := range multipliers {
		if !strings.HasSuffix(s, m.suffix) {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(s, m.suffix)), 64)
		if err != nil {
			return 0
		}
		return uint64(value * m.factor)
	}

	return 0
}

// checkDockerDiskFootprint implements DOC-DSK-001.
func (e *Engine) checkDockerDiskFootprint(ctx context.Context) []model.Finding {
	out, err := e.run.Run(ctx, 20*time.Second, "docker", "system", "df",
		"--format", "{{.Type}}\t{{.Size}}\t{{.Reclaimable}}")
	if err != nil {
		return nil
	}

	fsInfo, err := e.statfs(rootFilesystemPath())
	if err != nil {
		return nil
	}

	return evaluateDockerDiskFootprint(parseDockerSystemDF(string(out)), fsInfo.TotalBytes())
}

// evaluateDockerDiskFootprint reports when Docker dominates the filesystem.
// Disk exhaustion caused by image and layer accumulation is one of the most
// common container-host outages, and it is invisible from a plain `df` because
// the space sits under a single directory.
func evaluateDockerDiskFootprint(usage dockerDiskUsage, filesystemBytes uint64) []model.Finding {
	if filesystemBytes == 0 || usage.Total() == 0 {
		return nil
	}

	share := float64(usage.Total()) / float64(filesystemBytes)
	if share < dockerDiskThreshold {
		return nil
	}

	return []model.Finding{{
		ID:         "DOC-DSK-001",
		Title:      "Docker Storage Dominates the Root Filesystem",
		TargetType: model.TargetDocker,
		Category:   "Storage Saturation",
		Resource:   "docker:storage",
		Severity:   model.SeverityWarning,
		Symptom: fmt.Sprintf("Docker occupies %s (%.0f%% of the %s filesystem); %s of that is reclaimable.",
			humanBytes(usage.Total()), share*100, humanBytes(filesystemBytes), humanBytes(usage.Reclaimable)),
		RootCause: "Accumulated images, stopped containers, dangling volumes, and build cache are never reclaimed automatically. This is the usual cause of a container host filling up without any application growing.",
		RemedySteps: []string{
			"Review the breakdown before deleting anything: docker system df -v",
			"Reclaim dangling images, stopped containers, and build cache: docker system prune -a",
			"Schedule periodic pruning, and set log rotation so container logs stop growing unbounded",
		},
		QuickFixCmd: "docker system prune -f",
		Metadata: map[string]string{
			"total_bytes":       strconv.FormatUint(usage.Total(), 10),
			"reclaimable_bytes": strconv.FormatUint(usage.Reclaimable, 10),
		},
	}}
}
