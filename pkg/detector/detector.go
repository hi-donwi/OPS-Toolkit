package detector

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// Detect probes the current host to identify OS, distro, and active container/cluster deployments.
func Detect() model.EnvironmentContext {
	ctx := model.EnvironmentContext{
		OS:       runtime.GOOS,
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		Distro:   detectDistro(),
		Kernel:   detectKernel(),
	}

	// 1. Check for Systemd
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		ctx.HasSystemd = true
	}

	// 2. Check for Docker & Swarm
	ctx.HasDocker, ctx.IsDockerSwarm = detectDockerAndSwarm()

	// 3. Check for Kubernetes
	ctx.HasKubernetes = detectKubernetes()

	// Build active targets list
	targets := []model.TargetType{model.TargetHost}
	if ctx.HasDocker {
		targets = append(targets, model.TargetDocker)
	}
	if ctx.IsDockerSwarm {
		targets = append(targets, model.TargetSwarm)
	}
	if ctx.HasKubernetes {
		targets = append(targets, model.TargetKubernetes)
	}
	targets = append(targets, model.TargetSecurity)

	ctx.ActiveTargets = targets
	return ctx
}

func detectDistro() string {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("sw_vers", "-productVersion").Output()
		if err == nil {
			return "macOS " + strings.TrimSpace(string(out))
		}
		return "macOS"
	}

	// Check /etc/os-release for Linux distros
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				val := strings.TrimPrefix(line, "PRETTY_NAME=")
				return strings.Trim(val, "\"")
			}
		}
	}

	return runtime.GOOS
}

func detectKernel() string {
	out, err := exec.Command("uname", "-r").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "unknown"
}

func detectDockerAndSwarm() (bool, bool) {
	dockerSocket := "/var/run/docker.sock"
	if _, err := os.Stat(dockerSocket); err != nil {
		return false, false
	}

	// Try pinging Docker Socket via HTTP Unix domain socket
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(proto, addr string) (net.Conn, error) {
				return net.DialTimeout("unix", dockerSocket, 1*time.Second)
			},
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get("http://localhost/info")
	if err != nil {
		// Socket file exists but daemon not responsive or permission denied
		return true, false
	}
	defer resp.Body.Close()

	var isSwarm bool
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		// Simple string search for swarm active state in /info JSON
		if strings.Contains(line, `"LocalNodeState":"active"`) || strings.Contains(line, `"Swarm":{"NodeID"`) {
			isSwarm = true
			break
		}
	}

	return true, isSwarm
}

func detectKubernetes() bool {
	// Check in-cluster service account token
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}

	// Check local kubeconfig
	home, err := os.UserHomeDir()
	if err == nil {
		kubeconfig := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeconfig); err == nil {
			return true
		}
	}

	// Check KUBECONFIG env
	if env := os.Getenv("KUBECONFIG"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return true
		}
	}

	return false
}
