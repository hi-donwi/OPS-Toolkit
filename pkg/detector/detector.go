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

	// 1. Check for Systemd (Linux only)
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			ctx.HasSystemd = true
		}
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

func candidateDockerSockets() []string {
	var sockets []string

	// 1. DOCKER_HOST env
	if env := os.Getenv("DOCKER_HOST"); strings.HasPrefix(env, "unix://") {
		sock := strings.TrimPrefix(env, "unix://")
		if sock != "" {
			sockets = append(sockets, sock)
		}
	}

	// 2. Default standard path
	sockets = append(sockets, "/var/run/docker.sock")

	// 3. User socket on macOS (Docker Desktop) or rootless Docker
	if home, err := os.UserHomeDir(); err == nil {
		sockets = append(sockets, filepath.Join(home, ".docker", "run", "docker.sock"))
	}

	// 4. Linux rootless runtime dir
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		sockets = append(sockets, filepath.Join(xdg, "docker.sock"))
	}

	return sockets
}

func detectDockerAndSwarm() (bool, bool) {
	candidates := candidateDockerSockets()
	var socketFound bool

	for _, sock := range candidates {
		if _, err := os.Stat(sock); err != nil {
			continue
		}
		socketFound = true

		// Try pinging Docker Socket via HTTP Unix domain socket
		client := &http.Client{
			Transport: &http.Transport{
				Dial: func(proto, addr string) (net.Conn, error) {
					return net.DialTimeout("unix", sock, 1*time.Second)
				},
			},
			Timeout: 2 * time.Second,
		}

		resp, err := client.Get("http://localhost/info")
		if err != nil {
			// Socket exists but not responsive on this candidate; check next candidate
			continue
		}
		defer resp.Body.Close()

		var body strings.Builder
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			body.WriteString(scanner.Text())
		}
		isSwarm := dockerInfoSwarmActive(body.String())

		return true, isSwarm
	}

	if socketFound {
		return true, false
	}

	return false, false
}

// dockerInfoSwarmActive reports whether Docker /info describes a node that has
// joined a swarm. Docker includes a Swarm object with a NodeID even when
// LocalNodeState is inactive, so the object alone is not membership.
func dockerInfoSwarmActive(body string) bool {
	compact := strings.ReplaceAll(body, " ", "")
	return strings.Contains(compact, `"LocalNodeState":"active"`)
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
