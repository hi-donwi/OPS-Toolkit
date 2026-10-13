package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func (e *Engine) checkDataServices(ctx context.Context) []model.Finding {
	findings := make([]model.Finding, 0, 2)
	if strings.TrimSpace(os.Getenv("OPSKIT_MONGO_URI")) != "" {
		findings = append(findings, e.checkMongo(ctx)...)
	}
	if strings.TrimSpace(os.Getenv("OPSKIT_REDIS_ADDR")) != "" {
		findings = append(findings, e.checkRedis(ctx)...)
	}
	return findings
}

func (e *Engine) checkMongo(ctx context.Context) []model.Finding {
	uri, err := url.Parse(strings.TrimSpace(os.Getenv("OPSKIT_MONGO_URI")))
	if err != nil || uri.Host == "" || (uri.Scheme != "mongodb" && uri.Scheme != "mongodb+srv") {
		return []model.Finding{collectionUnavailable("DATA-MONGO-000", model.TargetHost, "mongodb:hello", fmt.Errorf("OPSKIT_MONGO_URI must be an explicit MongoDB URI"))}
	}
	if !e.run.Available("mongosh") {
		return []model.Finding{dataProbeUnavailable("DATA-MONGO-000", "mongosh")}
	}
	out, err := e.run.Run(ctx, 10*time.Second, "mongosh", "--quiet", "--norc", "--nodb", "--eval",
		"const connection = new Mongo(process.env.OPSKIT_MONGO_URI); print(JSON.stringify(connection.getDB('admin').runCommand({hello:1})))")
	if err != nil {
		return []model.Finding{collectionUnavailable("DATA-MONGO-000", model.TargetHost, "mongodb:hello", err)}
	}
	return evaluateMongoHello(string(out))
}

func (e *Engine) checkRedis(ctx context.Context) []model.Finding {
	if !e.run.Available("redis-cli") {
		return []model.Finding{dataProbeUnavailable("DATA-REDIS-000", "redis-cli")}
	}
	addr := strings.TrimSpace(os.Getenv("OPSKIT_REDIS_ADDR"))
	host, port, err := net.SplitHostPort(addr)
	number, parseErr := strconv.Atoi(port)
	if err != nil || host == "" || parseErr != nil || number < 1 || number > 65535 {
		return []model.Finding{collectionUnavailable("DATA-REDIS-000", model.TargetHost, "redis:info", fmt.Errorf("OPSKIT_REDIS_ADDR must be host:port"))}
	}
	args := []string{"-h", host, "-p", port}
	if user := strings.TrimSpace(os.Getenv("OPSKIT_REDIS_USER")); user != "" {
		args = append(args, "--user", user)
	}
	if os.Getenv("OPSKIT_REDIS_TLS") == "1" {
		args = append(args, "--tls")
		if ca := strings.TrimSpace(os.Getenv("OPSKIT_REDIS_CA")); ca != "" {
			args = append(args, "--cacert", ca)
		}
	} else if strings.TrimSpace(os.Getenv("OPSKIT_REDIS_CA")) != "" {
		return []model.Finding{collectionUnavailable("DATA-REDIS-000", model.TargetHost, "redis:info", fmt.Errorf("OPSKIT_REDIS_CA requires OPSKIT_REDIS_TLS=1"))}
	}
	out, err := e.run.Run(ctx, 10*time.Second, "redis-cli", append(args, "INFO", "replication")...)
	if err != nil {
		return []model.Finding{collectionUnavailable("DATA-REDIS-000", model.TargetHost, "redis:info", err)}
	}
	return evaluateRedisReplication(string(out))
}

func dataProbeUnavailable(id, binary string) model.Finding {
	return model.Finding{
		ID:         id,
		Title:      "Data Probe Binary Unavailable",
		TargetType: model.TargetHost,
		Category:   "Collection",
		Resource:   "binary:" + binary,
		Severity:   model.SeverityWarning,
		Symptom:    binary + " is not on PATH, so the requested read-only probe did not run.",
		Metadata:   map[string]string{"collection_error": "true"},
		RemedySteps: []string{
			"Install the client on the operator host or run the probe from a host that already has it",
		},
	}
}

type mongoHello struct {
	SetName           string `json:"setName"`
	IsWritablePrimary bool   `json:"isWritablePrimary"`
	Secondary         bool   `json:"secondary"`
	OK                int    `json:"ok"`
}

func evaluateMongoHello(raw string) []model.Finding {
	var hello mongoHello
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &hello); err != nil || hello.OK != 1 {
		return []model.Finding{collectionUnavailable("DATA-MONGO-000", model.TargetHost, "mongodb:hello", fmt.Errorf("unreadable hello response"))}
	}
	if hello.SetName == "" {
		return []model.Finding{{
			ID:         "DATA-MONGO-001",
			Title:      "MongoDB Is Not a Replica Set",
			TargetType: model.TargetHost,
			Category:   "Data Services",
			Resource:   "mongodb:hello",
			Severity:   model.SeverityWarning,
			Symptom:    "The server answered hello but did not report a replica set name.",
		}}
	}
	role := "secondary"
	if hello.IsWritablePrimary {
		role = "primary"
	} else if !hello.Secondary {
		return []model.Finding{{
			ID: "DATA-MONGO-001", Title: "MongoDB Member Is Not Serving", TargetType: model.TargetHost,
			Category: "Data Services", Resource: "mongodb:" + hello.SetName, Severity: model.SeverityWarning,
			Symptom: "Member is neither writable primary nor secondary. Replica-set membership alone is not readiness.",
		}}
	}
	return []model.Finding{{
		ID:         "DATA-MONGO-001",
		Title:      "MongoDB Replica Set Member Answered",
		TargetType: model.TargetHost,
		Category:   "Data Services",
		Resource:   "mongodb:" + hello.SetName,
		Severity:   model.SeverityPass,
		Symptom:    fmt.Sprintf("Member role is %s in set %s.", role, hello.SetName),
		Metadata:   map[string]string{"role": role, "set": hello.SetName},
	}}
}

func evaluateRedisReplication(raw string) []model.Finding {
	info := parseRedisInfo(raw)
	role := info["role"]
	if role != "master" && role != "slave" {
		return []model.Finding{collectionUnavailable("DATA-REDIS-000", model.TargetHost, "redis:info", fmt.Errorf("replication info did not include role"))}
	}
	if role == "master" {
		count, err := strconv.Atoi(info["connected_slaves"])
		if err != nil || count < 0 {
			return []model.Finding{collectionUnavailable("DATA-REDIS-000", model.TargetHost, "redis:info", fmt.Errorf("connected replica count is unavailable"))}
		}
		if count == 0 {
			return []model.Finding{{
				ID: "DATA-REDIS-001", Title: "Redis Has No Connected Replicas", TargetType: model.TargetHost,
				Category: "Data Services", Resource: "redis:replication", Severity: model.SeverityWarning,
				Symptom: "Primary answered, but no replica is connected. This is not HA readiness.",
			}}
		}
	}
	if role == "slave" && info["master_link_status"] != "up" {
		return []model.Finding{{
			ID:         "DATA-REDIS-001",
			Title:      "Redis Replica Link Down",
			TargetType: model.TargetHost,
			Category:   "Data Services",
			Resource:   "redis:replication",
			Severity:   model.SeverityCritical,
			Symptom:    "master_link_status is " + info["master_link_status"],
		}}
	}
	return []model.Finding{{
		ID:         "DATA-REDIS-001",
		Title:      "Redis Replication Answered",
		TargetType: model.TargetHost,
		Category:   "Data Services",
		Resource:   "redis:replication",
		Severity:   model.SeverityPass,
		Symptom:    fmt.Sprintf("role=%s connected_slaves=%s", role, info["connected_slaves"]),
		Metadata:   map[string]string{"role": role, "connected_slaves": info["connected_slaves"]},
	}}
}

func parseRedisInfo(raw string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if ok {
			out[key] = value
		}
	}
	return out
}
