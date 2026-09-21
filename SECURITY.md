# Security

## What opskit touches

Worth knowing before you run it on a production host, and before you decide what
to grant it.

**It reads.** `/proc`, `statfs` on the root filesystem, `/etc/os-release`,
`/etc/resolv.conf`, `/etc/ssh/sshd_config`, permission bits on `/etc/shadow`,
`/etc/passwd`, `/etc/sudoers` and similar, certificate files under
`/etc/ssl/certs`, `/etc/letsencrypt/live` and `/etc/pki/tls/certs`, and the rule
files in `rules.d/` and `~/.opskit/rules.d/`.

**It executes.** `dmesg`, `systemctl --failed`, `docker`, `kubectl`, and `ping`,
using whatever is on your `PATH`. Arguments are fixed by the rule that issues
them; nothing from a config file or a command line is interpolated into them.
Every invocation carries a timeout.

**It connects.** TCP to `127.0.0.1` on a small set of ports (2375, 6379, 27017,
2379, 11211) to see whether an unauthenticated service is listening, and to any
port a custom rule names in `port_listening`. TLS to whatever endpoint you pass
to `opskit audit certs`. `opskit daemon` posts to the webhook URL you configure.
`opskit explain` contacts a local Ollama when one is running (`OLLAMA_HOST`,
default `http://localhost:11434`) and falls back to offline templates when it is
not. Docker detection talks to `/var/run/docker.sock` over a unix socket.

**It contacts third-party infrastructure by default.** Worth knowing before you
run it somewhere restricted:

| What | When | Change it with |
|---|---|---|
| Resolves `google.com` | Every `diag` run, to time DNS | `OPSKIT_DNS_PROBE` |
| Queries `1.1.1.1:53` and `8.8.8.8:53` directly | `opskit net`, to compare your resolvers against known-good ones | not configurable today |
| Pings and TCP-connects `1.1.1.1` | `opskit net` with no target given | pass a target: `opskit net <host>` |

None of this reports anything about you — it is reachability and latency
measurement, and the payloads are a DNS question and an ICMP echo. But it is
outbound traffic to Cloudflare and Google, and in an air-gapped or
egress-filtered environment you should set `OPSKIT_DNS_PROBE` and always name
your own target for `opskit net`.

**It does not** send telemetry, report usage, or transmit anything to the author
or to any service beyond what is listed above.

## What it writes

Nothing, unless you ask. `-o` writes a report where you point it.
`opskit fix` executes remediation commands, and that is the one path that
changes your system — see below.

## `opskit fix`

`--dry-run` is the default. Nothing runs until you pass `--dry-run=false` or
`-y`.

Commands come from opskit's own rule set and from rule files you wrote, and are
executed through `sh -c` because several of them use shell operators. Each is
graded first — `LOW`, `MEDIUM`, or `HIGH` — and `--max-risk` refuses anything
above a grade you choose. The grading is a heuristic over the command text: it
decides what deserves a second look, never that something is safe to run
unattended.

Applying requires an interactive confirmation, or `-y`. With stdin not attached
to a terminal and no `-y`, it refuses rather than reading approval from whatever
happens to be piped in.

Treat `rules.d/*.yaml` as executable content, because `quick_fix_cmd` is exactly
that. Do not load rule files from a source you would not trust with a shell.

## Running it with privileges

Most host checks need root or `CAP_SYSLOG` to be useful — `dmesg` is commonly
restricted by `kernel.dmesg_restrict`, and permission checks on `/etc/shadow`
need to stat it. opskit degrades rather than failing: a check it cannot perform
is skipped, not reported as a pass.

The container images run as UID 65532. The Kubernetes and Swarm manifests mount
the host's `/proc` read-only and set `OPSKIT_PROC_ROOT`, and grant nothing else.
Give it more only if you want the checks that need more.

## Secret handling

`opskit explain` may send a finding's log evidence to a local LLM. That text is
scrubbed first: bearer tokens, `password`/`secret`/`token`/`api_key`
assignments, AWS access key IDs, and PEM private key blocks are replaced with
placeholders. The scrubber is pattern-based and is a safety net, not a
guarantee. If your logs contain secrets in a shape it does not recognise,
`explain` is not the command to reach for.

Reports include command output and log excerpts. Treat a saved report as
sensitive, particularly before attaching one to a ticket.

## Reporting a vulnerability

Please do not open a public issue.

Use GitHub's private reporting — **Security → Report a vulnerability** on the
repository — or email <hi.donwi@gmail.com>.

Include what you did, what happened, and what you expected. A reproduction case
helps more than anything else.

This is a personal project maintained in spare time, so I cannot promise a
response window. I will acknowledge what I receive and be straight with you
about whether and when I can fix it.

## Supported versions

The most recent release. There are no maintained backport branches.

Release binaries are built on a currently-supported Go toolchain, which is where
standard-library security fixes land, and CI runs `govulncheck` on every push.
