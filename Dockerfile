# syntax=docker/dockerfile:1

# ---- Stage 1: build the static binary -------------------------------------
# The build image must satisfy the `go` directive in go.mod, and should track a
# currently-supported Go release — that is where standard-library security fixes
# land. Pinning an older minor fails the build before any code is compiled.
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Dependencies are copied first so the module download layer is reused whenever
# only application source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# CGO_ENABLED=0 produces a binary with no libc dependency, which is what lets
# the same artifact run on Alpine (musl), Debian (glibc), and scratch.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w \
        -X 'github.com/hi-donwi/OPS-Toolkit/cmd.Version=${VERSION}' \
        -X 'github.com/hi-donwi/OPS-Toolkit/cmd.GitCommit=${COMMIT}' \
        -X 'github.com/hi-donwi/OPS-Toolkit/cmd.BuildDate=${BUILD_DATE}'" \
      -o /opskit .

# ---- Stage 2: runtime ------------------------------------------------------
FROM alpine:3.20

# ca-certificates is required for the TLS certificate audit and webhook
# delivery; tzdata keeps report timestamps correct outside UTC.
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 65532 -S opskit \
    && adduser -u 65532 -S -G opskit opskit

COPY --from=builder /opskit /usr/local/bin/opskit

# The exporter needs no privileges of its own. Deployments that additionally
# diagnose the host or the container runtime grant that access explicitly
# through mounts and capabilities, rather than by running as root by default.
USER 65532:65532

EXPOSE 9876

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/opskit", "version"]

ENTRYPOINT ["/usr/local/bin/opskit"]
CMD ["export-metrics", "--port", "9876", "--interval", "30s"]
