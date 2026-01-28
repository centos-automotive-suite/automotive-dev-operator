# Build the manager binary
FROM registry.access.redhat.com/ubi9/go-toolset:1.24.6 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy files as root first
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/
COPY cmd/main.go cmd/main.go
COPY cmd/build-api/main.go cmd/build-api/main.go
COPY cmd/init-secrets/main.go cmd/init-secrets/main.go
COPY api/ api/
COPY internal/ internal/

# Set ownership and switch to non-root user (go-toolset runs as 1001)
USER root
RUN chown -R 1001:0 /workspace && chmod -R 775 /workspace
USER 1001

ENV CGO_ENABLED=0
ENV GOCACHE=/workspace/.cache
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags "-s -w" -o manager cmd/main.go
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags "-s -w" -o build-api cmd/build-api/main.go
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags "-s -w" -o init-secrets cmd/init-secrets/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/build-api .
COPY --from=builder /workspace/init-secrets .
# Include CA bundle so OIDC discovery works without custom CA config
COPY --from=builder /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/tls/certs/ca-bundle.crt
USER 65532:65532

ENTRYPOINT ["/manager"]
