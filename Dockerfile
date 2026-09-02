ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi10/go-toolset:10.2-1787080020 AS builder
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/
COPY cmd/main.go cmd/main.go
COPY cmd/build-api/main.go cmd/build-api/main.go
COPY api/ api/
COPY internal/ internal/

USER root
RUN chown -R 1001:0 /workspace && chmod -R 775 /workspace
USER 1001

ENV CGO_ENABLED=0
ENV GOCACHE=/workspace/.cache
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags "-s -w" -o manager cmd/main.go
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags "-s -w" -o build-api cmd/build-api/main.go

FROM --platform=$TARGETPLATFORM registry.access.redhat.com/ubi10/ubi-minimal:latest

ARG VERSION=0.0.0
LABEL com.redhat.component="automotive-dev-operator-container" \
      name="automotive-dev-operator" \
      summary="Automotive Dev Operator" \
      description="OpenShift operator for automotive OS development" \
      io.k8s.display-name="Automotive Dev Operator" \
      io.k8s.description="Kubernetes operator for automotive OS development" \
      io.openshift.tags="automotive,operator" \
      vendor="Red Hat" \
      version="${VERSION}" \
      release="1"

COPY LICENSE /licenses/LICENSE

WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/build-api .
USER 65532:65532

ENTRYPOINT ["/manager"]
