# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Build all binaries
make build                    # Builds manager and init-secrets binaries

# Build specific components
make build-caib               # Build CLI tool
make build-api-server         # Build API server

# Run tests
make test                     # Run unit tests with coverage
go test ./test/e2e/ -v -ginkgo.v  # Run e2e tests

# Lint
make lint                     # Run golangci-lint
make lint-fix                 # Run linter with auto-fix

# Generate code after modifying API types
make generate                 # Generate DeepCopy methods
make manifests                # Generate CRDs, RBAC, webhooks

# Local development
go run ./cmd/main.go          # Run controller locally
go run ./cmd/build-api/ --kubeconfig-path ~/.kube/config  # Run API server locally

# Kubernetes deployment via OLM catalog (preferred method)
# IMPORTANT: Before running deploy-catalog.sh (redeploy or uninstall), you MUST:
#   1. Run: oc whoami --show-server && oc whoami
#   2. Show the cluster URL and user to the user
#   3. Ask the user to confirm this is the correct cluster
#   4. Only proceed with -y flag after user confirms
./hack/deploy-catalog.sh -y --keep-config          # Full redeploy: uninstall, build, install
./hack/deploy-catalog.sh uninstall -y              # Uninstall the operator only
./hack/deploy-catalog.sh build                     # Build and push images only (no install, no confirmation needed)
```

## Architecture

This is a Kubernetes operator for automotive OS image building, built with Kubebuilder and controller-runtime.

### Custom Resources (api/v1alpha1/)
- **ImageBuild**: Triggers an automotive OS image build via Tekton TaskRuns. Supports traditional AIB manifests and bootc container builds.
- **Image**: Represents a built image with location metadata (registry storage).
- **OperatorConfig**: Cluster-wide operator configuration (OS builds settings, memory volumes).

### Controllers (internal/controller/)
- **imagebuild/**: Reconciles ImageBuild CRs, creates Tekton TaskRuns, manages build lifecycle.
- **image/**: Manages Image CRs and their status.
- **operatorconfig/**: Deploys/undeploys optional components (Tekton tasks) based on OperatorConfig.

### Components
- **Controller Manager** (cmd/main.go): Main operator process running all controllers.
- **Build API** (cmd/build-api/, internal/buildapi/): REST API for build operations, used by CLI.
- **caib CLI** (cmd/caib/): CLI tool for creating/monitoring builds. See cmd/caib/README.md for usage.
- **Init Secrets** (cmd/init-secrets/): Init container for OAuth secret setup.

### Key Integrations
- **Tekton Pipelines**: Builds run as Tekton TaskRuns. Task definitions in internal/common/tasks/.
- **OpenShift**: Route support for artifact serving, OAuth integration for authentication.
- **automotive-image-builder (AIB)**: External tool invoked by build tasks to create automotive OS images.

## Coding Guidelines

- Add failing tests before starting implementation.
- Keep summaries short.
- Container tool defaults to `podman` (CONTAINER_TOOL variable in Makefile).
- After modifying types in api/v1alpha1/, run `make generate manifests`.
- To edit Tekton Tasks/Pipelines without the operator overwriting changes, annotate with `automotive.sdv.cloud.redhat.com/unmanaged=true`. See DEVELOPMENT.md for details.

## Active Technologies
- Go 1.22+, Kubebuilder, controller-runtime, Kubernetes client-go
- Tekton Pipelines for build execution
- Container registries for image artifacts
