# End-to-End Tests

This directory contains end-to-end tests for the Automotive Dev Operator.

## Prerequisites

- [Go](https://golang.org/dl/) (version 1.24+)
- [Kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Docker](https://www.docker.com/)
- [Tekton Pipelines](https://tekton.dev/) (will be installed automatically)

## Running E2E Tests Locally

### Local CRC/OpenShift (recommended)

Set up a local CRC cluster first, then use the local runner:

```bash
# One-time setup: provision CRC and expose the internal registry
hack/crc/setup-crc.sh

# Run a single lane or all tests
bash hack/run-e2e-local.sh operator
bash hack/run-e2e-local.sh auth
bash hack/run-e2e-local.sh bootc
bash hack/run-e2e-local.sh            # all lanes
```

See [hack/crc/README.md](../../hack/crc/README.md) for CRC setup details and prerequisites.

### Quick Start

```bash
# Run all e2e tests (this will create a Kind cluster, deploy the operator, and run tests)
make test-e2e
```

### Manual Setup

If you want more control over the test environment:

1. **Create a Kind cluster:**
   ```bash
   kind create cluster --name automotive-dev-e2e
   ```

2. **Install Tekton Pipelines:**
   ```bash
   kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
   kubectl wait --for=condition=ready pod --all -n tekton-pipelines --timeout=5m
   ```

3. **Build and load the operator image:**
   ```bash
   make docker-build IMG=automotive-dev-operator:test
   kind load docker-image automotive-dev-operator:test --name automotive-dev-e2e
   ```

4. **Install CRDs and deploy the operator:**
   ```bash
   make install
   make deploy IMG=automotive-dev-operator:test
   ```

5. **Wait for the operator to be ready:**
   ```bash
   kubectl wait --for=condition=available --timeout=5m deployment/ado-operator -n automotive-dev-operator-system
   ```

6. **Run the tests:**
   ```bash
   go test ./test/e2e/ -v -ginkgo.v
   ```

7. **Cleanup:**
   ```bash
   kind delete cluster --name automotive-dev-e2e
   ```

## Test Lanes

Tests are split into independently-runnable lanes, each deployed into its own namespace:

| Lane | Label | Namespace | What it covers |
|------|-------|-----------|----------------|
| `smoke` | `smoke` | `e2e-smoke` | CRDs, OperatorConfig, Build API endpoints, CR lifecycle, guard rails |
| `operator` | `operator` | `e2e-operator` | Operator health, Tekton tasks/pipeline, Build API CRUD, ImageBuild lifecycle, error handling |
| `features` | `features` | `e2e-features` | TTL expiry, image propagation in Tekton Tasks, Build API log streaming |
| `auth` | `auth` | `e2e-auth` | OIDC authentication (OpenShift or Kind+Dex) |
| `bootc` | `bootc` | `e2e-bootc` | Bootc container build via caib CLI |
| `internal-registry` | `internal-registry` | `e2e-internal-registry` | Internal-registry build path via `--internal-registry` (OpenShift only) |
| `package-mode` | `package-mode`, `smoke` | `e2e-package-mode` | Package mode disk image build (OpenShift only) |
| `container-build` | `container-build` | `e2e-container-build` | Shipwright container builds via `caib container build` (OpenShift only) |
| `manifest-validation` | `manifest-validation` | `e2e-manifest-validation` | AIB manifest schema/unknown-field validation behavior |
| `catalog` | `catalog` | `e2e-catalog` | Catalog discovery listing, sorting, latest filtering, and detail output |

### Running individual lanes

```bash
# Via Makefile
make test-e2e-smoke
make test-e2e-operator
make test-e2e-bootc
make test-e2e-container-build
make test-e2e-auth
make test-e2e-package-mode
make test-e2e-features
make test-e2e              # all lanes

# Via local runner (handles CRC/OpenShift setup)
bash hack/run-e2e-local.sh smoke
bash hack/run-e2e-local.sh operator
bash hack/run-e2e-local.sh bootc
bash hack/run-e2e-local.sh container-build
bash hack/run-e2e-local.sh auth
bash hack/run-e2e-local.sh package-mode
bash hack/run-e2e-local.sh features
bash hack/run-e2e-local.sh            # all lanes

# Via direct label filter (lanes without dedicated make/local shorthand)
go test ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="internal-registry"
go test ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="manifest-validation"
go test ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="catalog"
```

### Benchmarks

Times measured on CRC (cluster already running):

| Lane | macOS arm64 | Linux amd64 | `go test -timeout` |
|------|-------------|-------------|-------------------|
| `smoke` | ~3 min | ~3 min | 5m |
| `operator` | ~3 min | ~3 min | 5m |
| `auth` | ~3 min | ~3 min | 5m |
| `features` | ~4 min | ~4 min | 5m |
| `bootc` | ~7 min | ~7 min | 15m |
| `package-mode` | ~4 min | ~4 min | 15m |
| all | ~8 min | ~36 min | 45m |

## E2E Tests Summary

Per-test inventory (file, lane, Ginkgo label(s), prerequisites, steps, and pass checks) is in [e2e-test-summary.md](e2e-test-summary.md).

Run `make e2e-spec-index` (or `test/e2e/scripts/gen-spec-index.sh`) to print an auto-generated, lane-grouped index of every spec's group, test name, labels, and source location straight from `ginkgo --dry-run`. It needs no live cluster and is useful for catching drift in the Lane/Label/Test/File columns above before hand-editing them; it still cannot generate the prerequisites/steps/pass-check columns.

## Test Structure

- `e2e-test-summary.md`: Per-test inventory of every e2e spec
- `e2e_suite_test.go`: Suite setup, `BeforeSuite`/`AfterSuite`
- `helpers_test.go`: Shared helpers — `sync.Once`-based operator deploy, Build API access, caib credentials, and utility functions (`applyImageBuildCR`, `createBuildViaCaib`, `waitForImageBuildPhase`, etc.)
- `operator_test.go`: Operator health checks (`Label("operator", "smoke")`)
- `smoke_test.go`: CRD availability, OperatorConfig, Build API endpoints, CR lifecycle, negative/guard-rail tests (`Label("smoke")`)
- `buildapi_test.go`: Build API CRUD via caib CLI and ownership enforcement (`Label("operator")`)
- `imagebuild_lifecycle_test.go`: Export/push phase and build cancellation (`Label("operator")`)
- `operatorconfig_e2e_test.go`: OperatorConfig osBuilds toggle (`Label("operator")`)
- `error_handling_test.go`: Concurrent builds isolation (`Label("operator")`)
- `bootc_build_test.go`: Bootc build and internal-registry build via caib (`Label("bootc")`, `Label("internal-registry")`)
- `auth_test.go`: OIDC authentication (`Label("auth")`)
- `package_build_test.go`: Package mode disk image build (`Label("package-mode", "smoke")`)
- `features_e2e_test.go`: TTL expiry, image propagation, Build API log streaming (`Label("features")`)
- `manifest_validation_test.go`: caib manifest validation (`Label("manifest-validation")`)
- `container_build_test.go`: Shipwright container builds (`Label("container-build")`)
- `catalog_discovery_test.go`: Catalog list/get output behavior (`Label("catalog")`)
- `../utils/`: Utility functions for running commands and managing processes

## GitHub Actions

The e2e tests run automatically on:
- Pull requests to `main`
- Pushes to `main`
- Manual workflow dispatch (with optional `label_filter` input)

Individual lanes can be triggered on PRs via comment commands:
- `/e2e-smoke`, `/e2e-operator`, `/e2e-bootc`, `/e2e-auth`, `/e2e-package-mode`, `/e2e-features`, `/e2e-test-all`
- `/e2e-container-build`

See `.github/workflows/e2e.yml` and `.github/workflows/e2e-lanes.yml` for the CI configuration.

## Debugging Test Failures

If tests fail, check:

1. **Controller logs:**
   ```bash
   kubectl logs -n automotive-dev-operator-system -l control-plane=operator
   ```

2. **Pod status:**
   ```bash
   kubectl get pods -n automotive-dev-operator-system -o wide
   ```

3. **Events:**
   ```bash
   kubectl get events -n automotive-dev-operator-system --sort-by='.lastTimestamp'
   ```

4. **Custom resources:**
   ```bash
   kubectl get operatorconfig -n automotive-dev-operator-system -o yaml
   kubectl get imagebuilds -n automotive-dev-operator-system -o yaml
   ```

## Writing New Tests

When adding new test cases:

1. Follow the existing test structure using Ginkgo/Gomega
2. Use descriptive test names with `It("should ...")` 
3. Add proper cleanup in `AfterEach` or `AfterAll` blocks
4. Use `Eventually` for asynchronous checks
5. Check both positive and negative scenarios

