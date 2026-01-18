# End-to-End Tests

This directory contains end-to-end tests for the Automotive Dev Operator.

## Prerequisites

- [Go](https://golang.org/dl/) (version 1.24+)
- [Kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Docker](https://www.docker.com/)
- [Tekton Pipelines](https://tekton.dev/) (will be installed automatically)

## Running E2E Tests Locally

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
   kubectl wait --for=condition=available --timeout=5m deployment/ado-controller-manager -n automotive-dev-operator-system
   ```

6. **Run the tests:**
   ```bash
   go test ./test/e2e/ -v -ginkgo.v
   ```

7. **Cleanup:**
   ```bash
   kind delete cluster --name automotive-dev-e2e
   ```

## What the Tests Cover

The e2e test suite verifies:

1. **Operator Installation**: 
   - Operator pod starts successfully
   - CRDs are properly installed
   - Controller manager is running

2. **OperatorConfig Resource**:
   - Creates OperatorConfig with `osBuilds` enabled
   - Verifies Build API deployment is created
   - Verifies Tekton tasks and pipelines are created when osBuilds is enabled
   - Tests disabling osBuilds removes Tekton resources

3. **ImageBuild Resource**:
   - Creates ImageBuild CR
   - Verifies TaskRun is created
   - Verifies PVC is created for the build workspace

4. **Configuration Updates**:
   - Tests updating OperatorConfig
   - Verifies resources are properly reconciled

## Test Structure

- `e2e_suite_test.go`: Test suite setup and configuration
- `e2e_test.go`: Main test scenarios
- `../utils/`: Utility functions for test helpers

## GitHub Actions

The e2e tests run automatically on:
- Pull requests to `main`
- Pushes to `main`
- Manual workflow dispatch

See `.github/workflows/e2e.yml` for the CI configuration.

## Debugging Test Failures

If tests fail, check:

1. **Controller logs:**
   ```bash
   kubectl logs -n automotive-dev-operator-system -l control-plane=controller-manager
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

