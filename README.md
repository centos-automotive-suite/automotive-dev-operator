# CentOS Automotive Suite Operator

An operator for building automotive OS images on OpenShift. This operator provides a cloud-native way to create automotive OS images using the automotive-image-builder (AIB) project, with support for both traditional AIB manifests and modern bootc container builds.

## Description

The CentOS Automotive Suite Operator enables automotive OS image building through:

- **ImageBuild Custom Resource**: Declaratively define and trigger automotive OS image builds
- **Multiple Build Modes**: Support for traditional AIB manifests and bootc container builds
- **CLI Tool (caib)**: Command-line interface for creating and monitoring builds
- **Artifact Management**: Serve built images via OpenShift Routes or push to OCI registries
- **Tekton Integration**: Uses OpenShift Pipelines (Tekton) for scalable build execution

## Getting Started

### Prerequisites

**For OpenShift Installation (Recommended):**
- OpenShift 4.17+ cluster
- OpenShift Pipelines Operator (Tekton) installed
- Cluster admin permissions (for initial installation)

**For Development:**
- Go 1.22.0+
- Podman or Docker
- OpenShift CLI (`oc`) or kubectl
- Operator SDK v1.42.0+ (for development)

## Installation

### Option 1: OpenShift OperatorHub (Recommended)

The easiest way to install on OpenShift is through OperatorHub:

1. Open the OpenShift Console
2. Navigate to **Operators** > **OperatorHub**
3. Search for "CentOS Automotive Suite"
4. Click **Install** and follow the prompts

After installation, create an `OperatorConfig` to enable components:

```sh
oc apply -f config/samples/automotive_v1_operatorconfig.yaml
```

### Option 2: OLM Bundle (Local Testing)

For local development and testing:

```sh
# Deploy catalog and install operator
./hack/deploy-catalog.sh --uninstall --install

# Create OperatorConfig to configure the operator
oc apply -f config/samples/automotive_v1_operatorconfig.yaml
```

### Option 3: Manual Deployment

**Build and push your image:**

```sh
make docker-build docker-push IMG=<registry>/automotive-dev-operator:tag
```

**Install CRDs and deploy the operator:**

```sh
make install
make deploy IMG=<registry>/automotive-dev-operator:tag
```

**Configure the operator:**

```sh
oc apply -f config/samples/automotive_v1_operatorconfig.yaml
```

## Usage

### Creating Your First Build

1. **Create a ConfigMap with your AIB manifest:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-build-manifest
data:
  simple.aib.yml: |
    name: container

    content:
      rpms:
        - openssh-server
      systemd:
        enabled_services:
          - sshd.service
      add_files:
         - path: /usr/share/hello.txt
           text: |
             hello!
    image:
      image_size: 8 GiB

    auth:
      # "password"
      root_password: $6$xoLqEUz0cGGJRx01$H3H/bFm0myJPULNMtbSsOFd/2BnHqHkMD92Sfxd.EKM9hXTWSmELG8cf205l6dktomuTcgKGGtGDgtvHVXSWU.
      sshd_config:
        PermitRootLogin: true
        PasswordAuthentication: true
```

2. **Create an ImageBuild resource:**

```yaml
apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: ImageBuild
metadata:
  name: my-automotive-image
spec:
  distro: autosd
  architecture: amd64
  mode: image
  target: qemu
  exportFormat: qcow2
  manifestConfigMap: my-build-manifest
```

3. **Apply the resources:**

```sh
oc apply -f manifest-configmap.yaml
oc apply -f imagebuild.yaml
```

4. **Monitor the build:**

```sh
oc get imagebuild my-automotive-image -w
oc logs -f job/my-automotive-image-build
```

## Uninstallation

### For OperatorHub Installation

1. In OpenShift Console, go to **Operators** > **Installed Operators**
2. Find "CentOS Automotive Suite" and click the options menu
3. Select **Uninstall Operator**

### For OLM Bundle Installation

```sh
./hack/deploy-catalog.sh --uninstall
```

### For Manual Deployment

```sh
# Delete operator resources
oc delete -k config/samples/
make undeploy

# Remove CRDs
make uninstall
```

## Components

### Custom Resources

- **ImageBuild**: Defines an automotive OS image build job
- **Image**: Represents a built image with metadata and location information
- **OperatorConfig**: Cluster-wide configuration for the operator

### Optional Components

When `OperatorConfig.spec.osBuilds.enabled` is true:
- **Build API**: REST API for programmatic access

### CLI Tool

The `caib` CLI provides command-line access to build operations. See [`cmd/caib/README.md`](cmd/caib/README.md) for usage details.

## Architecture

This operator is built with the Kubebuilder framework and uses:

- **Controller Runtime**: Manages Custom Resources and reconciliation loops
- **OpenShift Pipelines (Tekton)**: Executes build workflows as TaskRuns
- **Automotive Image Builder**: External tool for creating automotive OS images
- **OpenShift Routes**: Exposes build API and artifact serving endpoints

### Dependencies

- **OpenShift Pipelines Operator**: Required for Tekton pipeline execution
- **OpenShift 4.17+**: Minimum supported OpenShift version
- **Container Registry**: For storing built images (internal or external)

## Development

### Local Development

1. **Clone and setup:**

```sh
git clone https://github.com/centos-automotive-suite/automotive-dev-operator.git
cd automotive-dev-operator
```

2. **Install dependencies:**

```sh
make install
```

3. **Run locally:**

```sh
make run
```

### Testing

```sh
# Unit tests
make test

# E2E tests
make test-e2e

# Linting
make lint
```

### Building

```sh
# Build all binaries
make build

# Build specific components
make build-caib           # CLI tool
make build-api-server     # API server

# Build container images
make docker-build
```

## Release Information

This project publishes versioned releases with:
- Multi-architecture container images (amd64, arm64)
- `caib` CLI binaries for Linux
- OLM bundles for OperatorHub distribution

For the latest release, visit: https://github.com/centos-automotive-suite/automotive-dev-operator/releases

## Contributing

We welcome contributions! To contribute:

1. **Fork the repository** and create a feature branch
2. **Follow the development setup** described above
3. **Add tests** for new functionality
4. **Run the full test suite** before submitting
5. **Submit a pull request** with a clear description

### Code Guidelines

- Follow Go best practices and formatting (`make lint`)
- Update documentation for user-facing changes
- Add appropriate tests for new features
- Ensure all CI checks pass

### Useful Make Targets

Run `make help` to see all available targets. Key targets include:

```sh
make help           # Show all targets
make generate       # Generate code after API changes
make manifests      # Generate CRDs and RBAC
make bundle         # Generate OLM bundle
make test           # Run unit tests
make test-e2e       # Run e2e tests
```

For more information, see the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html).

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
