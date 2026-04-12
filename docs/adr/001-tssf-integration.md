# ADR-001: Integrate Red Hat Trusted Software Supply Chain (RHTSSC)

## Status

Accepted

## Date

2026-04-10

## Context

The automotive-dev-operator generates Tekton PipelineRuns to build OS images
(`ImageBuild`) and generic software artifacts (`SoftwareBuild`). Today, build
outputs are not signed, have no SBOM, and produce no SLSA provenance
attestation. This blocks adoption in environments that require supply-chain
compliance (UNECE R155, ISO/SAE 21434, internal Red Hat product requirements).

Red Hat ships three products under the **Trusted Software Supply Chain**
umbrella:

| Product | Upstream | Function |
|---------|----------|----------|
| **RHTAP** (Trusted Application Pipeline) | Konflux / Tekton + Enterprise Contract | SLSA L3 build pipelines, policy enforcement |
| **RHTAS** (Trusted Artifact Signer) | Sigstore (cosign, Fulcio, Rekor) | Keyless artifact signing + transparency log |
| **RHTPA** (Trusted Profile Analyzer) | Trustification / GUAC | SBOM indexing, vulnerability analysis |

PR #199 review (finding #2, #10, #25) identified three immediate gaps:

1. Inline `TaskSpec` prevents Tekton Chains from verifying task provenance.
2. Build outputs are not traceable (no digest, no signature, no SBOM reference).
3. Mutable image tags undermine reproducibility.

Issue #200 tracks the prerequisite TaskRef migration for `SoftwareBuild`.

## Decision

### 1. Build on `main`, not on `feat/software-build`

TSSF integration is **post-build and strategy-agnostic**. The compliance
pipeline tail (SBOM → Sign → Provenance → Publish) is identical regardless of
whether the build used `ImageBuild` or `SoftwareBuild`. The existing
`ImageBuild` pipeline on `main` already uses `TaskRef` with cluster resolver
for `build-image`, `push-disk-artifact`, and `flash-image`, making it
partially Chains-compatible today.

Starting from `main`:

- Delivers value to `ImageBuild` immediately without waiting for PR #199.
- Keeps the TSSF PR scope clean and reviewable.
- Avoids coupling to `SoftwareBuild` review cycle.
- `SoftwareBuild` gains TSSF when PR #199 merges and issue #200 is resolved.

### 2. Use Tekton Chains for signing and provenance (not custom tasks)

**Chosen:** Tekton Chains as a passive observer.

**Rejected alternative:** A custom `comply` TaskRun that runs cosign/syft
inline. This was rejected because:

- Chains is the Red Hat-supported, Konflux-standard mechanism.
- It runs out-of-band (separate controller), so pipeline authors don't need to
  manage signing keys or attestation logic.
- It produces SLSA L3 provenance automatically when tasks use `TaskRef`.
- RHTAS (Fulcio + Rekor) plugs directly into Chains configuration.

Chains is configured cluster-wide via a `ConfigMap` in the `tekton-chains`
namespace. The operator does not need to manage Chains lifecycle—only ensure
pipelines emit the result contract Chains expects.

### 3. Add an explicit SBOM generation task

Tekton Chains handles signing and provenance but does **not** generate SBOMs.
A dedicated `sbom-generate` task will:

- Run Syft against the build workspace to produce SPDX or CycloneDX output.
- Attach the SBOM as an OCI artifact referrer to the build artifact.
- Emit a `SBOM_URI` result for status reporting.

This task is strategy-agnostic and appended after the build/test stages.

### 4. Require tasks to emit typed results

For Chains to sign the correct artifact, pipeline tasks must produce:

| Result name | Description |
|-------------|-------------|
| `IMAGE_URL` | OCI reference (registry/repo:tag) |
| `IMAGE_DIGEST` | Content-addressable digest (sha256:...) |
| `SBOM_URI` | OCI reference to attached SBOM |

The operator's pipeline generation code will wire these results as pipeline
results, making them visible to Chains.

### 5. Extend the CRD status for compliance traceability

```go
type ArtifactRef struct {
    Registry      string `json:"registry,omitempty"`
    Digest        string `json:"digest,omitempty"`
    SBOMRef       string `json:"sbomRef,omitempty"`
    SignatureRef  string `json:"signatureRef,omitempty"`
    ProvenanceRef string `json:"provenanceRef,omitempty"`
}
```

The reconciler will populate these fields from PipelineRun results, giving
developers a single place to find the full chain of trust.

### 6. Enterprise Contract as an optional policy gate

Enterprise Contract (EC) evaluates whether a built artifact meets a defined
policy (signed, has SBOM, no critical CVEs, SLSA provenance present). This
will be an optional, cluster-level configuration:

- `OperatorConfig.Spec.Compliance.PolicyRef` points to an EC policy.
- When set, the operator appends an `ec-validate` task as the final pipeline
  stage.
- Builds that fail policy are marked `Failed` with a compliance-specific
  condition.

### 7. OperatorConfig extensions

```go
type ComplianceConfig struct {
    Enabled              bool   `json:"enabled"`
    SBOMFormat           string `json:"sbomFormat,omitempty"`
    SBOMTaskBundle       string `json:"sbomTaskBundle,omitempty"`
    ECPolicyRef          string `json:"ecPolicyRef,omitempty"`
    TrustedArtifactSignerURL string `json:"trustedArtifactSignerURL,omitempty"`
    RekorURL             string `json:"rekorURL,omitempty"`
    FulcioURL            string `json:"fulcioURL,omitempty"`
}
```

These fields configure the cluster-wide compliance behaviour. Per-build
overrides via `spec.compliance` on individual CRs are a future consideration.

## Consequences

### Positive

- `ImageBuild` gains SBOM + signing + SLSA provenance without any CRD changes.
- `SoftwareBuild` gains the same once issue #200 is resolved.
- Single compliance tail shared across all build strategies.
- Aligns with Red Hat product direction (Konflux, RHTAP, RHTAS).
- Meets UNECE R155 / ISO 21434 traceability requirements.

### Negative

- Requires Tekton Chains to be installed on the cluster (operator does not
  manage its lifecycle).
- RHTAS (Fulcio/Rekor) must be available for keyless signing; clusters without
  RHTAS need a pre-provisioned cosign key pair.
- SBOM generation adds ~1-2 minutes to each build pipeline.

### Risks

- Tekton Chains' result contract (`IMAGE_URL`, `IMAGE_DIGEST`) may evolve.
  Mitigated by pinning Chains version in operator compatibility matrix.
- Enterprise Contract policy authoring requires separate expertise. Mitigated
  by shipping a default policy bundle.

## Implementation order

1. **Issue #200** — Migrate `SoftwareBuild` inline TaskSpec to signed TaskRef
   bundles (prerequisite for Chains on SoftwareBuild pipelines).
2. **Pipeline results contract** — Add `IMAGE_URL`, `IMAGE_DIGEST` results to
   existing `ImageBuild` tasks and new `SoftwareBuild` task bundles.
3. **SBOM task** — Create and publish a signed `sbom-generate` cluster task.
4. **Operator wiring** — Append SBOM task to pipeline generation when
   compliance is enabled; populate `status.artifact` from results.
5. **CRD extension** — Add `ArtifactRef` to status, `ComplianceConfig` to
   OperatorConfig.
6. **Tekton Chains cluster configuration** — Document RHTAS endpoint
   configuration for Chains.
7. **Enterprise Contract** — Optional policy gate task (stretch goal).

## References

- [Tekton Chains](https://tekton.dev/docs/chains/)
- [SLSA v1.0 requirements](https://slsa.dev/spec/v1.0/requirements)
- [Red Hat Trusted Software Supply Chain](https://red.ht/trusted)
- [Enterprise Contract](https://enterprisecontract.dev/)
- Issue #200: Migrate SoftwareBuild pipeline from inline TaskSpec to signed TaskRef bundles
- PR #199: feat: add SoftwareBuild CRD for multi-OS software builds
