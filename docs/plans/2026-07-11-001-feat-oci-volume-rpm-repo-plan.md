---
title: "feat: Accept OCI image volumes as RPM repo sources in build/build-dev"
type: feat
status: active
date: 2026-07-11
---

# feat: Accept OCI image volumes as RPM repo sources in build/build-dev

## Summary

Extend `--extra-repo` to accept OCI image references (prefixed `oci:`), mounting them as read-only Kubernetes ImageVolume sources in build pods. This eliminates the workspace-pod HTTP-server dependency for RPM repos — users package their RPMs into an OCI image with `repodata/`, and the build pod mounts it directly via kubelet image pull.

---

## Problem Frame

Today, `--extra-repo workspace:path` requires a running Workspace pod: the server starts a `python3 -m http.server` in the workspace, passes the HTTP URL to AIB, and the build pod pulls RPMs over the network during the build. This couples RPM repos to Workspace lifecycle and adds network latency.

OCI image volumes (Kubernetes `ImageVolumeSource`, GA in k8s 1.33) let the kubelet pull an OCI image and mount its filesystem directly as a read-only volume — no HTTP server, no workspace dependency, no network hop during build.

---

## Requirements

- R1. `caib image build` and `caib image build-dev` accept `--extra-repo oci:<image-ref>` (e.g., `--extra-repo oci:quay.io/org/rpms:latest`)
- R2. OCI repo refs flow through BuildRequest → ImageBuild CRD → build pod without requiring a running Workspace
- R3. Build pod mounts each OCI image as a read-only volume via `ImageVolumeSource`
- R4. AIB receives mounted repos as `extra_repos` entries with `file://` URLs — no build script changes needed
- R5. Existing `--extra-repo workspace:path` syntax continues to work unchanged
- R6. Up to 4 OCI repo volumes supported per build (pre-declared slots in Tekton Task)

---

## Scope Boundaries

- ImageVolume feature gate must be enabled on the cluster (beta k8s 1.31+, GA 1.33, enabled by default on OCP 4.21+)
- OCI images must contain pre-built repos (with `repodata/`); no `createrepo_c` support
- Private OCI images requiring pull auth are out of scope for v1 — the kubelet's configured pull secrets apply; explicit per-repo auth is deferred

### Deferred to Follow-Up Work

- Per-repo pull secrets for private OCI RPM images — separate PR
- Peer-pods compatibility (peer-pods webhook strips ImageVolumeSource — see memory `project-imagevolume-peerpods-bug`) — not fixable from operator side; document as known limitation

---

## Context & Research

### Relevant Code and Patterns

- `cmd/caib/image/image.go` — flag registration for `--extra-repo` (line 156 build, line 267 build-dev)
- `cmd/caib/buildcmd/build.go` — `RunBuild()` (line 590) and `RunBuildDev()` (line 836) set `ExtraRepos` on `BuildRequest`
- `internal/buildapi/types.go:154` — `BuildRequest.ExtraRepos []string`
- `internal/buildapi/server.go:824` — `resolveExtraRepos()` parses `workspace:path`, starts HTTP server, injects `extra_repos` JSON into `CustomDefs`
- `api/v1alpha1/imagebuild_types.go:161` — `AIBSpec` struct, `CustomDefs []string`
- `internal/common/tasks/tasks.go:696` — `GenerateTektonTask()` builds the `build-image` step with volumes
- `internal/controller/imagebuild/controller.go:1458` — PipelineRun construction with `TaskRunSpecs` support
- Pipeline task name for build: `"build-image"` (tasks.go:1254)
- Tekton `PodTemplate.Volumes` supports merge-by-name with Task volumes (pod/template.go:73)
- Tekton `PipelineTaskRunSpec` supports per-task PodTemplate (pipelinerun_types.go:661)

### Institutional Learnings

- ImageVolume + peer-pods bug: peer-pods webhook silently strips `ImageVolumeSource` — fixed by removing sandboxed containers operator (memory: `project-imagevolume-peerpods-bug`)
- Extra repos smuggled through `CustomDefs` as JSON `extra_repos=[{id, baseurl}]` — AIB interprets this internally

---

## Key Technical Decisions

- **Extend `--extra-repo` with `oci:` prefix** rather than new flag: keeps UX simple; `workspace:path` and `oci:image-ref` are distinguishable by prefix. The server separates them during parsing.
- **Pre-declare 4 OCI volume slots in Tekton Task**: Tasks are static (created once by OperatorConfig controller, shared across builds). Per-build dynamic Task generation would break secure/signed builds. 4 slots is sufficient — most builds need 0-2 extra repos. EmptyDir placeholders are nearly free.
- **Inject `file://` URLs via existing `extra_repos` CustomDefs mechanism**: No build script changes. The server constructs `extra_repos` JSON entries pointing to mount paths (`file:///extra-repos/oci-repo-0`). Same data flow as workspace repos.
- **Use `TaskRunSpecs` per-task PodTemplate** for volume override: Only the `build-image` pipeline task gets OCI volumes — flash and push tasks don't need them. `TaskRunSpecs[].PipelineTaskName = "build-image"`.
- **New CRD field `AIBSpec.OCIRepoImages`**: First-class field rather than encoding through CustomDefs, because the controller needs the image refs to construct `ImageVolumeSource` volumes.

---

## Open Questions

### Resolved During Planning

- **How to mount dynamic volumes in static Tasks?** Pre-declare slots in Task; override via PodTemplate.Volumes merge-by-name. Tekton PodTemplate volumes take precedence when names match.
- **How to pass repo paths to AIB?** Reuse existing `extra_repos` CustomDefs JSON mechanism with `file://` URLs. Zero build script changes.
- **Which Tekton PodTemplate level?** `TaskRunSpecs` per-task PodTemplate (not global PipelineRun PodTemplate) — only build task needs the volumes.

### Deferred to Implementation

- Exact validation error message wording for `oci:` prefix parsing edge cases
- Whether to validate OCI image ref format client-side or leave it to kubelet

---

## Implementation Units

### U1. Add `OCIRepoImages` field to AIBSpec CRD

**Goal:** First-class CRD field for OCI repo image references so the controller can construct ImageVolumeSource volumes.

**Requirements:** R2

**Dependencies:** None

**Files:**
- Modify: `api/v1alpha1/imagebuild_types.go`
- Test: `api/v1alpha1/imagebuild_types_test.go` (if exists, else verify via `make generate manifests`)

**Approach:**
- Add `OCIRepoImages []string` to `AIBSpec` with kubebuilder validation (`maxItems:4`)
- Add getter `GetOCIRepoImages()` on `ImageBuildSpec` (follows existing pattern like `GetCustomDefs()`)
- Run `make generate manifests` to update DeepCopy and CRDs

**Patterns to follow:**
- `AIBSpec.CustomDefs` field pattern (same struct, same getter style)
- `AIBSpec.AIBExtraArgs` for slice field convention

**Test scenarios:**
- Happy path: `GetOCIRepoImages()` returns refs when set, nil when AIB is nil
- Edge case: CRD validation rejects >4 items

**Verification:**
- `make generate manifests` succeeds
- CRD YAML in `config/crd/bases/` includes `ociRepoImages` field with maxItems validation

---

### U2. Add OCI repo field to BuildRequest and server-side resolution

**Goal:** Accept OCI image refs in the REST API and inject `file://` extra_repos entries into CustomDefs.

**Requirements:** R2, R4

**Dependencies:** U1

**Files:**
- Modify: `internal/buildapi/types.go`
- Modify: `internal/buildapi/server.go`
- Modify: `internal/buildapi/build_spec.go`
- Test: `internal/buildapi/server_test.go`

**Approach:**
- Add `OCIRepoImages []string` to `BuildRequest`
- In `resolveExtraRepos()` (or a new `resolveOCIRepoImages()`): for each OCI image ref, construct an extra_repos entry `{id: "oci-repo-N", baseurl: "file:///extra-repos/oci-repo-N"}` and append to `req.CustomDefs`
- In `buildAIBSpec()`: pass `OCIRepoImages` through to the ImageBuild CR's `AIBSpec.OCIRepoImages`
- Validate: reject if >4 OCI refs

**Patterns to follow:**
- `resolveExtraRepos()` for the extra_repos JSON injection pattern
- `buildAIBSpec()` for field mapping from BuildRequest to CRD spec

**Test scenarios:**
- Happy path: BuildRequest with `OCIRepoImages: ["quay.io/org/rpms:v1"]` → CustomDefs includes `extra_repos=[{"id":"oci-repo-0","baseurl":"file:///extra-repos/oci-repo-0"}]`
- Happy path: Mixed workspace and OCI repos — both types merged into single `extra_repos` JSON array
- Edge case: Empty OCI repo list → no extra_repos modification
- Error path: >4 OCI repos → validation error

**Verification:**
- Unit tests pass for server-side resolution
- `extra_repos` JSON contains both workspace HTTP URLs and OCI `file://` URLs when both types used

---

### U3. Pre-declare OCI repo volume slots in Tekton Task

**Goal:** Add 4 EmptyDir volume slots with VolumeMounts to the `build-image` step so OCI volumes can be overridden at PipelineRun time.

**Requirements:** R3, R6

**Dependencies:** None (parallel with U1/U2)

**Files:**
- Modify: `internal/common/tasks/tasks.go`
- Test: `internal/common/tasks/tasks_test.go`

**Approach:**
- In `GenerateTektonTask()`, add 4 volumes named `oci-repo-0` through `oci-repo-3` with EmptyDir source
- Add corresponding VolumeMounts to the `build-image` step at `/extra-repos/oci-repo-0` through `/extra-repos/oci-repo-3`, readOnly: true
- These are harmless when unused (empty dir, read-only mount)

**Patterns to follow:**
- Existing volume declarations in `GenerateTektonTask()` (line 774)
- Existing VolumeMounts on `build-image` step (line 737)

**Test scenarios:**
- Happy path: `GenerateTektonTask()` output includes 4 `oci-repo-*` volumes and mounts
- Happy path: VolumeMounts are readOnly
- Integration: existing memory-volume and PVC-scratch logic doesn't touch `oci-repo-*` volumes (they're not in the redirect maps)

**Verification:**
- Task YAML output (via test) shows oci-repo volumes and mounts
- Memory volume and PVC scratch redirects don't affect oci-repo volumes

---

### U4. Wire controller to add ImageVolumeSource to PipelineRun

**Goal:** When ImageBuild has OCI repo images, override EmptyDir slots with ImageVolumeSource via per-task PodTemplate.

**Requirements:** R3

**Dependencies:** U1, U3

**Files:**
- Modify: `internal/controller/imagebuild/controller.go`
- Test: `internal/controller/imagebuild/controller_test.go`

**Approach:**
- In the PipelineRun creation block (around line 1458), check `imageBuild.Spec.GetOCIRepoImages()`
- If non-empty, add `TaskRunSpecs` entry targeting `PipelineTaskName: "build-image"` with PodTemplate.Volumes containing `ImageVolumeSource{Reference: imageRef, PullPolicy: IfNotPresent}` for each OCI repo
- Volume names match the pre-declared slots: `oci-repo-0`, `oci-repo-1`, etc.

**Patterns to follow:**
- Existing `TaskRunSpecs` usage (if any) or Tekton `PipelineTaskRunSpec` struct pattern
- Existing PodTemplate construction (line 1442) for node affinity / runtime class

**Test scenarios:**
- Happy path: ImageBuild with 1 OCI repo → PipelineRun has TaskRunSpecs with 1 ImageVolumeSource volume
- Happy path: ImageBuild with 3 OCI repos → 3 ImageVolumeSource volumes, names match `oci-repo-0` through `oci-repo-2`
- Edge case: No OCI repos → no TaskRunSpecs addition, existing behavior unchanged
- Integration: OCI repo volumes coexist with other PodTemplate settings (affinity, runtime class, node selector)

**Verification:**
- Created PipelineRun includes per-task PodTemplate with ImageVolumeSource volumes
- Non-OCI builds produce identical PipelineRuns as before

---

### U5. Extend CLI `--extra-repo` to parse `oci:` prefix

**Goal:** Users can pass `--extra-repo oci:quay.io/org/rpms:latest` alongside existing `workspace:path` entries.

**Requirements:** R1, R5

**Dependencies:** U2

**Files:**
- Modify: `cmd/caib/buildcmd/build.go`
- Modify: `cmd/caib/image/image.go` (flag help text update)
- Test: `cmd/caib/buildcmd/build_test.go`

**Approach:**
- In `RunBuild()` and `RunBuildDev()`, before constructing the BuildRequest, iterate `ExtraRepos` and split into two slices: workspace entries (no prefix or `workspace:` prefix) and OCI entries (`oci:` prefix)
- Strip the `oci:` prefix from OCI entries
- Set `BuildRequest.ExtraRepos` to workspace entries, `BuildRequest.OCIRepoImages` to OCI entries
- Update flag help text: `"extra RPM repo (workspace:path or oci:image-ref, can be repeated)"`

**Patterns to follow:**
- Existing `ExtraRepos` population in `RunBuild()` (line 674) and `RunBuildDev()` (line 955)

**Test scenarios:**
- Happy path: `--extra-repo oci:quay.io/org/rpms:v1` → OCIRepoImages populated
- Happy path: `--extra-repo myworkspace:/rpms` → ExtraRepos populated (unchanged)
- Happy path: Mixed `--extra-repo oci:img1 --extra-repo ws:/path` → both fields populated
- Error path: `--extra-repo oci:` (empty ref after prefix) → error
- Edge case: Image ref with port number `oci:registry.example.com:5000/rpms:v1` → correctly parsed

**Verification:**
- BuildRequest sent to server has correct field separation
- Existing workspace extra-repo functionality unchanged

---

### U6. End-to-end integration test

**Goal:** Verify the full flow from CLI flag through PipelineRun creation.

**Requirements:** R1, R2, R3, R4

**Dependencies:** U1, U2, U3, U4, U5

**Files:**
- Modify: `internal/controller/imagebuild/controller_test.go`
- Test: (same file — this IS the test unit)

**Approach:**
- Add test case: create ImageBuild with `OCIRepoImages: ["quay.io/test/rpms:v1"]` → verify PipelineRun has TaskRunSpecs with ImageVolumeSource and CustomDefs contains extra_repos with file:// URL
- Add test case: ImageBuild with both workspace and OCI repos → verify both types in extra_repos JSON

**Test scenarios:**
- Happy path: ImageBuild with OCI repo → PipelineRun volumes + CustomDefs both correct
- Integration: Combined workspace + OCI repos → merged extra_repos JSON

**Verification:**
- All tests pass
- `make test` passes
- `make lint` passes

---

## System-Wide Impact

- **Interaction graph:** CLI → REST API → server resolution → ImageBuild CR → controller → PipelineRun → Tekton → kubelet ImageVolume pull → build step mount → AIB extra_repos
- **Error propagation:** Invalid OCI image ref → kubelet pull failure → TaskRun pod ImagePullBackOff → PipelineRun failure → ImageBuild phase=Failed. This is standard k8s behavior, no operator-side handling needed.
- **State lifecycle risks:** None — OCI volumes are read-only and pulled by kubelet. No cleanup needed. Image layer cache managed by kubelet garbage collection.
- **API surface parity:** `--extra-repo oci:` available on both `build` and `build-dev` commands (same flag registration pattern)
- **Unchanged invariants:** Existing `--extra-repo workspace:path` syntax, CustomDefs mechanism, and AIB `extra_repos` define format all unchanged

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| ImageVolume feature gate not enabled on cluster | Document requirement; OCP 4.21+ has it enabled by default. Kubelet will reject pod with clear error. |
| Peer-pods webhook strips ImageVolumeSource | Document as known limitation. Users must remove sandboxed containers operator or exclude namespace. |
| 4-slot limit insufficient | Start with 4; easy to increase later by adding more slots. No existing use case needs >4. |
| Secure builds (signed task bundles) won't include OCI slots | Task bundles need rebuilding to include the new volume slots. Document in release notes. |

---

## Sources & References

- Kubernetes ImageVolumeSource: k8s.io/api/core/v1 `VolumeSource.Image` field
- Tekton PodTemplate volumes: merge-by-name semantics in pipeline/pod/template.go
- Memory: `project-imagevolume-peerpods-bug` — peer-pods webhook compatibility
