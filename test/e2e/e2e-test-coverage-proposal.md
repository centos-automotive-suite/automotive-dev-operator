# E2E Test Coverage Proposal

## Current Coverage Baseline

### Existing Test Files

| File | Label | Tests | What It Covers | CI Trigger | Cluster |
|------|-------|-------|----------------|------------|---------|
| `operator_test.go` | `operator` | 4 | Controller pod running, Tekton Tasks exist, Tekton Pipeline exists, Build API deployment available | Every PR (Kind) | Kind |
| `bootc_build_test.go` | `bootc` | 1 | Full bootc container image build via caib CLI, verify completed in `caib image list` | `/e2e-bootc` PR comment | Kind + OpenShift |
| `auth_test.go` | `auth` | 3 | OIDC not-configured returns 404, OIDC config patched and reflected in API, Build API pod running | `/e2e-auth` PR comment | OpenShift only |
| `e2e_suite_test.go` | — | 0 | BeforeSuite (namespace, registry, arch), AfterSuite (teardown) | — | — |
| `helpers_test.go` | — | 0 | `deployOperator()`, `setupRegistry()`, `setupBuildAPIPortForward()`, `setupCaibCredentials()` | — | — |

### Existing CI Workflows

| Workflow | File | Trigger | What It Runs |
|----------|------|---------|--------------|
| E2E Tests | `e2e.yml` | Every PR push + merge to main | All labels (no filter by default), Kind cluster, 90 min timeout |
| E2E Test Lanes | `e2e-lanes.yml` | PR comment (`/e2e-operator`, `/e2e-bootc`, `/e2e-auth`, `/e2e-test-all`) | Single lane by label, Kind cluster |

### Coverage Gap Analysis

| Component | CRDs | Controllers | API Routes | Existing E2E Tests | Coverage |
|-----------|------|-------------|------------|-------------------|----------|
| ImageBuild | 1 | 1 (7 handlers) | 10 | 0 | ~5% |
| Image | 1 | 1 | 0 | 0 | 0% |
| CatalogImage | 1 | 1 | 6 | 0 | 0% |
| ContainerBuild | 1 | 1 | 5 | 0 | 0% |
| Workspace | 1 | 1 | 12 | 0 | 0% |
| ImageReseal | 1 | 1 | 4 | 0 | 0% |
| OperatorConfig | 1 | 1 (48+ handlers) | 1 | 4 (resource existence only) | ~10% |
| Build API (all route groups) | — | — | 46 total | 0 | ~2% |
| Authentication | — | — | 1 | 3 (OIDC only, OpenShift) | ~30% |
| Bootc Build | — | — | — | 1 (full build) | ~80% |
| **Total** | **7** | **7** | **46** | **8** | **~2%** |

### What Is NOT Tested Today

- No CRD lifecycle tests (create→reconcile→status→delete) for any CR type
- No Build API endpoint tests (POST/GET/DELETE builds, uploads, logs, config)
- No auth validation tests on Kind (auth tests skip on non-OpenShift)
- No error path tests (invalid manifests, missing storage class, timeouts)
- No cleanup/garbage-collection tests (owner references, TTL expiry, finalizers)
- No package mode AIB disk image build test
- No smoke test label — every PR runs the full suite (~30 min)
- No CatalogImage, ContainerBuild, Workspace, ImageReseal, or Flash coverage

---

## Test Matrix

| # | Area | Test Case | Description | Type | Priority | Complexity | Status | Dependencies |
|---|------|-----------|-------------|------|----------|------------|--------|--------------|
| **Operator Core** | | | | | | | | |
| 1 | Controller | Controller pod is running | Verify exactly 1 operator pod exists in Running phase with label `control-plane=operator`. | Smoke | High | Low | Existing, add `Label("smoke")` | — |
| 2 | Tekton | Tekton Tasks created | Verify `build-automotive-image` and `push-artifact-registry` tasks exist in operator namespace. | Smoke | High | Low | Existing, add `Label("smoke")` | — |
| 3 | Tekton | Tekton Pipeline created | Verify `automotive-build-pipeline` pipeline exists in operator namespace. | Smoke | High | Low | Existing, add `Label("smoke")` | — |
| 4 | Build API | Build API deployment available | Verify `ado-build-api` deployment has 1 available replica. | Smoke | High | Low | Existing, add `Label("smoke")` | — |
| 5 | Build API | /v1/healthz returns 200 | HTTP GET to Build API health endpoint returns 200 OK. | Smoke | High | Low | New | Build API |
| **CRD Availability** | | | | | | | | |
| 6 | CRDs | All CRDs are installed | Verify `kubectl get crd` contains all 7 CRDs: imagebuilds, images, catalogimages, containerbuilds, workspaces, imagereseals, operatorconfigs. | Smoke | High | Low | New | — |
| **OperatorConfig (Smoke)** | | | | | | | | |
| 7 | OperatorConfig | Status phase is Ready | Verify OperatorConfig `status.phase=Ready` and `status.osBuildsDeployed=true`, confirming platform controller fully reconciled. | Smoke | High | Low | New | — |
| 8 | OperatorConfig | Target defaults ConfigMap exists | Verify ConfigMap `aib-target-defaults` exists in operator namespace, confirming target architecture/partition config deployed. | Smoke | High | Low | New | — |
| 9 | OperatorConfig | Build ServiceAccount exists | Verify ServiceAccount `ado-build` exists, confirming RBAC setup for build pods completed. | Smoke | High | Low | New | — |
| 10 | OperatorConfig | Internal JWT secret exists | Verify secret `ado-build-api-internal-jwt` exists, confirming Build API auth credentials were generated. | Smoke | High | Low | New | — |
| **CR Lifecycle (Smoke)** | | | | | | | | |
| 11 | ImageBuild | ImageBuild creates PipelineRun | Create minimal ImageBuild CR, verify a PipelineRun is created with matching label within 30s. | Smoke | High | Low | New | Tekton |
| 12 | CatalogImage | CatalogImage reaches Available | Create CatalogImage pointing to public image (`registry.access.redhat.com/ubi9/ubi-micro:latest`), verify it transitions to Available with `resolvedDigest` populated. | Smoke | High | Low | New | Public registry |
| **Build API Endpoints (Smoke)** | | | | | | | | |
| 13 | API | GET /v1/openapi.yaml responds | Verify OpenAPI spec endpoint returns 200 with YAML content, confirming API schema is served. | Smoke | Medium | Low | New | Build API |
| 14 | API | GET /v1/auth/config responds | Verify auth config endpoint returns 200 or 404 (both valid), confirming auth subsystem is loaded. | Smoke | Medium | Low | New | Build API |
| 15 | API | GET /v1/config returns OperatorConfig | Verify config endpoint returns JSON containing `osBuilds` and `images` fields, confirming Build API reads cluster state. | Smoke | Medium | Low | New | Build API, Auth |
| 16 | API | GET /v1/builds returns 200 | Verify list builds endpoint responds (empty list is fine), confirming routing and auth middleware wired. | Smoke | Medium | Low | New | Build API, Auth |
| **Negative / Guard Rails (Smoke)** | | | | | | | | |
| 17 | Auth | Unauthenticated request returns 401 | Send request to protected endpoint `/v1/builds` without token, verify 401 Unauthorized returned. | Smoke | High | Low | New | Build API |
| 18 | Error | Invalid ImageBuild reaches Failed | Create ImageBuild with intentionally broken config (missing distro), verify phase→Failed with non-empty `status.message`. | Smoke | High | Low | New | — |
| 19 | Cleanup | ImageBuild deletion cleans up | Create ImageBuild, wait for PipelineRun, delete ImageBuild, verify PipelineRun garbage-collected via owner references. | Smoke | High | Low | New | Tekton |
| **ImageBuild Lifecycle** | | | | | | | | |
| 20 | Build Phases | Full lifecycle (Pending→Building→Completed) | Create ImageBuild with valid AIB manifest, verify phase transitions and startTime, completionTime, pipelineRunName populated. | E2E | High | Medium | New | Tekton, Registry |
| 21 | Build Phases | Export/push phase | Create ImageBuild with `export` spec, verify Building→Pushing→Completed and artifact accessible in registry. | E2E | High | Medium | New | Registry |
| 22 | Build Phases | Build cancellation | Patch running ImageBuild to cancel, verify phase→Cancelled and PipelineRun stops. | E2E | High | Low | New | — |
| 23 | Build Phases | Package mode disk image build | Run full package mode disk image build using AIB manifest (`mode=package`), verify Completed phase and artifact produced. Mirrors bootc lane for disk images. | E2E | High | High | New | Tekton, Registry, OpenShift |
| 24 | TTL / Expiry | TTL expiry cleanup | Create ImageBuild with short `spec.ttl`, verify it expires and PVC/PipelineRun/ConfigMap deleted. | E2E | Medium | Medium | New | — |
| 25 | TTL / Expiry | Default TTL | Verify OperatorConfig `defaultBuildTTL` applies when `spec.ttl` is unset. | E2E | Medium | Low | New | — |
| 26 | Upload | Upload pod creation | Create ImageBuild with `inputFilesServer=true`, verify upload pod exists and phase is Uploading. | E2E | Medium | Medium | New | Build API |
| 27 | Upload | Upload timeout | Create upload-based build with short timeout, don't complete upload, verify phase→Failed. | E2E | Low | Medium | New | — |
| **Secure & Reproducible Builds** | | | | | | | | |
| 28 | Secure Build | Bundle task resolution | Verify `secureBuild` resolves tasks from digest-pinned Tekton Bundle. | E2E | Medium | High | New | Bundle registry |
| 29 | Secure Build | Reject non-digest ref | Verify `secureBuild` rejects tag-based `taskBundleRef` with validation error. | E2E | Medium | Low | New | — |
| 30 | Reproducible | OCI referrers saved | Verify reproducible build attaches RPM list, manifest, bundle ref as OCI referrers. | E2E | Low | High | New | ORAS, Registry |
| **ContainerBuild** | | | | | | | | |
| 31 | ContainerBuild | BuildRun created | Verify ContainerBuild CR creates Shipwright BuildRun with correct params. | E2E | Medium | Medium | New | Shipwright |
| 32 | ContainerBuild | Completes with digest | Verify ContainerBuild reaches Completed with `imageDigest` populated. | E2E | Medium | Medium | New | Shipwright, Registry |
| **Workspace** | | | | | | | | |
| 33 | Workspace | Pod reaches Running | Verify Workspace CR creates pod in Running phase with PVC bound. | E2E | Medium | Medium | New | — |
| 34 | Workspace | Auto-pause on idle | Verify workspace transitions to Stopped after `autoPauseTimeoutMinutes`. | E2E | Low | Medium | New | — |
| 35 | Workspace | Stop/resume toggle | Verify `spec.stopped=true` stops pod, `spec.stopped=false` recreates it. | E2E | Low | Low | New | — |
| 36 | Workspace | Image allowlist | Verify workspace rejects images not in `allowedImages` list. | E2E | Low | Low | New | — |
| **OperatorConfig (E2E)** | | | | | | | | |
| 37 | OperatorConfig | Toggle osBuilds.enabled | Verify disabling removes Tekton resources, re-enabling recreates them. | E2E | High | Low | New | — |
| 38 | OperatorConfig | Image propagation | Verify changing `spec.images` updates Tekton Task image references. | E2E | Medium | Low | New | — |
| 39 | OperatorConfig | ServiceMonitor | Verify `monitoring.enabled=true` creates ServiceMonitor, false removes it. | E2E | Low | Low | New | Prometheus CRD |
| 40 | OperatorConfig | Memory volumes | Verify `useMemoryVolumes` uses emptyDir `medium=Memory` instead of PVC. | E2E | Low | Medium | New | — |
| **Build API (E2E)** | | | | | | | | |
| 41 | Build API | POST /v1/builds | Verify API creates ImageBuild CR and returns build name. | E2E | High | Low | New | Build API |
| 42 | Build API | GET /v1/builds/{name} | Verify API returns correct phase, architecture, timestamps. | E2E | High | Low | New | Build API |
| 43 | Build API | DELETE /v1/builds/{name} | Verify API cancels build and CR transitions to Cancelled. | E2E | Medium | Low | New | Build API |
| 44 | Build API | GET /v1/builds/{name}/logs | Verify API streams Tekton TaskRun log content. | E2E | Medium | Medium | New | Build API, Tekton |
| 45 | Build API | POST /v1/builds/{name}/uploads | Verify file upload works and size limits are enforced. | E2E | Medium | Medium | New | Build API |
| 46 | Build API | GET /v1/config | Verify API returns current OperatorConfig settings. | E2E | Low | Low | New | Build API |
| **Authentication (E2E)** | | | | | | | | |
| 47 | Auth | Build ownership enforcement | Verify a user cannot cancel or delete another user's build (returns 403 Forbidden). | E2E | High | Low | New | Build API |
| 48 | Auth | Valid JWT → 200 | Verify valid service account token grants access. | E2E | Medium | Medium | New | Build API |
| 49 | Auth | Invalid token → 401 | Verify expired/malformed token returns 401 without leaking details. | E2E | Medium | Low | New | Build API |
| 50 | Auth | OIDC config endpoint | Verify `/v1/auth/config` returns configured OIDC provider and client ID. | E2E | Low | Low | New | Build API |
| 51 | Auth | OIDC not configured returns 404 only | Tighten assertion: when OIDC is not configured, `/v1/auth/config` must return exactly 404 (not 200). | E2E | Low | Low | New | Build API |
| **Image & CatalogImage** | | | | | | | | |
| 52 | Image | Image CR after build | Verify Image CR created with correct location, distro, architecture, exportFormat. | E2E | Medium | Medium | New | Registry |
| 53 | CatalogImage | Registry verification | Verify CatalogImage populates `registryMetadata` and `lastVerificationTime`. | E2E | Low | High | New | Registry |
| 54 | CatalogImage | Label propagation | Verify `spec.metadata` fields produce correct labels (architecture normalized). | E2E | Low | Low | New | — |
| 55 | CatalogImage | Unreachable registry | Verify non-existent registry transitions to Unavailable with `Available=False`. | E2E | Low | Low | New | — |
| **ImageReseal & Flash** | | | | | | | | |
| 56 | ImageReseal | Sealed-image pipeline | Verify ImageReseal CR creates PipelineRun with sealed-image-stage tasks. | E2E | Low | High | New | Cosign, Registry |
| 57 | Flash | Flash TaskRun | Verify ImageBuild with flash spec creates flash TaskRun with correct lease params. | E2E | Low | High | New | Jumpstarter |
| **Error Handling & Cleanup** | | | | | | | | |
| 58 | Errors | Missing storage class | Verify non-existent `storageClass` fails with clear error, not hanging. | E2E | Medium | Low | New | — |
| 59 | Errors | Concurrent builds | Verify two simultaneous builds get independent resources without conflicts. | E2E | Medium | Medium | New | — |
| 60 | Cleanup | Expired build cleanup | Verify expired build deletes PipelineRun, TaskRuns, PVC, ConfigMap, ImageStream. | E2E | Medium | Medium | New | — |
| 61 | Cleanup | CatalogImage deletion | Verify deleting Available CatalogImage removes finalizer and completes within 30s. | E2E | Low | Low | New | — |

---

## CI / Workflow Changes

| # | Change | Description | Files |
|---|--------|-------------|-------|
| W1 | Smoke as default PR filter | Change `e2e.yml` default label filter from full suite to `smoke` on every PR push. Full suite via `workflow_dispatch` or `/e2e-test-all` comment. Reduces PR CI from ~30 min to ~2 min test time. | `.github/workflows/e2e.yml` |
| W2 | Package mode build lane trigger | Add `/e2e-package-mode` PR comment trigger for test #23 on OpenShift. Skip on Kind (no AIB tooling). | `.github/workflows/e2e-lanes.yml` |
| W3 | Auth nightly schedule | Add nightly scheduled workflow targeting self-hosted OpenShift runner for auth lane tests (#50, #51). | New nightly workflow |
| W4 | Smoke lane in e2e-lanes.yml | Add `/e2e-smoke` PR comment trigger to `e2e-lanes.yml` case statement. | `.github/workflows/e2e-lanes.yml` |

---

## Label Strategy

| Label | Tests | Trigger | Cluster | Runtime |
|-------|-------|---------|---------|---------|
| `smoke` | #1–19 (superset of `operator`) | Every PR push (default) | Kind + OpenShift | ~5 min |
| `operator` | #1–4 (subset of `smoke`, existing `operator_test.go` tests only) | `/e2e-operator` PR comment | Kind + OpenShift | ~3 min |
| `package-mode` | #23 | `/e2e-package-mode` PR comment | OpenShift only | ~10 min |
| `bootc` | Existing bootc lane | `/e2e-bootc` PR comment | Kind + OpenShift | ~10 min |
| `auth` | #50, #51 + existing auth tests | Nightly + `/e2e-auth` | OpenShift only | ~5 min |

---

## Summary

| Metric | Smoke | E2E | Total |
|--------|-------|-----|-------|
| Existing (add smoke label) | 4 | — | 4 |
| New | 15 | 42 | 57 |
| **Total** | **19** | **42** | **61** |
| CI workflow changes | — | — | 4 |

---

## Implementation Phases

| Phase | Target | Tests | Deliverables | Cluster | CI Trigger | Est. Effort |
|-------|--------|-------|--------------|---------|------------|-------------|
| **Phase 1: Smoke Suite** | Week 1–2 | #1–19 | Add `Label("smoke")` to 4 existing tests. Write 15 new smoke tests in `smoke_test.go`. Apply W1 (smoke as default PR filter) + W4 (smoke lane). | Kind | Every PR push | 3–4 days |
| **Phase 2: Core E2E** | Week 3–4 | #20–22, 37, 41–42, 47, 58 | ImageBuild lifecycle (full, cancel), OperatorConfig toggle, Build API create/get, auth gate, errors. Write in `imagebuild_lifecycle_test.go` + `buildapi_test.go`. | Kind | On demand | 3–4 days |
| **Phase 3: Package Mode Build + CI** | Week 5–6 | #23 + W2 | Package mode disk image build lane. Write `package_build_test.go`. Add `/e2e-package-mode` to `e2e-lanes.yml`. | OpenShift | PR comment | 2–3 days |
| **Phase 4: Extended E2E** | Week 7–9 | #24–26, 31–33, 38, 43–45, 48–49, 52, 59–60 | TTL/expiry, upload flow, ContainerBuild, Workspace basics, Build API CRUD, auth edge cases, cleanup. | Kind + OpenShift | On demand | 5–7 days |
| **Phase 5: Advanced & Nightly** | Week 10–12 | #27–30, 34–36, 39–40, 46, 50–51, 53–57, 61 + W3 | Secure/reproducible builds, workspace advanced (pause/resume/allowlist), monitoring, ImageReseal, Flash, catalog deep tests, auth nightly. | OpenShift | Nightly / on demand | 5–7 days |

---

## Future Planning

### Short-Term

| Goal | Description | Depends On |
|------|-------------|------------|
| Smoke gate on every PR | Phase 1 complete — smoke tests block merge if failing. Reduces feedback loop from ~30 min to ~2 min. | Phase 1 |
| Core E2E on merge to main | Phase 2 tests run automatically on merge to main branch (post-merge validation). | Phase 2 |
| Package mode build parity | Package mode disk image lane matches bootc lane coverage — both build types tested in CI. | Phase 3 |
| Coverage target: 40% | Phases 1–3 bring coverage from ~2% to ~40% of controller/API surface. | Phases 1–3 |

### Mid-Term

| Goal | Description | Depends On |
|------|-------------|------------|
| Coverage target: 70% | Phases 4–5 bring coverage to ~70% across all CRDs, API endpoints, and error paths. | Phases 4–5 |
| Nightly regression suite | Full e2e suite (all labels) runs nightly on OpenShift with results reported to Slack/dashboard. | W3, Phase 5 |
| Multi-arch e2e | Run smoke + core e2e on both amd64 and arm64 clusters. Currently arm64 only. | Phase 1, CI infra |
| Flaky test quarantine | Introduce `Label("flaky")` for tests that fail intermittently. Quarantined tests skip in smoke/PR, run in nightly only. | Phase 4 |
| OpenShift-specific smoke | Add OpenShift-only smoke tests: OAuth proxy, Route creation, internal registry token minting. Run via `/e2e-smoke-ocp`. | Phase 1, OpenShift runner |

### Long-Term

| Goal | Description | Depends On |
|------|-------------|------------|
| Coverage target: 90% | Full coverage of all 7 CRDs, 24 API routes, auth flows, error paths, cleanup, and edge cases. | All phases |
| Performance benchmarks | Track PipelineRun creation latency, Build API response times, controller reconcile duration as e2e metrics. | Phase 2, Prometheus |
| Chaos/resilience tests | Test operator recovery from: controller pod restart mid-build, Tekton pipeline deletion during build, registry unavailability during push. | Phase 4 |
| Upgrade/migration tests | Deploy operator v(N-1), create resources, upgrade to v(N), verify resources are reconciled correctly with no data loss. | Phase 5, OLM |
| Hardware-in-the-loop | Flash tests on real hardware via Jumpstarter lab. Nightly only, dedicated hardware runner. | Phase 5, Jumpstarter infra |
| Security scanning in e2e | Run container image vulnerability scan and RBAC audit as part of nightly e2e. | Phase 5 |
| Test result dashboard | Grafana dashboard showing e2e pass/fail trends, flaky test rate, coverage growth over time. | Nightly suite, Prometheus |
