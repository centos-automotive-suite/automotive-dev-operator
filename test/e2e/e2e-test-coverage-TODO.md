# E2E Test Coverage — Implementation TODO

Tracks progress against the original test coverage proposal.
Last updated: 2026-06-22

## Summary

| Phase | Scope | Done | Remaining | Status |
|-------|-------|------|-----------|--------|
| Phase 1: Smoke Suite | #1–19, W1, W4 | 19/19 tests, 2/2 CI | 0 | Complete |
| Phase 2: Core E2E | #20–22, 37, 41–42, 47 | 7/7 | 0 | Complete |
| Phase 3: Package Mode | #23, W2 | 1/1 test, 1/1 CI | 0 | Complete |
| Phase 4: Extended E2E | #24–26, 31–33, 38, 43–45, 48–49, 52, 59–60 | 9/15 | 6 | In progress |
| Phase 5: Advanced & Nightly | #27–30, 34–36, 39–40, 46, 50–51, 53–57, 61, W3 | 2/18 tests, 0/1 CI | 17 | Not started |
| **Total** | **61 tests + 4 CI** | **38/61 tests, 3/4 CI** | **24** | |

---

## Phase 1: Smoke Suite — COMPLETE

All 19 smoke tests implemented. CI runs smoke on every PR.

| # | Test | File | Status |
|---|------|------|--------|
| 1 | Controller pod is running | `operator_test.go` | Done |
| 2 | Tekton Tasks created | `operator_test.go` | Done |
| 3 | Tekton Pipeline created | `operator_test.go` | Done |
| 4 | Build API deployment available | `operator_test.go` | Done |
| 5 | /v1/healthz returns 200 | `smoke_test.go` | Done |
| 6 | All CRDs installed | `smoke_test.go` | Done |
| 7 | OperatorConfig status Ready | `smoke_test.go` | Done |
| 8 | Target defaults ConfigMap exists | `smoke_test.go` | Done |
| 9 | Build ServiceAccount exists | `smoke_test.go` | Done |
| 10 | Internal JWT secret exists | `smoke_test.go` | Done |
| 11 | ImageBuild creates PipelineRun | `smoke_test.go` | Done |
| 12 | CatalogImage reaches Available | `smoke_test.go` | Done |
| 13 | /v1/openapi.yaml responds | `smoke_test.go` | Done |
| 14 | /v1/auth/config responds | `smoke_test.go` | Done |
| 15 | /v1/config returns OperatorConfig | `smoke_test.go` | Done |
| 16 | /v1/builds returns 200 | `smoke_test.go` | Done |
| 17 | Unauthenticated request returns 401 | `smoke_test.go` | Done |
| 18 | Invalid ImageBuild reaches Failed | `smoke_test.go` | Done |
| 19 | ImageBuild deletion cleans up | `smoke_test.go` | Done |

| CI | Change | Status |
|----|--------|--------|
| W1 | Smoke as default PR filter | Done |
| W4 | `/e2e-smoke` lane in e2e-lanes.yml | Done |

---

## Phase 2: Core E2E — COMPLETE

| # | Test | File | Status |
|---|------|------|--------|
| 20 | Full lifecycle (Pending->Building->Completed) | `bootc_build_test.go` | Done |
| 21 | Export/push phase | `imagebuild_lifecycle_test.go` | Done — implemented in `By("verifying push-disk-artifact task ran in the PipelineRun")` |
| 22 | Build cancellation | `imagebuild_lifecycle_test.go` | Done |
| 37 | Toggle osBuilds.enabled | `operatorconfig_e2e_test.go` | Done |
| 41 | POST /v1/builds — via `caib image build-dev` | `buildapi_test.go` | Done |
| 42 | GET /v1/builds/{name} — via `caib image show` | `buildapi_test.go` | Done |
| 47 | Build ownership enforcement (403) — raw HTTP | `buildapi_test.go` | Done |
| 58 | Missing storage class error | — | N/A |

---

## Phase 3: Package Mode Build + CI — COMPLETE

| # | Test | File | Status |
|---|------|------|--------|
| 23 | Package mode disk image build | `package_build_test.go` | Done — OpenShift only |

| CI | Change | Status |
|----|--------|--------|
| W2 | `/e2e-package-mode` lane trigger | Done |

---

## Phase 4: Extended E2E — IN PROGRESS

| # | Test | File | Status |
|---|------|------|--------|
| 24 | TTL expiry cleanup | `features_e2e_test.go` | Done |
| 25 | Default TTL from OperatorConfig | `features_e2e_test.go` | Done |
| 26 | Upload pod creation (inputFilesServer) | — | TODO |
| 31 | ContainerBuild creates BuildRun | — | TODO — requires Shipwright |
| 32 | ContainerBuild completes with digest | — | TODO — requires Shipwright + registry |
| 33 | Workspace pod reaches Running | — | TODO |
| 38 | Image propagation in Tekton Tasks | `features_e2e_test.go` | Done |
| 43 | DELETE /v1/builds/{name} — via `caib image delete` | `buildapi_test.go` | Done |
| 44 | GET /v1/builds/{name}/logs | `features_e2e_test.go` | Done |
| 45 | POST /v1/builds/{name}/uploads | — | TODO |
| 48 | Valid JWT -> 200 | `auth_test.go` | Done |
| 49 | Invalid token -> 401 | `auth_test.go` | Done |
| 52 | Image CR created after build | — | TODO — requires registry |
| 59 | Concurrent builds independence | `error_handling_test.go` | Done |
| 60 | Expired build cleanup | `features_e2e_test.go` | Done |

---

## Phase 5: Advanced & Nightly — NOT STARTED

| # | Test | File | Status |
|---|------|------|--------|
| 27 | Upload timeout | — | TODO |
| 28 | Bundle task resolution (secureBuild) | — | TODO — requires bundle registry |
| 29 | Reject non-digest taskBundleRef | — | TODO |
| 30 | OCI referrers saved (reproducible) | — | TODO — requires ORAS + registry |
| 34 | Workspace auto-pause on idle | — | TODO |
| 35 | Workspace stop/resume toggle | — | TODO |
| 36 | Workspace image allowlist | — | TODO |
| 39 | ServiceMonitor creation | — | TODO — requires Prometheus CRD |
| 40 | Memory volumes (useMemoryVolumes) | — | TODO |
| 46 | GET /v1/config (E2E-level validation) | — | TODO |
| 50 | OIDC config endpoint returns provider | `auth_test.go` | Done |
| 51 | OIDC not configured returns 404 only | `auth_test.go` | Done |
| 53 | CatalogImage registry verification | — | TODO — requires registry |
| 54 | CatalogImage label propagation | — | TODO |
| 55 | CatalogImage unreachable registry | — | TODO |
| 56 | ImageReseal sealed-image pipeline | — | TODO — requires Cosign + registry |
| 57 | Flash TaskRun | — | TODO — requires Jumpstarter |
| 61 | CatalogImage deletion finalizer | — | TODO |

| CI | Change | Status |
|----|--------|--------|
| W3 | Auth nightly schedule | TODO — new nightly workflow for OpenShift |

---

## File Inventory

| File | Tests | Labels |
|------|-------|--------|
| `operator_test.go` | #1–4 | `operator`, `smoke` |
| `smoke_test.go` | #5–19 | `smoke` |
| `imagebuild_lifecycle_test.go` | #21–22 | `operator` |
| `operatorconfig_e2e_test.go` | #37 | `operator` |
| `buildapi_test.go` | #41–43, #47 | `operator` |
| `error_handling_test.go` | #59 | `operator` |
| `package_build_test.go` | #23 | `package-mode` |
| `features_e2e_test.go` | #24–25, #38, #44, #60 | `features` |
| `auth_test.go` | #48–51 | `auth` |
| `bootc_build_test.go` | #20, bootc build, internal registry | `bootc`, `internal-registry` |
| `manifest_validation_test.go` | manifest validation (no proposal #) | `manifest-validation` |

---

## Remaining Work by Priority

### High priority (next)
- [x] #24–25 — TTL expiry tests
- [x] #44 — Build API log streaming
- [ ] #52 — Image CR verification after build
- [x] #60 — Expired build cleanup

### Medium priority
- [ ] #26 — Upload pod creation
- [ ] #27 — Upload timeout
- [ ] #31–32 — ContainerBuild (requires Shipwright)
- [ ] #33 — Workspace pod running
- [x] #38 — Image propagation
- [ ] #45 — Build API uploads

### Low priority / infrastructure-dependent
- [ ] #28–30 — Secure/reproducible builds (bundle registry, ORAS)
- [ ] #34–36 — Workspace advanced (pause, resume, allowlist)
- [ ] #39–40 — ServiceMonitor, memory volumes
- [ ] #53–55 — CatalogImage deep tests
- [ ] #56–57 — ImageReseal, Flash (Cosign, Jumpstarter)
- [ ] #61 — CatalogImage deletion
- [ ] W3 — Auth nightly workflow
