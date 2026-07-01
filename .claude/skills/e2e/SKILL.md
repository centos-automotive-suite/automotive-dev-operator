---
name: e2e
description: >-
  Scaffold a new Ginkgo e2e test suite: add CI lane wiring in e2e.yml and
  e2e-lanes.yml, register timeout in hack/e2e/timeouts.env, add a Makefile.e2e
  target, create a template test file under test/e2e, and update reference
  docs. Use when the user invokes /e2e or asks to add a new e2e suite, lane, or
  label.
disable-model-invocation: true
---

# /e2e — Add E2E Test Suite

Scaffold a new labeled Ginkgo suite so it runs locally, in CI (`e2e.yml`), and via PR comment lanes (`/e2e-<name>`).

## Expectations

- **Default PR CI runs `smoke` only** (`e2e.yml`). A new suite is not in the PR gate unless tests are added to the smoke label or the lane is triggered via `/e2e-<name>`.
- **Every new lane needs full wiring**: timeout, workflows, Makefile, runners, README, and real tests. Do not stop at `timeouts.env` + a Ginkgo label alone (see incomplete suites below).

## Input

`$ARGUMENTS` is the suite **label** in kebab-case (e.g. `my-feature`, `package-mode`).

If missing, ask for:
1. Label name (kebab-case) — must not prefix or be prefixed by an existing lane (see pitfalls)
2. Timeout tier: `10m` (fast), `15m` (medium), or `45m` (slow) — default `10m`
3. Whether tests need Dex (`hack/e2e/setup-dex.sh`) — default no

## Naming conventions

| Concept | Example (`my-feature`) |
|---------|------------------------|
| Ginkgo label | `my-feature` |
| Go test file | `test/e2e/my_feature_test.go` |
| Timeout var | `E2E_TIMEOUT_my_feature` |
| PR comment | `/e2e-my-feature` |
| CI namespace | `e2e-my-feature` |
| Make target | `test-e2e-my-feature` |

Hyphens in the label become underscores in env vars and filenames (`${name//-/_}`).

## Pitfalls

- **`/e2e-*` prefix collisions**: `e2e-lanes.yml` matches with shell globs (`/e2e-bootc*`). Avoid lane names that are prefixes of existing lanes (e.g. `boot` vs `bootc`). Put more specific `case` arms before general ones.
- **Dex on Kind**: CI workflows call `hack/e2e/setup-dex.sh`, but `hack/run-e2e-kind.sh` does not yet. When Dex is required, add a pre-test step to that script (and `run-e2e-local.sh` if applicable):

  ```bash
  if [[ "$E2E_LANE" == "my-feature" || "$E2E_LANE" == "all" ]]; then
    bash hack/e2e/setup-dex.sh
  fi
  ```

## Workflow

Copy this checklist and track progress:

```
- [ ] 1. hack/e2e/timeouts.env
- [ ] 2. .github/workflows/e2e.yml
- [ ] 3. .github/workflows/e2e-lanes.yml
- [ ] 4. Makefile.e2e
- [ ] 5. test/e2e/<name>_test.go (real tests, not placeholder)
- [ ] 6. Reference docs (README, runners)
- [ ] 7. Verify (fmt, lint, compile, then cluster if available)
```

### 1. `hack/e2e/timeouts.env`

Add one line in the appropriate tier section:

```bash
E2E_TIMEOUT_my_feature=10m
```

Place under the matching comment block (`# fast lanes`, `# medium lanes`, or `# slow lanes`).

Update the file header if it still says "No other files need to change" — that is outdated; full lane wiring requires the steps below.

### 2. `.github/workflows/e2e.yml`

Add the label to the `workflow_dispatch.inputs.label_filter.description` string (keep alphabetical or grouped with similar suites).

If the suite needs Dex (like `auth`), extend the **Deploy Dex for OIDC tests** `if:` condition:

```yaml
github.event.inputs.label_filter == 'my-feature' ||
```

### 3. `.github/workflows/e2e-lanes.yml`

Add a `case` arm in **Parse lane from comment** (before the `*)` default). Place it so it does not shadow or get shadowed by existing prefix patterns:

```bash
/e2e-my-feature*)
  echo "label_filter=my-feature" >> "$GITHUB_OUTPUT"
  echo "lane_name=my-feature" >> "$GITHUB_OUTPUT"
  ;;
```

Update the `Supported:` line in the `*)` branch to include `/e2e-my-feature`.

If the suite needs Dex, extend **Deploy Dex for OIDC tests** `if:`:

```yaml
needs.parse-comment.outputs.lane_name == 'my-feature' ||
```

### 4. `Makefile.e2e`

Add a one-line comment in the header block (after existing lane comments) and a target after the last lane target:

```makefile
#   test-e2e-my-feature     - short description of the suite
.PHONY: test-e2e-my-feature
test-e2e-my-feature:
	E2E_NAMESPACE=$${E2E_NAMESPACE:-e2e-my-feature} go test ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="my-feature" -timeout $(E2E_TIMEOUT_my_feature)
```

### 5. `test/e2e/<name>_test.go`

Create from this template (replace `my-feature`, `My Feature`, and implement real tests):

```go
/*
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
*/

package e2e

import (
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("My Feature", Label("my-feature"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	It("should …", func() { Fail("implement before merge") })
})
```

**Do not merge** `Expect(true).To(BeTrue())` or other no-op assertions. Replace `Pending(...)` with real `It` blocks before opening a PR. Use `Skip(...)` only for environment-specific conditions (see `auth_test.go`).

Adjust `BeforeAll` helpers to match suite needs (common: `ensureBuildAPIAccess()`, `ensureCaibCredentials()`).

### 6. Reference docs

Keep lane lists in sync wherever runners and docs enumerate suites. When editing, **scan and fix stale lists** for other lanes too (e.g. `container-build` missing from README tables, benchmark timeouts out of sync with `timeouts.env`).

Search for gaps:

```bash
rg 'test-e2e-|/e2e-|Label\(\"' test/e2e hack .github/workflows
```

#### `test/e2e/README.md` (required)

Update these sections:

1. **Test Lanes** table — add a row:

   ```markdown
   | `my-feature` | `my-feature` | `e2e-my-feature` | Short description of what the suite covers |
   ```

2. **Running individual lanes** — add `make test-e2e-my-feature`, `bash hack/run-e2e-local.sh my-feature`, and `bash hack/run-e2e-kind.sh my-feature`.

3. **Test Structure** — add the new file:

   ```markdown
   - `my_feature_test.go`: short description (`Label("my-feature")`)
   ```

4. **GitHub Actions** — add `/e2e-my-feature` to the PR comment command list.

5. **Benchmarks** (optional) — add a row only after measuring runtime; copy the timeout value from `timeouts.env`, not from other README rows.

#### `hack/run-e2e-local.sh` and `hack/run-e2e-kind.sh`

Add the lane to the help text, the file header comment, and the `case` pattern:

```bash
# header / usage:
printf '  my-feature      - short description\n'

# case arm:
smoke|operator|...|my-feature)
```

If Dex is required, add the `setup-dex.sh` hook described in **Pitfalls** above.

#### Other docs (when relevant)

- `test/e2e/e2e-test-coverage-TODO.md` — if the suite maps to tracked coverage items
- `README.md` — only if the suite introduces user-facing behavior worth documenting outside e2e

## Verify

**1. Format and lint** (no cluster required). Fix any failures before proceeding:

```bash
make fmt
make lint
```

If `make lint` fails, fix reported issues (or run `make lint-fix` when auto-fix applies), then re-run `make fmt` and `make lint` until both pass.

**2. Compile** (no cluster required):

```bash
go test -c ./test/e2e/
go vet ./test/e2e/
```

**3. Label filter** (no cluster required):

```bash
go test ./test/e2e/ -ginkgo.label-filter="my-feature" -ginkgo.dry-run -v -ginkgo.v -timeout 10m || \
  go test ./test/e2e/ -ginkgo.label-filter="my-feature" -c -count=1
```

**4. Full lane** (cluster required):

```bash
make test-e2e-my-feature
```

Confirm:
- `make fmt` and `make lint` pass
- Label in the Go file matches `label_filter` / `lane_name` in workflows and `-ginkgo.label-filter` in Makefile.e2e
- Timeout variable name matches lane name with hyphens → underscores
- No duplicate labels or timeout vars
- README, Makefile, and runner scripts list the new lane
- No `Pending` or no-op tests remain

## Reference — existing suites

Fully wired lanes (use as models):

| Label | File | Make / PR lane | Timeout |
|-------|------|----------------|---------|
| `smoke` | `smoke_test.go` | `test-e2e-smoke` / `/e2e-smoke` | 15m |
| `operator` | `operator_test.go` | `test-e2e-operator` / `/e2e-operator` | 10m |
| `auth` | `auth_test.go` | `test-e2e-auth` / `/e2e-auth` | 10m |
| `features` | `features_e2e_test.go` | `test-e2e-features` / `/e2e-features` | 10m |
| `bootc` | `bootc_build_test.go` | `test-e2e-bootc` / `/e2e-bootc` | 15m |
| `package-mode` | `package_build_test.go` | `test-e2e-package-mode` / `/e2e-package-mode` | 15m |
| `container-build` | `container_build_test.go` | `test-e2e-container-build` / `/e2e-container-build` | 45m |

Incomplete (timeout + label only — do not copy this pattern):

| Label | File | Missing wiring |
|-------|------|----------------|
| `manifest-validation` | `manifest_validation_test.go` | Makefile target, `/e2e-*` lane, README lane row |
| `internal-registry` | `bootc_build_test.go` | Makefile target, `/e2e-*` lane, README lane row |

Shared helpers live in `test/e2e/helpers_test.go`.
