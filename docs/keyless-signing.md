# Keyless Signing

Tekton Chains signs built container images automatically using Fulcio short-lived
certificates. No long-lived keys needed.

## Configure Tekton Chains

Patch `TektonConfig` to point Chains at Fulcio and Rekor:

```bash
oc patch tektonconfig config --type=merge -p '{
  "spec": {
    "chain": {
      "signers.x509.fulcio.enabled": true,
      "signers.x509.fulcio.address": "http://fulcio-server.trusted-artifact-signer.svc",
      "transparency.enabled": true,
      "transparency.url": "http://rekor-server.trusted-artifact-signer.svc:80",
      "artifacts.taskrun.format": "slsa/v1",
      "artifacts.taskrun.storage": "oci",
      "artifacts.pipelinerun.format": "slsa/v1",
      "artifacts.pipelinerun.storage": "oci"
    }
  }
}'
```

Fulcio must accept Kubernetes SA tokens as OIDC identity. The Securesign CR
needs this OIDC config:

```yaml
fulcio:
  config:
    OIDCIssuers:
      - ClientID: "sigstore"
        IssuerURL: "https://kubernetes.default.svc"
        Issuer: "https://kubernetes.default.svc"
        Type: "kubernetes"
```

Initialize cosign with the TUF root so it trusts the local Fulcio CA:

```bash
TUF_URL="https://$(oc get route tuf -n trusted-artifact-signer -o jsonpath='{.spec.host}')"
cosign initialize --mirror "$TUF_URL" --root "$TUF_URL/root.json"
```

## Build an Image

```bash
caib image build manifest.aib.yml \
  --name my-build \
  --arch aarch64 \
  --push quay.io/<user>/my-build:bootc \
  --push-disk quay.io/<user>/my-build:disk
```

On completion, the output shows the image digest that Chains will sign:

```
Tekton Chains: IMAGE_URL=quay.io/<user>/my-build:bootc IMAGE_DIGEST=sha256:...
```

## Verify Signing

### Check Chains annotations on the TaskRun

```bash
oc get taskrun <taskrun-name> -n automotive-dev-operator-system \
  -o jsonpath='{.metadata.annotations.chains\.tekton\.dev/signed}'
```

Should return `true`.

### Verify signature with cosign

```bash
EXT_HOST="$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')"
REKOR_URL="https://$(oc get route rekor-server -n trusted-artifact-signer -o jsonpath='{.spec.host}')"

cosign login "$EXT_HOST" -u "$(oc whoami)" -p "$(oc whoami -t)"

cosign verify \
  --rekor-url "$REKOR_URL" \
  --certificate-identity "https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller" \
  --certificate-oidc-issuer "https://kubernetes.default.svc" \
  "${EXT_HOST}/<namespace>/<image>@sha256:<digest>"
```

Expected output:

```
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
```

## Signing Identity

| Field | Value |
|-------|-------|
| Certificate Identity | `https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller` |
| OIDC Issuer | `https://kubernetes.default.svc` |

Identity comes from the Chains controller ServiceAccount token. Fulcio validates
it against the cluster OIDC issuer and embeds it as the certificate SAN.

## Operator-Side Verification

The operator can verify keyless signatures on task bundles and workspace images
via OperatorConfig. To pin a specific Fulcio instance (preventing trust of
certificates from other Fulcio instances like public Sigstore), set
`fulcioRootCARef`:

```yaml
spec:
  osBuilds:
    taskBundleVerify: true
    taskBundleRef: "quay.io/org/my-bundle@sha256:..."
    taskBundleCosignKeyless:
      certificateIdentity: "https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller"
      certificateOIDCIssuer: "https://kubernetes.default.svc"
      fulcioRootCARef:
        name: fulcio-root-ca
        key: ca.pem
```

Create the ConfigMap from the Fulcio root CA certificate:

```bash
oc create configmap fulcio-root-ca \
  --from-file=ca.pem=.e2e/sigstore-certs/fulcio-root.pem \
  -n automotive-dev-operator-system
```

Without `fulcioRootCARef`, the operator trusts the default Sigstore TUF root,
which means any Kubernetes cluster could produce valid-looking signatures with
the same SA identity via public Sigstore Fulcio.
