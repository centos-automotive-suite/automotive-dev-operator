#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=${VERSION:-$(cat "$SCRIPT_DIR/../VERSION" 2>/dev/null || echo "0.0.0")}
NAMESPACE=${NAMESPACE:-openshift-marketplace}

echo "Detecting OpenShift internal registry..."
INTERNAL_REGISTRY=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null || echo "")

if [ -z "$INTERNAL_REGISTRY" ]; then
    echo "ERROR: Internal registry route not found. Run ./deploy-catalog.sh first."
    exit 1
fi

REGISTRY=${REGISTRY:-${INTERNAL_REGISTRY}}
CATALOG_IMG="${REGISTRY}/${NAMESPACE}/automotive-dev-operator-catalog:v${VERSION}"
CONTAINER_TOOL=${CONTAINER_TOOL:-podman}

echo "=========================================="
echo "Rebuilding Catalog"
echo "=========================================="
echo "Catalog Image: ${CATALOG_IMG}"
echo "=========================================="

echo ""
echo "Logging in to OpenShift registry..."
${CONTAINER_TOOL} login -u "$(oc whoami)" -p "$(oc whoami -t)" ${REGISTRY} --tls-verify=false

echo ""
echo "Regenerating catalog..."
cat > catalog/automotive-dev-operator.yaml << EOF
---
defaultChannel: alpha
name: automotive-dev-operator
schema: olm.package
---
schema: olm.channel
package: automotive-dev-operator
name: alpha
entries:
  - name: automotive-dev-operator.v${VERSION}
---
EOF
./bin/opm render bundle/ --output yaml >> catalog/automotive-dev-operator.yaml

echo ""
echo "Validating catalog..."
if [ -f "bin/opm" ]; then
    ./bin/opm validate catalog/
else
    echo "Warning: opm not found, skipping validation"
fi

echo ""
echo "Building catalog image..."
${CONTAINER_TOOL} build -f catalog.Dockerfile -t ${CATALOG_IMG} .

echo ""
echo "Pushing catalog image..."
${CONTAINER_TOOL} push ${CATALOG_IMG} --tls-verify=false

echo ""
echo "Refreshing CatalogSource..."
kubectl delete catalogsource automotive-dev-operator-catalog -n openshift-marketplace --ignore-not-found=true

sleep 5

CATALOG_IMG_INTERNAL="image-registry.openshift-image-registry.svc:5000/${NAMESPACE}/automotive-dev-operator-catalog:v${VERSION}"
sed -i.bak "s|image:.*|image: ${CATALOG_IMG_INTERNAL}|g" catalogsource.yaml
rm -f catalogsource.yaml.bak

oc apply -f catalogsource.yaml

echo ""
echo "=========================================="
echo "Catalog Rebuilt and Deployed!"
echo "=========================================="
echo ""
echo "  oc get catalogsource -n openshift-marketplace"
echo "  oc get pods -n openshift-marketplace | grep automotive"
echo ""
echo "Check for packages:"
echo "  oc get packagemanifests | grep automotive"
echo ""

