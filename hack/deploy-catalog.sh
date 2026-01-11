#!/bin/bash
set -e

# Parse command line options
COMMAND=""
case ${1:-} in
    install)
        COMMAND="install"
        ;;
    uninstall|remove)
        COMMAND="uninstall"
        ;;
    redeploy|reinstall)
        COMMAND="redeploy"
        ;;
    clean)
        COMMAND="clean"
        ;;
    *)
        echo "Usage: $0 {install|uninstall|redeploy|clean}"
        echo ""
        echo "Commands:"
        echo "  install    - Deploy the operator catalog and install operator"
        echo "  uninstall  - Uninstall the operator and remove resources"
        echo "  redeploy   - Uninstall and reinstall (equivalent to uninstall + install)"
        echo "  clean      - Thorough cleanup of all operator resources"
        echo ""
        exit 1
        ;;
esac

# Configuration
VERSION=${VERSION:-0.0.1}
NAMESPACE=${NAMESPACE:-automotive-dev-operator-system}

# Detect OpenShift internal registry
echo "Detecting OpenShift internal registry..."
INTERNAL_REGISTRY=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null || echo "")

if [ -z "$INTERNAL_REGISTRY" ]; then
    echo "Internal registry route not found. Creating it..."
    oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{"spec":{"defaultRoute":true}}' --type=merge

    echo "Waiting for registry route to be created..."
    for i in {1..30}; do
        INTERNAL_REGISTRY=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null || echo "")
        if [ -n "$INTERNAL_REGISTRY" ]; then
            break
        fi
        sleep 2
    done

    if [ -z "$INTERNAL_REGISTRY" ]; then
        echo "ERROR: Failed to get internal registry route"
        exit 1
    fi
fi

echo "Using OpenShift internal registry: ${INTERNAL_REGISTRY}"

REGISTRY=${REGISTRY:-${INTERNAL_REGISTRY}}
CATALOG_NAMESPACE=${CATALOG_NAMESPACE:-openshift-marketplace}
OPERATOR_IMG="${REGISTRY}/${NAMESPACE}/automotive-dev-operator:latest"
CONSOLE_PLUGIN_IMG="${REGISTRY}/${NAMESPACE}/automotive-dev-console-plugin:latest"
BUNDLE_IMG="${REGISTRY}/${CATALOG_NAMESPACE}/automotive-dev-operator-bundle:v${VERSION}"
CATALOG_IMG="${REGISTRY}/${CATALOG_NAMESPACE}/automotive-dev-operator-catalog:v${VERSION}"
CONTAINER_TOOL=${CONTAINER_TOOL:-podman}

uninstall_operator() {
    echo "=========================================="
    echo "Uninstalling existing operator"
    echo "=========================================="

    echo "Removing finalizers from OperatorConfig CRs..."
    for oc_name in $(oc get operatorconfig -n ${NAMESPACE} -o name 2>/dev/null); do
        oc patch ${oc_name} -n ${NAMESPACE} --type=merge -p '{"metadata":{"finalizers":[]}}' 2>/dev/null || true
    done
    echo "Deleting OperatorConfig CRs..."
    oc delete operatorconfig --all -n ${NAMESPACE} --ignore-not-found=true --timeout=10s 2>/dev/null || true

    echo "Deleting subscription (if exists)..."
    oc delete subscriptions.operators.coreos.com automotive-dev-operator -n ${NAMESPACE} --ignore-not-found=true

    echo "Deleting CSVs (if exist)..."
    oc delete csv -n ${NAMESPACE} -l operators.coreos.com/automotive-dev-operator.${NAMESPACE}= --ignore-not-found=true 2>/dev/null || true
    # Also try by name pattern
    CSVS=$(oc get csv -n ${NAMESPACE} -o name 2>/dev/null | grep automotive-dev-operator || true)
    if [ -n "$CSVS" ]; then
        echo "$CSVS" | xargs -r oc delete -n ${NAMESPACE} --ignore-not-found=true
    fi

    echo "Deleting InstallPlans (if exist)..."
    oc delete installplan -n ${NAMESPACE} --all --ignore-not-found=true 2>/dev/null || true

    echo "Force-deleting all operator-managed resources..."
    # Delete ALL resources that might be left over
    oc delete deployment ado-webui ado-build-api ado-controller-manager automotive-dev-console-plugin -n ${NAMESPACE} --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
    oc delete service ado-webui ado-build-api automotive-dev-console-plugin -n ${NAMESPACE} --ignore-not-found=true 2>/dev/null || true
    oc delete route ado-webui ado-build-api -n ${NAMESPACE} --ignore-not-found=true 2>/dev/null || true
    oc delete serviceaccount ado-controller-manager ado-webui -n ${NAMESPACE} --ignore-not-found=true 2>/dev/null || true
    oc delete configmap ado-webui-nginx-config automotive-dev-console-plugin -n ${NAMESPACE} --ignore-not-found=true 2>/dev/null || true
    oc delete secret ado-oauth-secrets ado-webui-oauth-proxy ado-build-api-oauth-proxy automotive-dev-console-plugin-cert -n ${NAMESPACE} --ignore-not-found=true 2>/dev/null || true

    # Also delete any console plugin resources (cluster-scoped)
    echo "Deleting console plugin resources (cluster-scoped)..."
    oc delete consoleplugin automotive-dev-console-plugin --ignore-not-found=true 2>/dev/null || true

    echo "Waiting for all pods to terminate..."
    oc wait --for=delete pod -l control-plane=controller-manager -n ${NAMESPACE} --timeout=30s 2>/dev/null || true
    oc wait --for=delete pod -l app.kubernetes.io/part-of=automotive-dev-operator -n ${NAMESPACE} --timeout=30s 2>/dev/null || true

    echo "Force-deleting any stuck pods..."
    oc delete pods -l control-plane=controller-manager -n ${NAMESPACE} --force --grace-period=0 --ignore-not-found=true 2>/dev/null || true
    oc delete pods -l app.kubernetes.io/part-of=automotive-dev-operator -n ${NAMESPACE} --force --grace-period=0 --ignore-not-found=true 2>/dev/null || true

    echo "Deleting CatalogSource to force catalog refresh..."
    oc delete catalogsource automotive-dev-operator-catalog -n ${CATALOG_NAMESPACE} --ignore-not-found=true
    echo "Waiting for catalog pod to terminate..."
    oc wait --for=delete pod -l olm.catalogSource=automotive-dev-operator-catalog -n ${CATALOG_NAMESPACE} --timeout=60s 2>/dev/null || true

    echo "Operator uninstall complete."
    echo ""
}

clean_all() {
    echo "=========================================="
    echo "Thorough cleanup of all resources"
    echo "=========================================="

    # First do normal uninstall
    uninstall_operator

    echo "Cleaning up Tekton resources..."
    oc delete tasks,pipelines,pipelineruns -n ${NAMESPACE} -l automotive.sdv.cloud.redhat.com/managed-by --ignore-not-found=true 2>/dev/null || true

    echo "Cleaning up catalog resources..."
    oc delete catalogsource automotive-dev-operator-catalog -n ${CATALOG_NAMESPACE} --ignore-not-found=true 2>/dev/null || true

    echo "Removing operator images from registry..."
    oc delete imagestream automotive-dev-operator automotive-dev-console-plugin -n ${NAMESPACE} --ignore-not-found=true 2>/dev/null || true
    oc delete imagestream automotive-dev-operator-bundle automotive-dev-operator-catalog -n ${CATALOG_NAMESPACE} --ignore-not-found=true 2>/dev/null || true

    echo "Clean complete."
    echo ""
}

if [ "$COMMAND" = "uninstall" ]; then
    uninstall_operator
    exit 0
fi

if [ "$COMMAND" = "clean" ]; then
    clean_all
    exit 0
fi

if [ "$COMMAND" = "redeploy" ]; then
    uninstall_operator
fi

echo "=========================================="
echo "Building and Deploying Operator Catalog"
echo "=========================================="
echo "Version: ${VERSION}"
echo "Operator Namespace: ${NAMESPACE}"
echo "Catalog Namespace: ${CATALOG_NAMESPACE}"
echo "Registry: ${REGISTRY}"
echo "Operator Image: ${OPERATOR_IMG}"
echo "Console Plugin Image: ${CONSOLE_PLUGIN_IMG}"
echo "Bundle Image: ${BUNDLE_IMG}"
echo "Catalog Image: ${CATALOG_IMG}"
echo "=========================================="

echo ""
echo "Ensuring push permissions..."
oc policy add-role-to-user system:image-pusher $(oc whoami) -n ${NAMESPACE} 2>/dev/null || true
oc policy add-role-to-user system:image-pusher $(oc whoami) -n ${CATALOG_NAMESPACE} 2>/dev/null || true

echo ""
echo "Logging in to OpenShift registry..."
${CONTAINER_TOOL} login -u $(oc whoami) -p $(oc whoami -t) ${REGISTRY} --tls-verify=false

echo ""
echo "Ensuring namespace ${NAMESPACE} exists..."
oc create namespace ${NAMESPACE} --dry-run=client -o yaml | oc apply -f -

echo ""
echo "Detecting cluster architectures..."
CLUSTER_ARCHS=$(oc get nodes -o jsonpath='{.items[*].status.nodeInfo.architecture}' 2>/dev/null | tr ' ' '\n' | sort -u | tr '\n' ' ')
echo "Found architectures: ${CLUSTER_ARCHS}"

# Build multi-arch manifest if cluster has multiple architectures
ARCHS_ARRAY=(${CLUSTER_ARCHS})
if [ ${#ARCHS_ARRAY[@]} -gt 1 ]; then
    echo ""
    echo "Multi-arch cluster detected. Building for all architectures..."

    # Build and push each architecture
    for arch in ${CLUSTER_ARCHS}; do
        echo ""
        echo "Building for linux/${arch}..."
        ${CONTAINER_TOOL} buildx build -f Dockerfile --platform linux/${arch} --load -t ${OPERATOR_IMG}-${arch} .
        echo "Pushing ${OPERATOR_IMG}-${arch}..."
        ${CONTAINER_TOOL} push ${OPERATOR_IMG}-${arch} --tls-verify=false
    done

    echo ""
    echo "Creating multi-arch manifest..."
    # Remove any existing manifest or image with this name
    ${CONTAINER_TOOL} manifest rm ${OPERATOR_IMG} 2>/dev/null || true
    ${CONTAINER_TOOL} rmi ${OPERATOR_IMG} 2>/dev/null || true

    MANIFEST_ARGS=""
    for arch in ${CLUSTER_ARCHS}; do
        MANIFEST_ARGS="${MANIFEST_ARGS} ${OPERATOR_IMG}-${arch}"
    done
    ${CONTAINER_TOOL} manifest create ${OPERATOR_IMG} ${MANIFEST_ARGS}
    ${CONTAINER_TOOL} manifest push ${OPERATOR_IMG} --tls-verify=false
else
    BUILD_PLATFORM="linux/${ARCHS_ARRAY[0]}"
    echo "Single architecture cluster. Building for: ${BUILD_PLATFORM}"

    echo ""
    echo "Building operator image..."
    make docker-build IMG=${OPERATOR_IMG} BUILD_PLATFORM=${BUILD_PLATFORM}

    echo ""
    echo "Pushing operator image..."
    ${CONTAINER_TOOL} push ${OPERATOR_IMG} --tls-verify=false
fi

# Build and push console plugin image
if [ -d "webui" ] && [ -f "webui/package.json" ]; then
    echo ""
    echo "Building console plugin image..."
    make console-plugin-docker-build CONSOLE_PLUGIN_IMG=${CONSOLE_PLUGIN_IMG} BUILD_PLATFORM=${BUILD_PLATFORM:-linux/amd64}

    echo ""
    echo "Pushing console plugin image..."
    ${CONTAINER_TOOL} push ${CONSOLE_PLUGIN_IMG} --tls-verify=false
else
    echo ""
    echo "Skipping console plugin build (webui directory not found)"
fi

echo ""
echo "Generating bundle..."
make bundle IMG=${OPERATOR_IMG} VERSION=${VERSION}

echo ""
echo "Fixing images in bundle to use internal registry..."
# The bundle generator doesn't replace env var values or related images
# We need to manually update them to use the internal registry
OPERATOR_IMG_INTERNAL="image-registry.openshift-image-registry.svc:5000/${NAMESPACE}/automotive-dev-operator:latest"
CONSOLE_PLUGIN_IMG_INTERNAL="image-registry.openshift-image-registry.svc:5000/${NAMESPACE}/automotive-dev-console-plugin:latest"

# Add relatedImages section (bundle generator doesn't include this)
sed -i.bak '67a\
  relatedImages:\
  - name: manager\
    image: quay.io/rh-sdv-cloud/automotive-dev-operator:latest\
  - name: console-plugin\
    image: quay.io/rh-sdv-cloud/automotive-dev-console-plugin:latest\
' bundle/manifests/automotive-dev-operator.clusterserviceversion.yaml

# Fix environment variable values
sed -i.bak2 "s|value: controller:latest|value: ${OPERATOR_IMG_INTERNAL}|g" bundle/manifests/automotive-dev-operator.clusterserviceversion.yaml
sed -i.bak3 "s|value: quay.io/rh-sdv-cloud/automotive-dev-console-plugin:latest|value: ${CONSOLE_PLUGIN_IMG_INTERNAL}|g" bundle/manifests/automotive-dev-operator.clusterserviceversion.yaml

# Fix related images
sed -i.bak4 "s|image: quay.io/rh-sdv-cloud/automotive-dev-operator:latest|image: ${OPERATOR_IMG_INTERNAL}|g" bundle/manifests/automotive-dev-operator.clusterserviceversion.yaml
sed -i.bak5 "s|image: quay.io/rh-sdv-cloud/automotive-dev-console-plugin:latest|image: ${CONSOLE_PLUGIN_IMG_INTERNAL}|g" bundle/manifests/automotive-dev-operator.clusterserviceversion.yaml

rm -f bundle/manifests/automotive-dev-operator.clusterserviceversion.yaml.bak*

echo ""
echo "Building bundle image..."
make bundle-build BUNDLE_IMG=${BUNDLE_IMG}

echo ""
echo "Pushing bundle image to OpenShift registry..."
${CONTAINER_TOOL} push ${BUNDLE_IMG} --tls-verify=false

echo ""
echo "Ensuring opm is available..."
if [ ! -f "./bin/opm" ]; then
    echo "opm not found, downloading..."
    make opm
fi

echo ""
echo "Regenerating catalog..."
BUNDLE_IMG_INTERNAL="image-registry.openshift-image-registry.svc:5000/${CATALOG_NAMESPACE}/automotive-dev-operator-bundle:v${VERSION}"
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
# Update bundle image reference to internal registry (handles both empty and existing image refs)
sed -i.bak "s|^image:.*|image: ${BUNDLE_IMG_INTERNAL}|g" catalog/automotive-dev-operator.yaml
rm -f catalog/automotive-dev-operator.yaml.bak

echo ""
echo "Building catalog image..."
${CONTAINER_TOOL} build -f catalog.Dockerfile -t ${CATALOG_IMG} .

echo ""
echo "Pushing catalog image to OpenShift registry..."
${CONTAINER_TOOL} push ${CATALOG_IMG} --tls-verify=false

echo ""
echo "Updating CatalogSource manifest..."
CATALOG_IMG_INTERNAL="image-registry.openshift-image-registry.svc:5000/${CATALOG_NAMESPACE}/automotive-dev-operator-catalog:v${VERSION}"
sed -i.bak "s|image:.*|image: ${CATALOG_IMG_INTERNAL}|g" catalogsource.yaml
rm -f catalogsource.yaml.bak

echo ""
echo "Applying CatalogSource to OpenShift cluster..."
oc apply -f catalogsource.yaml -n ${CATALOG_NAMESPACE}

echo ""
echo "=========================================="
echo "Catalog Deployment Complete!"
echo "=========================================="
echo ""
echo "Your operator catalog has been deployed to OpenShift."
echo ""
echo "To view the catalog pods:"
echo "  oc get pods -n openshift-marketplace | grep automotive-dev-operator"
echo ""

if [ "$COMMAND" = "install" ] || [ "$COMMAND" = "redeploy" ]; then
    echo ""
    echo "=========================================="
    echo "Installing Operator"
    echo "=========================================="

    echo ""
    echo "Waiting for catalog pod to be ready..."
    for i in {1..60}; do
        CATALOG_POD=$(oc get pods -n ${CATALOG_NAMESPACE} -l olm.catalogSource=automotive-dev-operator-catalog -o name 2>/dev/null || echo "")
        if [ -n "$CATALOG_POD" ]; then
            oc wait --for=condition=Ready ${CATALOG_POD} -n ${CATALOG_NAMESPACE} --timeout=120s && break
        fi
        sleep 2
    done

    echo ""
    echo "Creating OperatorGroup..."
    oc apply -f config/samples/operatorgroup.yaml

    echo ""
    echo "Creating Subscription..."
    oc apply -f config/samples/subscription.yaml

    echo ""
    echo "Waiting for CSV to be installed..."
    for i in {1..60}; do
        CSV=$(oc get csv -n ${NAMESPACE} -o name 2>/dev/null | grep automotive-dev-operator || echo "")
        if [ -n "$CSV" ]; then
            PHASE=$(oc get ${CSV} -n ${NAMESPACE} -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
            echo "  CSV phase: ${PHASE}"
            if [ "$PHASE" = "Succeeded" ]; then
                break
            elif [ "$PHASE" = "Failed" ]; then
                echo "ERROR: CSV installation failed!"
                oc get ${CSV} -n ${NAMESPACE} -o jsonpath='{.status.message}'
                echo ""
                exit 1
            fi
        else
            echo "  Waiting for CSV to be created..."
        fi
        sleep 5
    done

    echo ""
    echo "Waiting for operator deployment to be available..."
    for i in {1..60}; do
        if oc get deployment ado-controller-manager -n ${NAMESPACE} &>/dev/null; then
            echo "  Deployment found, checking readiness..."
            if oc wait --for=condition=Available deployment/ado-controller-manager -n ${NAMESPACE} --timeout=30s 2>/dev/null; then
                echo "  Deployment is available!"
                break
            fi
        fi

        # Check pod status and show any issues
        echo "  Checking pod status (attempt $i/60)..."
        PODS=$(oc get pods -n ${NAMESPACE} --no-headers 2>/dev/null || echo "")
        if [ -n "$PODS" ]; then
            echo "$PODS" | while read line; do
                POD_NAME=$(echo "$line" | awk '{print $1}')
                POD_STATUS=$(echo "$line" | awk '{print $3}')

                if [[ "$POD_STATUS" == "CrashLoopBackOff" || "$POD_STATUS" == "Error" || "$POD_STATUS" == "Failed" ]]; then
                    echo "  ERROR: Pod $POD_NAME in $POD_STATUS state!"
                    echo "  Pod logs:"
                    oc logs "$POD_NAME" -n ${NAMESPACE} --tail=20 2>/dev/null || echo "    (no logs available)"
                    echo "  Pod events:"
                    oc get events --field-selector involvedObject.name="$POD_NAME" -n ${NAMESPACE} --sort-by='.lastTimestamp' --no-headers 2>/dev/null | tail -5 || echo "    (no events)"
                    echo ""
                elif [[ "$POD_STATUS" == "Pending" ]]; then
                    # Check why it's pending
                    REASON=$(oc get pod "$POD_NAME" -n ${NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="PodScheduled")].reason}' 2>/dev/null || echo "")
                    if [ -n "$REASON" ]; then
                        echo "  Pod $POD_NAME pending: $REASON"
                    fi
                fi
            done
        else
            echo "  No pods found yet..."
        fi

        sleep 5
    done

    echo ""
    echo "Force-updating CRDs to ensure schema is current..."
    echo "(OLM may skip CRD updates for same-version reinstalls)"
    for crd in bundle/manifests/automotive.sdv.cloud.redhat.com_*.yaml; do
        echo "  Applying $(basename $crd)..."
        oc apply -f "$crd"
    done

    echo ""
    echo "Creating sample OperatorConfig..."
    oc apply -f config/samples/automotive_v1_operatorconfig.yaml

    echo ""
    echo "=========================================="
    echo "Installation Complete!"
    echo "=========================================="
    echo ""
    echo "The operator is now installed and configured."
    echo ""
    echo "To check operator status:"
    echo "  oc get pods -n ${NAMESPACE}"
    echo ""
    echo "To check OperatorConfig:"
    echo "  oc get operatorconfig -n ${NAMESPACE}"
    echo ""
fi