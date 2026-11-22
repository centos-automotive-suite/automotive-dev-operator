package buildapi

// The build API acts as its own ServiceAccount, never as the requesting user,
// so these markers are everything it may do. `make manifests` generates
// config/rbac/build-api/role.yaml from them.
//
// Requesters authenticate through TokenReview.
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
//
// Registry tokens for builds and users.
// +kubebuilder:rbac:groups="",namespace=system,resources=serviceaccounts/token,resourceNames=ado-registry;ado-registry-pull,verbs=create
//
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=operatorconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagebuilds,verbs=get;list;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=containerbuilds,verbs=get;list;create
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagereseals,verbs=get;list;create;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=workspaces,verbs=get;list;create;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=workspaces/status,verbs=patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=catalogimages,verbs=get;list;create;update;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=catalogimages/status,verbs=update
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=webhookdeliveries,verbs=get
//
// Owner references that block their owner's deletion need update on the
// owner's finalizers (OwnerReferencesPermissionEnforcement on OpenShift).
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagebuilds/finalizers;containerbuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,namespace=system,resources=taskruns/finalizers,verbs=update
//
// Cancelling builds, and flash TaskRuns.
// +kubebuilder:rbac:groups=tekton.dev,namespace=system,resources=pipelineruns,verbs=get;update
// +kubebuilder:rbac:groups=tekton.dev,namespace=system,resources=taskruns,verbs=get;list;create;delete
//
// Build Secrets, and the JWT CA Secrets and ConfigMaps, which it polls by
// name. It never lists or watches them: that would read every one in the
// namespace. A CA kept in another namespace needs get granted there by hand.
// +kubebuilder:rbac:groups="",namespace=system,resources=secrets,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=configmaps,verbs=get
//
// Build logs and progress, and container build context uploads.
// +kubebuilder:rbac:groups="",namespace=system,resources=pods,verbs=get;list
// +kubebuilder:rbac:groups="",namespace=system,resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",namespace=system,resources=pods/exec,verbs=create
//
// Workspace build caches.
// +kubebuilder:rbac:groups="",namespace=system,resources=persistentvolumeclaims,verbs=get;list;create
//
// Internal registry streams.
// +kubebuilder:rbac:groups=image.openshift.io,namespace=system,resources=imagestreams,verbs=get;create;delete
// +kubebuilder:rbac:groups=image.openshift.io,namespace=system,resources=imagestreamtags,verbs=delete
//
// The registry's external route, in openshift-image-registry, when
// OperatorConfig does not name one.
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,resourceNames=default-route,verbs=get
