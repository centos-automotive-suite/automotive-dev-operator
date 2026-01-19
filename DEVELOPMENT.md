# Running build server locally

Run server locally from source against an existing cluster:
```console
go run ./cmd/build-api/ --kubeconfig-path ~/.kube/config
```

Make requests
```console
export BEARER=$(oc whoami -it)
curl -H "Authorization: Bearer $BEARER" http://localhost:8080/v1/builds
```

# Editing Managed Tekton Resources

The operator manages Tekton Tasks and Pipelines deployed via OperatorConfig. By default, any manual edits to these resources will be overwritten on the next reconciliation.

To temporarily disable operator management of a specific Task or Pipeline (e.g., for testing changes), add the `unmanaged` annotation:

```bash
# Mark a task as unmanaged (operator will skip updates)
kubectl annotate task build-automotive-image \
  automotive.sdv.cloud.redhat.com/unmanaged=true \
  -n automotive-dev-operator-system

# Edit the task freely
kubectl edit task build-automotive-image -n automotive-dev-operator-system

# When done, remove the annotation to resume operator management
kubectl annotate task build-automotive-image \
  automotive.sdv.cloud.redhat.com/unmanaged- \
  -n automotive-dev-operator-system
```

This works for both Tasks and Pipelines. The operator logs will show "Skipping update for unmanaged task/pipeline" when it respects the annotation.
