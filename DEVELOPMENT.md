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
