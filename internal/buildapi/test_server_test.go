package buildapi

import (
	"context"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type testReporter interface {
	Helper()
	Errorf(string, ...any)
}

func newTestServer(t testReporter, configure func(*apiDependencies)) *APIServer {
	t.Helper()
	unexpected := func(name string) error {
		t.Helper()
		err := fmt.Errorf("unexpected API dependency call: %s", name)
		t.Errorf("%v", err)
		return err
	}
	deps := apiDependencies{
		getClientFromRequest:     func(*gin.Context) (client.Client, error) { return nil, unexpected("getClientFromRequest") },
		getRESTConfigFromRequest: func(*gin.Context) (*rest.Config, error) { return nil, unexpected("getRESTConfigFromRequest") },
		createInternalRegistrySecret: func(context.Context, *rest.Config, string, string, int64) (string, error) {
			return "", unexpected("createInternalRegistrySecret")
		},
		loadOperatorConfig: func(context.Context, client.Client, string) (*automotivev1alpha1.OperatorConfig, error) {
			return nil, unexpected("loadOperatorConfig")
		},
		loadTargetDefaults: func(context.Context, client.Client, string) (map[string]buildcontract.TargetDefaults, error) {
			return nil, unexpected("loadTargetDefaults")
		},
	}
	if configure != nil {
		configure(&deps)
	}
	a := &APIServer{addr: ":0", log: logr.Discard(), limits: DefaultAPILimits(), deps: deps, exec: podExecutor{
		newExecutor: func(*rest.Config, string, string, string, []string) (remotecommand.Executor, error) {
			return nil, unexpected("newPodExecExecutor")
		},
	}}
	return a
}
