package buildapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestAPIServerDependenciesAreIsolated(t *testing.T) {
	for _, name := range []string{"first", "second"} {
		server := newTestServer(t, func(deps *apiDependencies) {
			deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return nil, nil }
			deps.loadOperatorConfig = func(context.Context, client.Client, string) (*automotivev1alpha1.OperatorConfig, error) {
				return &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{Images: &automotivev1alpha1.ImagesConfig{AutomotiveImageBuilder: name}}}, nil
			}
			deps.loadTargetDefaults = func(context.Context, client.Client, string) (map[string]buildcontract.TargetDefaults, error) {
				return map[string]buildcontract.TargetDefaults{name: {Architecture: "arm64"}}, nil
			}
		})
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for range 10 {
				response := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(response)
				ctx.Request = httptest.NewRequest(http.MethodGet, "/v1/config", nil)
				server.handleGetOperatorConfig(ctx)
				var config buildcontract.OperatorConfigResponse
				if response.Code != http.StatusOK {
					t.Fatalf("config response: %d %s", response.Code, response.Body)
				}
				if err := json.Unmarshal(response.Body.Bytes(), &config); err != nil {
					t.Fatal(err)
				}
				if config.AutomotiveImageBuilder != name || len(config.TargetDefaults) != 1 || config.TargetDefaults[name].Architecture != "arm64" {
					t.Fatalf("server %s used another instance's dependencies: %+v", name, config)
				}
			}
		})
	}
}
