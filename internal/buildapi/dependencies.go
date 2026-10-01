package buildapi

import (
	"context"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type apiDependencies struct {
	getClientFromRequest         func(*gin.Context) (client.Client, error)
	getRESTConfigFromRequest     func(*gin.Context) (*rest.Config, error)
	createInternalRegistrySecret func(context.Context, *rest.Config, string, string, int64) (string, error)
	loadOperatorConfig           func(context.Context, client.Client, string) (*automotivev1alpha1.OperatorConfig, error)
	loadTargetDefaults           func(context.Context, client.Client, string) (map[string]buildcontract.TargetDefaults, error)
}

func defaultAPIDependencies() apiDependencies {
	return apiDependencies{
		getClientFromRequest:         getClientFromRequest,
		getRESTConfigFromRequest:     getRESTConfigFromRequest,
		createInternalRegistrySecret: createInternalRegistrySecret,
		loadOperatorConfig:           loadOperatorConfig,
		loadTargetDefaults:           loadTargetDefaults,
	}
}

func loadOperatorConfig(
	ctx context.Context,
	k8sClient client.Client,
	namespace string,
) (*automotivev1alpha1.OperatorConfig, error) {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      "config",
	}, operatorConfig); err != nil {
		return nil, err
	}
	return operatorConfig, nil
}

func loadTargetDefaults(
	ctx context.Context,
	k8sClient client.Client,
	namespace string,
) (map[string]buildcontract.TargetDefaults, error) {
	cm := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      "aib-target-defaults",
	}, cm); err != nil {
		return nil, err
	}

	data, ok := cm.Data["target-defaults.yaml"]
	if !ok {
		return nil, nil
	}

	var parsed struct {
		Targets map[string]struct {
			Architecture          string   `yaml:"architecture"`
			ExtraArgs             []string `yaml:"extraArgs"`
			DefaultFormat         string   `yaml:"defaultFormat"`
			AcceptedFormats       []string `yaml:"acceptedFormats"`
			AcceptedArchitectures []string `yaml:"acceptedArchitectures"`
		} `yaml:"targets"`
	}
	if err := yaml.Unmarshal([]byte(data), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse target-defaults.yaml: %w", err)
	}

	result := make(map[string]buildcontract.TargetDefaults, len(parsed.Targets))
	for name, t := range parsed.Targets {
		result[name] = buildcontract.TargetDefaults{
			Architecture:          t.Architecture,
			ExtraArgs:             t.ExtraArgs,
			DefaultFormat:         t.DefaultFormat,
			AcceptedFormats:       t.AcceptedFormats,
			AcceptedArchitectures: t.AcceptedArchitectures,
		}
	}

	if err := validateTargetDefaults(result); err != nil {
		return nil, fmt.Errorf("invalid target-defaults.yaml: %w", err)
	}

	return result, nil
}
