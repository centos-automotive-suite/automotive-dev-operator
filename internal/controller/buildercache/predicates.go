package buildercache

import (
	"slices"

	automotivev1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Progress and unrelated status writes do not change retention decisions.
func retentionEvents() predicate.Predicate {
	return predicate.Funcs{
		GenericFunc: func(event.GenericEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			switch next := e.ObjectNew.(type) {
			case *automotivev1.OperatorConfig:
				return e.ObjectOld.GetGeneration() != next.Generation
			case *automotivev1.ImageBuild:
				previous := e.ObjectOld.(*automotivev1.ImageBuild)
				return previous.Spec.GetBuilderImage() != next.Spec.GetBuilderImage() ||
					previous.Status.BuilderImageUsed != next.Status.BuilderImageUsed ||
					!previous.Status.CompletionTime.Equal(next.Status.CompletionTime) ||
					(previous.Status.Phase != next.Status.Phase &&
						(automotivev1.IsTerminalBuildPhase(previous.Status.Phase) || automotivev1.IsTerminalBuildPhase(next.Status.Phase)))
			case *automotivev1.ImageReseal:
				previous := e.ObjectOld.(*automotivev1.ImageReseal)
				return previous.Spec.BuilderImage != next.Spec.BuilderImage ||
					(previous.Status.Phase != next.Status.Phase &&
						(resealFinished(previous) || resealFinished(next)))
			case *automotivev1.CatalogImage:
				previous := e.ObjectOld.(*automotivev1.CatalogImage)
				oldResolved, oldRefs := catalogHelpers(previous.Status.RegistryMetadata)
				newResolved, newRefs := catalogHelpers(next.Status.RegistryMetadata)
				return previous.Spec.BuilderImage != next.Spec.BuilderImage ||
					previous.Status.SourceImageBuild != next.Status.SourceImageBuild ||
					oldResolved != newResolved || !slices.Equal(oldRefs, newRefs)
			default:
				return false
			}
		},
	}
}

func resealFinished(reseal *automotivev1.ImageReseal) bool {
	return reseal.Status.Phase == "Completed" || reseal.Status.Phase == "Failed"
}

func catalogHelpers(metadata *automotivev1.RegistryMetadata) (bool, []string) {
	if metadata == nil {
		return false, nil
	}
	return metadata.BuilderImageResolved, metadata.BuilderImages
}
