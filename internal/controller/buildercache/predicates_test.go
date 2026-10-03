package buildercache

import (
	"testing"
	"time"

	automotivev1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestRetentionEvents(t *testing.T) {
	build := &automotivev1.ImageBuild{}
	reseal := &automotivev1.ImageReseal{}
	entry := &automotivev1.CatalogImage{}
	config := &automotivev1.OperatorConfig{}
	for _, tc := range []struct {
		name   string
		object client.Object
		change func(client.Object)
		want   bool
	}{
		{"build progress", build, func(o client.Object) { o.(*automotivev1.ImageBuild).Status.Message = "downloading" }, false},
		{"build nonterminal phase", build, func(o client.Object) {
			o.(*automotivev1.ImageBuild).Status.Phase = automotivev1.ImageBuildPhaseBuilding
		}, false},
		{"build terminal phase", build, func(o client.Object) {
			o.(*automotivev1.ImageBuild).Status.Phase = automotivev1.ImageBuildPhaseCompleted
		}, true},
		{"build result helper", build, func(o client.Object) { o.(*automotivev1.ImageBuild).Status.BuilderImageUsed = builderRef("a") }, true},
		{"build completion time", build, func(o client.Object) {
			o.(*automotivev1.ImageBuild).Status.CompletionTime = &metav1.Time{Time: testNow}
		}, true},
		{"build helper override", build, func(o client.Object) {
			o.(*automotivev1.ImageBuild).Spec.AIB = &automotivev1.AIBSpec{BuilderImage: builderRef("a")}
		}, true},
		{"reseal progress", reseal, func(o client.Object) { o.(*automotivev1.ImageReseal).Status.Message = "working" }, false},
		{"reseal nonterminal phase", reseal, func(o client.Object) { o.(*automotivev1.ImageReseal).Status.Phase = "Running" }, false},
		{"reseal terminal phase", reseal, func(o client.Object) { o.(*automotivev1.ImageReseal).Status.Phase = "Failed" }, true},
		{"reseal helper override", reseal, func(o client.Object) { o.(*automotivev1.ImageReseal).Spec.BuilderImage = builderRef("b") }, true},
		{"catalog access count", entry, func(o client.Object) { o.(*automotivev1.CatalogImage).Status.AccessCount++ }, false},
		{"catalog verification", entry, func(o client.Object) {
			o.(*automotivev1.CatalogImage).Status.LastVerificationTime = &metav1.Time{Time: testNow}
		}, false},
		{"catalog empty metadata", entry, func(o client.Object) {
			o.(*automotivev1.CatalogImage).Status.RegistryMetadata = &automotivev1.RegistryMetadata{SizeBytes: 123}
		}, false},
		{"catalog resolved helper", entry, func(o client.Object) {
			o.(*automotivev1.CatalogImage).Status.RegistryMetadata = &automotivev1.RegistryMetadata{BuilderImageResolved: true}
		}, true},
		{"catalog registry references", entry, func(o client.Object) {
			o.(*automotivev1.CatalogImage).Status.RegistryMetadata = &automotivev1.RegistryMetadata{BuilderImages: []string{builderRef("a")}}
		}, true},
		{"catalog source", entry, func(o client.Object) { o.(*automotivev1.CatalogImage).Status.SourceImageBuild = "source" }, true},
		{"catalog retained helper", entry, func(o client.Object) { o.(*automotivev1.CatalogImage).Spec.BuilderImage = builderRef("a") }, true},
		{"config status", config, func(o client.Object) { o.(*automotivev1.OperatorConfig).Status.Message = "ready" }, false},
		{"config spec", config, func(o client.Object) { o.SetGeneration(o.GetGeneration() + 1) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := tc.object.DeepCopyObject().(client.Object)
			tc.change(next)
			filter := retentionEvents()
			if got := filter.Update(event.UpdateEvent{ObjectOld: tc.object, ObjectNew: next}); got != tc.want {
				t.Fatalf("update accepted = %v, want %v", got, tc.want)
			}
			if got := filter.Update(event.UpdateEvent{ObjectOld: next, ObjectNew: tc.object}); got != tc.want {
				t.Fatalf("reverse update accepted = %v, want %v", got, tc.want)
			}
			if !filter.Create(event.CreateEvent{Object: next}) || !filter.Delete(event.DeleteEvent{Object: next}) || filter.Generic(event.GenericEvent{Object: next}) {
				t.Fatal("incorrect create/delete/generic filtering")
			}
		})
	}
}

func TestCompletionTimestampChange(t *testing.T) {
	previous := build("source", builderRef("a"), testNow)
	next := previous.DeepCopy()
	next.Status.CompletionTime = &metav1.Time{Time: testNow.Add(time.Hour)}
	if !retentionEvents().Update(event.UpdateEvent{ObjectOld: previous, ObjectNew: next}) {
		t.Fatal("ignored updated last-use timestamp")
	}
}
