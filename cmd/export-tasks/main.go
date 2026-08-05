/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package main exports Tekton Task and Pipeline definitions as YAML files for Tekton Bundle packaging.
// Resources are generated from the same Go code used by the operator, ensuring the bundle
// contains the exact same definitions as cluster-installed ones.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

func main() {
	outputDir := flag.String("output-dir", "", "Directory to write task YAML files (writes to stdout if empty)")
	flag.Parse()

	// Use nil buildConfig for defaults — bundle resources should not bake in
	// cluster-specific settings like memory volumes or custom timeouts.
	taskList := []*tektonv1.Task{
		tasks.GenerateBuildAutomotiveImageTask("", nil, ""),
		tasks.GeneratePushArtifactRegistryTask("", nil),
		tasks.GeneratePushArtifactS3Task("", nil),
		tasks.GeneratePrepareBuilderTask("", nil),
		tasks.GenerateFlashTask("", nil),
	}
	taskList = append(taskList, tasks.GenerateSealedTasks("")...)

	pipeline := tasks.GenerateTektonPipeline("automotive-build-pipeline", "", &tasks.BuildConfig{
		TaskResolver:  tasks.TaskResolverBundle,
		TaskBundleRef: "$(params.task-bundle-ref)",
	})

	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}

	type namedResource struct {
		name string
		obj  interface{}
	}

	stripMetadata := func(obj metav1.Object) {
		obj.SetNamespace("")
		obj.SetManagedFields(nil)
		obj.SetResourceVersion("")
		obj.SetUID("")
		obj.SetCreationTimestamp(metav1.Time{})
	}

	resources := make([]namedResource, 0, len(taskList)+1)
	for _, task := range taskList {
		stripMetadata(task)
		resources = append(resources, namedResource{task.Name, task})
	}

	stripMetadata(pipeline)
	resources = append(resources, namedResource{pipeline.Name, pipeline})

	for _, res := range resources {
		data, err := yaml.Marshal(res.obj)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error marshaling %s: %v\n", res.name, err)
			os.Exit(1)
		}

		if *outputDir == "" {
			fmt.Printf("---\n%s", data)
		} else {
			path := filepath.Join(*outputDir, res.name+".yaml")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing %s: %v\n", path, err)
				os.Exit(1)
			}
			fmt.Printf("wrote %s\n", path)
		}
	}
}
