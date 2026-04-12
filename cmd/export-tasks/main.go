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

// Package main exports Tekton Task definitions as YAML files for Tekton Bundle packaging.
// Tasks are generated from the same Go code used by the operator, ensuring the bundle
// contains the exact same task definitions as cluster-installed ones.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"sigs.k8s.io/yaml"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

func main() {
	outputDir := flag.String("output-dir", "", "Directory to write task YAML files (writes to stdout if empty)")
	flag.Parse()

	// Use nil buildConfig for defaults — bundle tasks should not bake in
	// cluster-specific settings like memory volumes or custom timeouts.
	taskList := []*tektonv1.Task{
		tasks.GenerateBuildAutomotiveImageTask("", nil, ""),
		tasks.GeneratePushArtifactRegistryTask("", nil),
		tasks.GeneratePrepareBuilderTask("", nil),
		tasks.GenerateFlashTask("", nil),
	}
	taskList = append(taskList, tasks.GenerateSealedTasks("")...)

	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}

	for _, task := range taskList {
		// Strip namespace and runtime metadata — these are cluster concerns, not bundle content.
		task.Namespace = ""
		task.ManagedFields = nil
		task.ResourceVersion = ""
		task.UID = ""
		task.CreationTimestamp.Reset()

		data, err := yaml.Marshal(task)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error marshaling task %s: %v\n", task.Name, err)
			os.Exit(1)
		}

		if *outputDir == "" {
			fmt.Printf("---\n%s", data)
		} else {
			path := filepath.Join(*outputDir, task.Name+".yaml")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing %s: %v\n", path, err)
				os.Exit(1)
			}
			fmt.Printf("wrote %s\n", path)
		}
	}
}
