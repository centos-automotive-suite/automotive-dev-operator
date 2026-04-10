package tasks

import (
	"fmt"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SoftwareBuildPipelineName = "software-build-pipeline"
	defaultSoftwareBuildImage = "ubuntu:24.04"
	softwareBuildPVCSize      = "1Gi"
)

func softwareBuildStageTask(stageName, paramImage, paramCommand string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name: stageName,
		TaskSpec: &tektonv1.EmbeddedTask{
			TaskSpec: tektonv1.TaskSpec{
				Params: []tektonv1.ParamSpec{
					{Name: "image", Type: tektonv1.ParamTypeString},
					{Name: "command", Type: tektonv1.ParamTypeString},
				},
				Workspaces: []tektonv1.WorkspaceDeclaration{
					{Name: "ws", MountPath: "/workspace"},
				},
				Steps: []tektonv1.Step{
					{
						Name:  "run",
						Image: "$(params.image)",
						Script: `#!/usr/bin/env bash
set -euo pipefail
cd $(workspaces.ws.path)
bash -lc "$(params.command)"
`,
					},
				},
			},
		},
		Params: []tektonv1.Param{
			{Name: "image", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: paramImage}},
			{Name: "command", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: paramCommand}},
		},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "ws", Workspace: "shared-workspace"},
		},
	}
}

// GenerateSoftwareBuildPipeline creates the Tekton Pipeline that runs five
// sequential stages inside a user-chosen container image.
func GenerateSoftwareBuildPipeline(name, namespace string, _ *BuildConfig) *tektonv1.Pipeline {
	stages := []string{"fetch", "prebuild", "build", "postbuild", "deploy"}

	tasks := make([]tektonv1.PipelineTask, len(stages))
	for i, s := range stages {
		tasks[i] = softwareBuildStageTask(
			s,
			"$(params.containerImage)",
			fmt.Sprintf("$(params.%sCommand)", s),
		)
		if i > 0 {
			tasks[i].RunAfter = []string{stages[i-1]}
		}
	}

	return &tektonv1.Pipeline{
		TypeMeta: metav1.TypeMeta{APIVersion: "tekton.dev/v1", Kind: "Pipeline"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "automotive-dev-operator",
			},
		},
		Spec: tektonv1.PipelineSpec{
			Params: []tektonv1.ParamSpec{
				{
					Name: "containerImage", Type: tektonv1.ParamTypeString,
					Default:     &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: defaultSoftwareBuildImage},
					Description: "Container image providing the build toolchain",
				},
				{Name: "fetchCommand", Type: tektonv1.ParamTypeString, Description: "Fetch stage command"},
				{Name: "prebuildCommand", Type: tektonv1.ParamTypeString, Description: "Prebuild stage command"},
				{Name: "buildCommand", Type: tektonv1.ParamTypeString, Description: "Build stage command"},
				{Name: "postbuildCommand", Type: tektonv1.ParamTypeString, Description: "Postbuild stage command"},
				{Name: "deployCommand", Type: tektonv1.ParamTypeString, Description: "Deploy stage command"},
			},
			Workspaces: []tektonv1.PipelineWorkspaceDeclaration{
				{Name: "shared-workspace"},
			},
			Tasks: tasks,
		},
	}
}

// GenerateSoftwareBuildPipelineRun creates a PipelineRun for the given
// SoftwareBuild CR, referencing the software-build-pipeline.
func GenerateSoftwareBuildPipelineRun(sb *automotivev1alpha1.SoftwareBuild, config *BuildConfig) *tektonv1.PipelineRun {
	image := sb.Spec.Runtime.Image
	if image == "" {
		image = defaultSoftwareBuildImage
	}

	pvcSize := softwareBuildPVCSize
	if config != nil && config.PVCSize != "" {
		pvcSize = config.PVCSize
	}

	prName := fmt.Sprintf("%s-%d", sb.Name, time.Now().Unix())

	return &tektonv1.PipelineRun{
		TypeMeta: metav1.TypeMeta{APIVersion: "tekton.dev/v1", Kind: "PipelineRun"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      prName,
			Namespace: sb.Namespace,
			Labels: map[string]string{
				"automotive.sdv.cloud.redhat.com/softwarebuild": sb.Name,
				"app.kubernetes.io/managed-by":                  "automotive-dev-operator",
			},
		},
		Spec: tektonv1.PipelineRunSpec{
			PipelineRef: &tektonv1.PipelineRef{Name: SoftwareBuildPipelineName},
			Params: []tektonv1.Param{
				{Name: "containerImage", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: image}},
				{Name: "fetchCommand", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sb.Spec.Stages.Fetch.Command}},
				{Name: "prebuildCommand", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sb.Spec.Stages.Prebuild.Command}},
				{Name: "buildCommand", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sb.Spec.Stages.Build.Command}},
				{Name: "postbuildCommand", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sb.Spec.Stages.Postbuild.Command}},
				{Name: "deployCommand", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sb.Spec.Stages.Deploy.Command}},
			},
			Workspaces: []tektonv1.WorkspaceBinding{
				{
					Name: "shared-workspace",
					VolumeClaimTemplate: &corev1.PersistentVolumeClaim{
						Spec: corev1.PersistentVolumeClaimSpec{
							AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
							Resources: corev1.VolumeResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceStorage: resource.MustParse(pvcSize),
								},
							},
						},
					},
				},
			},
		},
	}
}
