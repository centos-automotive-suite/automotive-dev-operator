package tasks

import (
	"fmt"
	"regexp"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	SoftwareBuildPipelineName = "software-build-pipeline"
	defaultSoftwareBuildImage = "ubuntu:24.04"
	softwareBuildPVCSize      = "1Gi"
)

var safeGitRefRe = regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)

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
						Name:            "run",
						Image:           "$(params.image)",
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
						},
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
func GenerateSoftwareBuildPipeline(name, namespace string, config *BuildConfig) *tektonv1.Pipeline {
	stages := []string{"fetch", "prebuild", "build", "postbuild", "deploy"}

	defaultImage := defaultSoftwareBuildImage
	if config != nil && config.DefaultImage != "" {
		defaultImage = config.DefaultImage
	}

	tasks := make([]tektonv1.PipelineTask, len(stages))
	for i, s := range stages {
		tasks[i] = softwareBuildStageTask(
			s,
			fmt.Sprintf("$(params.%sImage)", s),
			fmt.Sprintf("$(params.%sCommand)", s),
		)
		if i > 0 {
			tasks[i].RunAfter = []string{stages[i-1]}
		}
	}

	params := []tektonv1.ParamSpec{
		{
			Name: "containerImage", Type: tektonv1.ParamTypeString,
			Default:     &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: defaultImage},
			Description: "Container image providing the build toolchain",
		},
	}
	for _, s := range stages {
		params = append(params,
			tektonv1.ParamSpec{
				Name:        fmt.Sprintf("%sImage", s),
				Type:        tektonv1.ParamTypeString,
				Default:     &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(params.containerImage)"},
				Description: fmt.Sprintf("Image for %s stage (defaults to containerImage)", s),
			},
			tektonv1.ParamSpec{
				Name:        fmt.Sprintf("%sCommand", s),
				Type:        tektonv1.ParamTypeString,
				Description: fmt.Sprintf("%s stage command", s),
			},
		)
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
			Params:     params,
			Workspaces: []tektonv1.PipelineWorkspaceDeclaration{{Name: "shared-workspace"}},
			Tasks:      tasks,
		},
	}
}

// GenerateSoftwareBuildPipelineRun creates a PipelineRun for the given
// SoftwareBuild CR, referencing the software-build-pipeline.
func GenerateSoftwareBuildPipelineRun(sb *automotivev1alpha1.SoftwareBuild, config *BuildConfig) *tektonv1.PipelineRun {
	image := sb.Spec.Runtime.Image
	if image == "" {
		if config != nil && config.DefaultImage != "" {
			image = config.DefaultImage
		} else {
			image = defaultSoftwareBuildImage
		}
	}

	pvcSize := parsePVCSize(config)

	fetchCommand := sb.Spec.Stages.Fetch.Command
	if sb.Spec.Source.Type == automotivev1alpha1.SoftwareBuildSourceGit && sb.Spec.Source.Git != nil {
		revision := sb.Spec.Source.Git.Revision
		if revision == "" {
			revision = "main"
		}
		if !safeGitRefRe.MatchString(revision) {
			revision = "main"
		}
		gitClone := fmt.Sprintf("git clone --branch '%s' --single-branch '%s' src\n", revision, sb.Spec.Source.Git.URL)
		fetchCommand = gitClone + fetchCommand
	}

	prName := fmt.Sprintf("%s-gen%d", sb.Name, sb.Generation)

	pr := &tektonv1.PipelineRun{
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
			Params:      buildPipelineRunParams(sb, image),
			Workspaces:  buildWorkspaceBinding(sb, pvcSize),
		},
	}

	if sb.Spec.Runtime.ServiceAccountName != "" {
		pr.Spec.TaskRunTemplate = tektonv1.PipelineTaskRunTemplate{
			ServiceAccountName: sb.Spec.Runtime.ServiceAccountName,
		}
	}

	pr.Spec.Timeouts = buildTimeouts(sb, config)

	return pr
}

func buildPipelineRunParams(sb *automotivev1alpha1.SoftwareBuild, globalImage string) []tektonv1.Param {
	fetchCommand := sb.Spec.Stages.Fetch.Command
	if sb.Spec.Source.Type == automotivev1alpha1.SoftwareBuildSourceGit && sb.Spec.Source.Git != nil {
		revision := sb.Spec.Source.Git.Revision
		if revision == "" {
			revision = "main"
		}
		if !safeGitRefRe.MatchString(revision) {
			revision = "main"
		}
		gitClone := fmt.Sprintf("git clone --branch '%s' --single-branch '%s' src\n", revision, sb.Spec.Source.Git.URL)
		fetchCommand = gitClone + fetchCommand
	}

	type stageInfo struct {
		name    string
		command string
		image   string
	}
	stages := []stageInfo{
		{"fetch", fetchCommand, sb.Spec.Stages.Fetch.Image},
		{"prebuild", sb.Spec.Stages.Prebuild.Command, sb.Spec.Stages.Prebuild.Image},
		{"build", sb.Spec.Stages.Build.Command, sb.Spec.Stages.Build.Image},
		{"postbuild", sb.Spec.Stages.Postbuild.Command, sb.Spec.Stages.Postbuild.Image},
		{"deploy", sb.Spec.Stages.Deploy.Command, sb.Spec.Stages.Deploy.Image},
	}

	params := []tektonv1.Param{
		{Name: "containerImage", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: globalImage}},
	}
	for _, s := range stages {
		stageImage := "$(params.containerImage)"
		if s.image != "" {
			stageImage = s.image
		}
		params = append(params,
			tektonv1.Param{Name: fmt.Sprintf("%sImage", s.name), Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: stageImage}},
			tektonv1.Param{Name: fmt.Sprintf("%sCommand", s.name), Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: s.command}},
		)
	}
	return params
}

func buildTimeouts(sb *automotivev1alpha1.SoftwareBuild, config *BuildConfig) *tektonv1.TimeoutFields {
	var d time.Duration
	if sb.Spec.TimeoutSeconds > 0 {
		d = time.Duration(sb.Spec.TimeoutSeconds) * time.Second
	} else if config != nil && config.BuildTimeoutMinutes > 0 {
		d = time.Duration(config.BuildTimeoutMinutes) * time.Minute
	}
	if d > 0 {
		return &tektonv1.TimeoutFields{
			Pipeline: &metav1.Duration{Duration: d},
		}
	}
	return nil
}

func parsePVCSize(config *BuildConfig) string {
	if config != nil && config.PVCSize != "" {
		if _, err := resource.ParseQuantity(config.PVCSize); err == nil {
			return config.PVCSize
		}
	}
	return softwareBuildPVCSize
}

func buildWorkspaceBinding(sb *automotivev1alpha1.SoftwareBuild, pvcSize string) []tektonv1.WorkspaceBinding {
	if sb.Spec.Source.Type == automotivev1alpha1.SoftwareBuildSourcePVC && sb.Spec.Source.PVC != nil {
		return []tektonv1.WorkspaceBinding{
			{
				Name: "shared-workspace",
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: sb.Spec.Source.PVC.ClaimName,
				},
			},
		}
	}
	return []tektonv1.WorkspaceBinding{
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
	}
}
