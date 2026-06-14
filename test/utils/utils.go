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

// Package testutils provides common test utilities for e2e and integration tests.
package testutils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck // Dot import is standard for Ginkgo tests
)

const (
	openshiftInternalRegistryDefault = "image-registry.openshift-image-registry.svc:5000"
	buildToolPodman                  = "podman"
	buildToolDocker                  = "docker"
)

func getOpenshiftInternalRegistry() string {
	if v := strings.TrimSpace(os.Getenv("OPENSHIFT_INTERNAL_REGISTRY")); v != "" {
		return v
	}
	return openshiftInternalRegistryDefault
}

var namespaceFinalizerResources = []string{
	"operatorconfig",
	"taskruns",
	"pipelineruns",
	"persistentvolumeclaims",
}

// Run executes the provided command within this context.
// Not goroutine-safe due to os.Chdir; use RunSafe for concurrent execution.
// If cmd.Env is non-empty it is used as the base environment (callers must include
// PATH, HOME, etc.); GO111MODULE=on is always appended.
func Run(cmd *exec.Cmd) ([]byte, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %s\n", err)
	}

	if len(cmd.Env) == 0 {
		cmd.Env = append([]string{}, os.Environ()...)
	}
	cmd.Env = append(cmd.Env, "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %s\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s failed with error: (%v) %s", command, err, string(output))
	}

	return output, nil
}

// RunSafe executes the provided command using cmd.Dir only (no os.Chdir).
// Safe to call from multiple goroutines concurrently.
// If cmd.Env is non-empty it is used as the base environment (callers must include
// PATH, HOME, etc.); GO111MODULE=on is always appended.
func RunSafe(cmd *exec.Cmd) ([]byte, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if len(cmd.Env) == 0 {
		cmd.Env = append([]string{}, os.Environ()...)
	}
	cmd.Env = append(cmd.Env, "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %s\n", command)
	output, err := cmd.CombinedOutput()
	_, _ = fmt.Fprintf(GinkgoWriter, "finished: %s\n", command)
	if err != nil {
		return output, fmt.Errorf("%s failed with error: (%v) %s", command, err, string(output))
	}

	return output, nil
}

// IsOpenShiftCluster returns true when the target cluster is OpenShift.
// It checks the OPENSHIFT_CLUSTER env var first (set explicitly by run-e2e-local.sh),
// then falls back to probing the OpenShift config API.
func IsOpenShiftCluster() bool {
	v := strings.TrimSpace(os.Getenv("OPENSHIFT_CLUSTER"))
	if strings.EqualFold(v, "true") || v == "1" {
		return true
	}
	cmd := exec.Command("kubectl", "get", "--raw", "/apis/config.openshift.io/v1")
	_, err := Run(cmd)
	return err == nil
}

// GetBuildAPIURL returns the Build API URL when an OpenShift Route exists, or "" otherwise.
func GetBuildAPIURL(namespace string) string {
	cmd := exec.Command("kubectl", "get", "route", "ado-build-api",
		"-n", namespace, "-o", "jsonpath={.spec.host}")
	output, err := Run(cmd)
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return ""
	}
	return "https://" + strings.TrimSpace(string(output))
}

// CleanupNamespace removes the target namespace and repeatedly strips finalizers
// from common blocking resources until the namespace is fully deleted.
func CleanupNamespace(targetNamespace string) {
	cmd := exec.Command("kubectl", "delete", "ns", targetNamespace, "--ignore-not-found=true", "--timeout=60s")
	_, _ = Run(cmd)
	stripNamespaceFinalizers(targetNamespace)
	waitForNamespaceGone := func() error {
		cmd := exec.Command("kubectl", "get", "ns", targetNamespace, "--ignore-not-found")
		output, err := Run(cmd)
		if err != nil {
			return fmt.Errorf("check namespace %q deletion: %w", targetNamespace, err)
		}
		if strings.TrimSpace(string(output)) == "" {
			return nil // namespace is gone
		}
		stripNamespaceFinalizers(targetNamespace)
		return fmt.Errorf("namespace still exists or terminating")
	}
	Eventually(waitForNamespaceGone, 5*time.Minute, 5*time.Second).Should(Succeed())
}

// PatchTektonTaskStep fetches a Tekton Task, applies script replacements and optional
// field overrides on step[stepIndex], then runs kubectl replace.
func PatchTektonTaskStep(namespace, taskName string, stepIndex int, scriptReplacements map[string]string, stepFields map[string]any) error {
	raw, err := Run(exec.Command("kubectl", "get", "task", taskName, "-n", namespace, "-o", "json"))
	if err != nil {
		return err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("task %s: invalid json: %w", taskName, err)
	}
	step, err := getTektonTaskStep(obj, taskName, stepIndex)
	if err != nil {
		return err
	}
	script, ok := step["script"].(string)
	if !ok {
		return fmt.Errorf("task %s: step[%d] has no script field", taskName, stepIndex)
	}
	for old, repl := range scriptReplacements {
		script = strings.ReplaceAll(script, old, repl)
	}
	step["script"] = script
	for k, v := range stepFields {
		step[k] = v
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("task %s: marshal patched task: %w", taskName, err)
	}
	rep := exec.Command("kubectl", "replace", "-f", "-")
	rep.Stdin = bytes.NewReader(out)
	_, err = Run(rep)
	return err
}

func getTektonTaskStep(obj map[string]any, taskName string, stepIndex int) (map[string]any, error) {
	if obj == nil {
		return nil, fmt.Errorf("task %s: nil object", taskName)
	}
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("task %s: missing or invalid spec", taskName)
	}
	steps, ok := spec["steps"].([]any)
	if !ok || len(steps) == 0 {
		return nil, fmt.Errorf("task %s: missing or empty spec.steps", taskName)
	}
	if stepIndex < 0 || stepIndex >= len(steps) {
		return nil, fmt.Errorf("task %s: step %d out of range (%d steps)", taskName, stepIndex, len(steps))
	}
	step, ok := steps[stepIndex].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("task %s: step[%d] is not an object", taskName, stepIndex)
	}
	return step, nil
}

// NewCaibCommand builds a `bin/caib` command with the provided environment.
// Pass a non-nil context to enable cancellation/timeout control.
func NewCaibCommand(ctx context.Context, env []string, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if ctx != nil {
		cmd = exec.CommandContext(ctx, "bin/caib", args...)
	} else {
		cmd = exec.Command("bin/caib", args...)
	}
	cmd.Env = append([]string{}, env...)
	return cmd
}

// PrepareOperatorImage builds the operator image and makes it available to the target cluster.
func PrepareOperatorImage(projectImage, namespace string) string {
	By("building the manager(Operator) image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
	_, err := Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("making the manager(Operator) image available to the cluster")
	deployedImage, err := LoadImageToClusterWithName(projectImage, namespace)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return deployedImage
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster
func LoadImageToKindClusterWithName(name string) error {
	cluster := "kind"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := exec.Command("kind", kindOptions...)
	_, err := Run(cmd)
	return err
}

// LoadImageToClusterWithName makes a locally built image available to the target cluster.
// On Kind this uses `kind load`; on OpenShift it tags and pushes into the cluster registry.
func LoadImageToClusterWithName(name, namespace string) (string, error) {
	if IsOpenShiftCluster() {
		return pushImageToOpenShiftRegistry(name, namespace)
	}
	return name, LoadImageToKindClusterWithName(name)
}

func pushImageToOpenShiftRegistry(localImage, namespace string) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("namespace is required to push image %q to OpenShift", localImage)
	}

	routeHost, err := getOpenShiftRegistryRoute()
	if err != nil {
		return "", err
	}

	username, err := getCommandOutput("oc", "whoami")
	if err != nil {
		return "", fmt.Errorf("resolve OpenShift registry username: %w", err)
	}
	token, err := getCommandOutput("oc", "whoami", "-t")
	if err != nil {
		return "", fmt.Errorf("resolve OpenShift registry token: %w", err)
	}

	repo, tag := splitImageName(localImage)
	externalRef := fmt.Sprintf("%s/%s/%s%s", routeHost, namespace, repo, tag)
	internalRef := fmt.Sprintf("%s/%s/%s%s", getOpenshiftInternalRegistry(), namespace, repo, tag)
	tool := resolveContainerTool()

	loginArgs := []string{"login", "-u", username, "--password-stdin"}
	if tool == buildToolPodman {
		loginArgs = append(loginArgs, tlsVerifyArgs()...)
	}
	loginArgs = append(loginArgs, routeHost)
	loginCmd := exec.Command(tool, loginArgs...)
	loginCmd.Stdin = strings.NewReader(token)
	loginOutput, err := loginCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s login failed: %v: %s", tool, err, strings.TrimSpace(string(loginOutput)))
	}

	if _, err := Run(exec.Command(tool, "tag", localImage, externalRef)); err != nil {
		return "", fmt.Errorf("%s tag failed: %w", tool, err)
	}

	// Pre-create the ImageStream so the registry has a repository entry before
	// the push. Without this the OpenShift internal registry returns HTTP 500
	// when the namespace storage backend is not yet initialised.
	createImageStreamCmd := exec.Command("oc", "create", "imagestream", repo, "-n", namespace)
	createImageStreamOut, createImageStreamErr := Run(createImageStreamCmd)
	if createImageStreamErr != nil && !strings.Contains(string(createImageStreamOut), "AlreadyExists") {
		return "", fmt.Errorf("create OpenShift imagestream %q: %w", repo, createImageStreamErr)
	}

	pushArgs := []string{"push"}
	if tool == buildToolPodman {
		pushArgs = append(pushArgs, tlsVerifyArgs()...)
	}
	pushArgs = append(pushArgs, externalRef)

	if _, err := Run(exec.Command(tool, pushArgs...)); err != nil {
		return "", fmt.Errorf("%s push failed: %w", tool, err)
	}

	return internalRef, nil
}

func getOpenShiftRegistryRoute() (string, error) {
	routeHost, err := getCommandOutput("kubectl", "get", "route", "default-route",
		"-n", "openshift-image-registry", "-o", "jsonpath={.spec.host}")
	if err != nil {
		return "", fmt.Errorf("resolve OpenShift registry route: %w", err)
	}
	if routeHost == "" {
		return "", fmt.Errorf("OpenShift registry route is empty")
	}
	return routeHost, nil
}

func getCommandOutput(command string, args ...string) (string, error) {
	output, err := Run(exec.Command(command, args...))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func resolveContainerTool() string {
	if tool := strings.TrimSpace(os.Getenv("CONTAINER_TOOL")); tool != "" {
		return tool
	}
	if _, err := exec.LookPath(buildToolPodman); err == nil {
		return buildToolPodman
	}
	return buildToolDocker
}

func tlsVerifyArgs() []string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("REGISTRY_TLS_VERIFY")), "true") {
		return []string{"--tls-verify=true"}
	}
	return []string{"--tls-verify=false"}
}

func splitImageName(image string) (string, string) {
	lastSlash := strings.LastIndex(image, "/")
	name := image
	tag := ":latest"
	if lastAt := strings.LastIndex(image, "@"); lastAt >= 0 {
		tag = image[lastAt:]
		name = image[:lastAt]
	} else if lastColon := strings.LastIndex(image, ":"); lastColon > lastSlash {
		tag = image[lastColon:]
		name = image[:lastColon]
	}

	repo := name
	if lastSlash >= 0 {
		repo = name[lastSlash+1:]
	}

	return repo, tag
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}

func stripNamespaceFinalizers(targetNamespace string) {
	for _, resource := range namespaceFinalizerResources {
		output, err := Run(exec.Command("kubectl", "get", resource, "-n", targetNamespace, "-o", "name"))
		if err != nil {
			continue
		}
		for _, name := range GetNonEmptyLines(string(output)) {
			_, _ = Run(exec.Command(
				"kubectl", "patch", name,
				"-n", targetNamespace,
				"--type=merge",
				"-p", `{"metadata":{"finalizers":[]}}`,
			))
		}
	}
}

// GenerateRandomString returns a random hex string of the specified length.
func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive, got %d", length)
	}
	b := make([]byte, (length+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand read failed: %w", err)
	}
	return hex.EncodeToString(b)[:length], nil
}
