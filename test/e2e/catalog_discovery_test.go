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

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

// Catalog discovery e2e tests: sort, latest, schedule name display, detail view.

var _ = Describe("Catalog Discovery", Label("catalog"), Ordered, func() {
	const (
		catalogPrefix = "catdisc"
	)

	BeforeAll(func() {
		ensureOperatorDeployed()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
	})

	cleanupCatalogImage := func(name string) {
		cmd := exec.Command("kubectl", "delete", "catalogimage", name,
			"-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	}

	applyCatalogImage := func(name string, labels map[string]string, tags []string, registryURL string) {
		labelYAML := ""
		if len(labels) > 0 {
			labelYAML = "  labels:\n"
			for k, v := range labels {
				labelYAML += fmt.Sprintf("    %s: %q\n", k, v)
			}
		}

		tagsYAML := ""
		if len(tags) > 0 {
			tagsYAML = "  tags:\n"
			for _, t := range tags {
				tagsYAML += fmt.Sprintf("    - %s\n", t)
			}
		}

		cr := fmt.Sprintf(`apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: CatalogImage
metadata:
  name: %s
  namespace: %s
%s
spec:
  registryUrl: %q
%s  metadata:
    architecture: x86_64
    distro: autosd
    targets:
      - name: qemu
        verified: true
`, name, testNamespace, labelYAML, registryURL, tagsYAML)

		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(cr)
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to apply CatalogImage %s", name)
	}

	waitForCatalogPhase := func(name, phase string) {
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "catalogimage", name,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			got := strings.TrimSpace(string(output))
			if got != phase {
				return fmt.Errorf("CatalogImage %s phase is %q, want %q", name, got, phase)
			}
			return nil
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	}

	Context("Sort and Latest", func() {
		olderName := catalogPrefix + "-older"
		newerName := catalogPrefix + "-newer"

		BeforeAll(func() {
			applyCatalogImage(olderName, map[string]string{
				"automotive.sdv.cloud.redhat.com/scheduledimagebuild-name": "nightly-qemu",
				"automotive.sdv.cloud.redhat.com/source-type":              "Scheduled",
				"automotive.sdv.cloud.redhat.com/architecture":             "x86_64",
				"automotive.sdv.cloud.redhat.com/distro":                   "autosd",
				"automotive.sdv.cloud.redhat.com/target":                   "qemu",
			}, []string{"nightly"}, "registry.access.redhat.com/ubi9/ubi-micro:9.4")

			// Small delay so CreationTimestamps differ
			time.Sleep(2 * time.Second)

			applyCatalogImage(newerName, map[string]string{
				"automotive.sdv.cloud.redhat.com/scheduledimagebuild-name": "nightly-qemu",
				"automotive.sdv.cloud.redhat.com/source-type":              "Scheduled",
				"automotive.sdv.cloud.redhat.com/architecture":             "x86_64",
				"automotive.sdv.cloud.redhat.com/distro":                   "autosd",
				"automotive.sdv.cloud.redhat.com/target":                   "qemu",
			}, []string{"nightly"}, "registry.access.redhat.com/ubi9/ubi-micro:latest")

			DeferCleanup(func() {
				cleanupCatalogImage(olderName)
				cleanupCatalogImage(newerName)
			})

			waitForCatalogPhase(olderName, "Available")
			waitForCatalogPhase(newerName, "Available")
		})

		It("should sort by created date (newest first) by default", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "list",
				"--tags", "nightly",
				"--output-format", "json",
			)
			Expect(err).NotTo(HaveOccurred(), "caib catalog list failed: %s", string(output))

			var result struct {
				Items []struct {
					Name      string `json:"name"`
					CreatedAt string `json:"createdAt"`
				} `json:"items"`
			}
			Expect(json.Unmarshal(output, &result)).To(Succeed())
			Expect(result.Items).To(HaveLen(2))
			Expect(result.Items[0].Name).To(Equal(newerName),
				"expected newest item first, got %s", result.Items[0].Name)
		})

		It("should show only latest per schedule with --latest", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "list",
				"--tags", "nightly",
				"--latest",
				"--output-format", "json",
			)
			Expect(err).NotTo(HaveOccurred(), "caib catalog list --latest failed: %s", string(output))

			var result struct {
				Items []struct {
					Name string `json:"name"`
				} `json:"items"`
			}
			Expect(json.Unmarshal(output, &result)).To(Succeed())
			Expect(result.Items).To(HaveLen(1), "expected 1 item (latest per schedule)")
			Expect(result.Items[0].Name).To(Equal(newerName))
		})

		It("should display schedule name in SCHEDULE column in table output", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "list",
				"--tags", "nightly",
				"--latest",
			)
			Expect(err).NotTo(HaveOccurred(), "caib catalog list table failed: %s", string(output))

			lines := strings.Split(string(output), "\n")
			Expect(lines[0]).To(ContainSubstring("SCHEDULE"),
				"expected SCHEDULE column header, got: %s", lines[0])
			foundScheduleName := false
			for _, line := range lines[1:] {
				if strings.Contains(line, "nightly-qemu") {
					foundScheduleName = true
					break
				}
			}
			Expect(foundScheduleName).To(BeTrue(),
				"expected schedule name 'nightly-qemu' in table output, got:\n%s", string(output))
		})

		It("should show AGE column instead of raw timestamp in table", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "list",
				"--tags", "nightly",
				"--latest",
			)
			Expect(err).NotTo(HaveOccurred())

			lines := strings.Split(string(output), "\n")
			Expect(lines[0]).To(ContainSubstring("AGE"),
				"expected AGE column header, got: %s", lines[0])
			Expect(lines[0]).NotTo(ContainSubstring("CREATED"),
				"should not have CREATED column header")
		})

		It("should hide TAGS column when --tags filter is active", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "list",
				"--tags", "nightly",
			)
			Expect(err).NotTo(HaveOccurred())

			header := strings.Split(string(output), "\n")[0]
			Expect(header).NotTo(ContainSubstring("TAGS"),
				"TAGS column should be hidden when filtering by tags")
		})

		It("should show TAGS column when no --tags filter", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "list",
				"--distro", "autosd",
			)
			Expect(err).NotTo(HaveOccurred())

			header := strings.Split(string(output), "\n")[0]
			Expect(header).To(ContainSubstring("TAGS"),
				"TAGS column should be visible without --tags filter")
		})
	})

	Context("Catalog Get Detail View", func() {
		detailName := catalogPrefix + "-detail"

		BeforeAll(func() {
			applyCatalogImage(detailName, map[string]string{
				"automotive.sdv.cloud.redhat.com/scheduledimagebuild-name": "nightly-detail",
				"automotive.sdv.cloud.redhat.com/source-type":              "Scheduled",
				"automotive.sdv.cloud.redhat.com/architecture":             "x86_64",
				"automotive.sdv.cloud.redhat.com/distro":                   "autosd",
				"automotive.sdv.cloud.redhat.com/target":                   "qemu",
			}, []string{"nightly", "qa"}, "registry.access.redhat.com/ubi9/ubi-micro:latest")

			DeferCleanup(func() {
				cleanupCatalogImage(detailName)
			})

			waitForCatalogPhase(detailName, "Available")
		})

		It("should include schedule name and tags in JSON detail", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "get", detailName,
				"--output-format", "json",
			)
			Expect(err).NotTo(HaveOccurred(), "caib catalog get failed: %s", string(output))

			var result map[string]any
			Expect(json.Unmarshal(output, &result)).To(Succeed())
			Expect(result["scheduleName"]).To(Equal("nightly-detail"))
			Expect(result["sourceType"]).To(Equal("Scheduled"))
			Expect(result["tags"]).To(ContainElements("nightly", "qa"))
		})

		It("should show schedule and tags in table detail", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "get", detailName,
			)
			Expect(err).NotTo(HaveOccurred(), "caib catalog get table failed: %s", string(output))

			text := string(output)
			Expect(text).To(ContainSubstring("Schedule"))
			Expect(text).To(ContainSubstring("nightly-detail"))
			Expect(text).To(ContainSubstring("nightly, qa"))
		})
	})

	Context("Sort by Name", func() {
		aName := catalogPrefix + "-aaa"
		zName := catalogPrefix + "-zzz"

		BeforeAll(func() {
			applyCatalogImage(zName, map[string]string{
				"automotive.sdv.cloud.redhat.com/architecture": "x86_64",
				"automotive.sdv.cloud.redhat.com/distro":       "autosd",
			}, nil, "registry.access.redhat.com/ubi9/ubi-micro:9.4")

			applyCatalogImage(aName, map[string]string{
				"automotive.sdv.cloud.redhat.com/architecture": "x86_64",
				"automotive.sdv.cloud.redhat.com/distro":       "autosd",
			}, nil, "registry.access.redhat.com/ubi9/ubi-micro:latest")

			DeferCleanup(func() {
				cleanupCatalogImage(aName)
				cleanupCatalogImage(zName)
			})
		})

		It("should sort alphabetically with --sort name", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			output, err := runCaibCommand(ctx,
				"catalog", "list",
				"--distro", "autosd",
				"--sort", "name",
				"--output-format", "json",
			)
			Expect(err).NotTo(HaveOccurred(), "caib catalog list --sort name failed: %s", string(output))

			var result struct {
				Items []struct {
					Name string `json:"name"`
				} `json:"items"`
			}
			Expect(json.Unmarshal(output, &result)).To(Succeed())
			Expect(len(result.Items)).To(BeNumerically(">=", 2))

			aIdx, zIdx := -1, -1
			for i, item := range result.Items {
				if item.Name == aName {
					aIdx = i
				}
				if item.Name == zName {
					zIdx = i
				}
			}
			Expect(aIdx).NotTo(Equal(-1), "expected %s in results", aName)
			Expect(zIdx).NotTo(Equal(-1), "expected %s in results", zName)
			Expect(aIdx).To(BeNumerically("<", zIdx),
				"expected %s (idx %d) before %s (idx %d)", aName, aIdx, zName, zIdx)
		})
	})
})
