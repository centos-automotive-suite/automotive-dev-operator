package buildapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

var isTerminalPhase = automotivev1alpha1.IsTerminalBuildPhase

func getStepContainerNames(pod corev1.Pod) []string {
	stepNames := make([]string, 0, len(pod.Spec.Containers))
	for _, cont := range pod.Spec.Containers {
		if strings.HasPrefix(cont.Name, "step-") {
			stepNames = append(stepNames, cont.Name)
		}
	}
	if len(stepNames) == 0 {
		for _, cont := range pod.Spec.Containers {
			stepNames = append(stepNames, cont.Name)
		}
	}
	return stepNames
}

func sortPodsByStartTime(pods []corev1.Pod) {
	sort.Slice(pods, func(i, j int) bool {
		if pods[i].Status.StartTime == nil {
			return false
		}
		if pods[j].Status.StartTime == nil {
			return true
		}
		return pods[i].Status.StartTime.Before(pods[j].Status.StartTime)
	})
}

func podTaskName(pod corev1.Pod) string {
	if name := pod.Labels["tekton.dev/pipelineTask"]; name != "" {
		return name
	}
	return pod.Name
}

func logStreamHeader(taskName, containerName string) string {
	return "\n===== Logs from " + taskName + "/" + strings.TrimPrefix(containerName, "step-") + " =====\n\n"
}

func isPodTerminal(phase corev1.PodPhase) bool {
	return phase == corev1.PodSucceeded || phase == corev1.PodFailed
}

func isBuildTerminal(ctx context.Context, k8sClient client.Client, name, namespace string, ib *automotivev1alpha1.ImageBuild) bool {
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, ib); err != nil {
		return false
	}
	return isTerminalPhase(ib.Status.Phase)
}

func streamContainerLogs(
	ctx context.Context, c *gin.Context, cs *kubernetes.Clientset,
	namespace, podName, containerName, taskName string, sinceTime *metav1.Time, follow bool,
) bool {
	req := cs.CoreV1().Pods(namespace).GetLogs(
		podName, &corev1.PodLogOptions{Container: containerName, Follow: follow, SinceTime: sinceTime},
	)

	type streamOpenResult struct {
		stream io.ReadCloser
		err    error
	}

	openResultCh := make(chan streamOpenResult, 1)
	go func() {
		stream, err := req.Stream(ctx)
		openResultCh <- streamOpenResult{stream: stream, err: err}
	}()

	openTicker := time.NewTicker(10 * time.Second)
	defer openTicker.Stop()

	var stream io.ReadCloser
	for stream == nil {
		select {
		case <-ctx.Done():
			select {
			case result := <-openResultCh:
				if result.stream != nil {
					_ = result.stream.Close()
				}
			default:
			}
			return true
		case <-openTicker.C:
			_, _ = c.Writer.Write([]byte("[Waiting for container log stream...]\n"))
			c.Writer.Flush()
		case result := <-openResultCh:
			if result.err != nil {
				return false
			}
			stream = result.stream
		}
	}

	defer func() {
		if err := stream.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close stream: %v\n", err)
		}
	}()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	lineCh := make(chan string)
	scanErrCh := make(chan error, 1)
	go func() {
		defer close(lineCh)
		for scanner.Scan() {
			line := scanner.Text()
			select {
			case lineCh <- line:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			select {
			case scanErrCh <- err:
			default:
			}
		}
	}()

	headerWritten := false
	keepaliveTicker := time.NewTicker(20 * time.Second)
	defer keepaliveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return true
		case <-keepaliveTicker.C:
			if !headerWritten {
				_, _ = c.Writer.Write([]byte(".\n"))
			} else {
				_, _ = c.Writer.Write([]byte("[Waiting for container log output...]\n"))
			}
			c.Writer.Flush()
		case line, ok := <-lineCh:
			if !ok {
				select {
				case scanErr := <-scanErrCh:
					var errMsg []byte
					errMsg = fmt.Appendf(errMsg, "\n[Stream error: %v]\n", scanErr)
					_, _ = c.Writer.Write(errMsg)
					c.Writer.Flush()
				default:
				}
				return true
			}

			if !headerWritten {
				_, _ = c.Writer.Write([]byte(logStreamHeader(taskName, containerName)))
				headerWritten = true
			}

			if _, writeErr := c.Writer.Write([]byte(line)); writeErr != nil {
				return true
			}
			if _, writeErr := c.Writer.Write([]byte("\n")); writeErr != nil {
				return true
			}
			c.Writer.Flush()
		}
	}
}

func processPodLogs(
	ctx context.Context, c *gin.Context, cs *kubernetes.Clientset,
	pod corev1.Pod, namespace string, sinceTime *metav1.Time,
	streamedContainers map[string]bool, hadStream *bool,
) {
	stepNames := getStepContainerNames(pod)
	taskName := podTaskName(pod)

	for _, cName := range stepNames {
		if streamedContainers[cName] {
			continue
		}

		if !*hadStream {
			c.Writer.Flush()
		}

		if streamContainerLogs(ctx, c, cs, namespace, pod.Name, cName, taskName, sinceTime, true) {
			*hadStream = true
			streamedContainers[cName] = true
		} else if isPodTerminal(pod.Status.Phase) {
			streamedContainers[cName] = true
		}
	}
}

func (a *APIServer) streamLogs(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := a.getK8sClientOrFail(c)
	if err != nil {
		return
	}

	sinceTime := parseSinceTime(c.Query("since"))
	streamDuration := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute
	ctx, cancel := context.WithTimeout(c.Request.Context(), streamDuration)
	defer cancel()

	ib := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, ib, "build"); err != nil {
		return
	}

	if strings.TrimSpace(ib.Status.PipelineRunName) == "" && ib.Status.SourceTaskRunName == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "logs not available yet"})
		return
	}

	cs, err := a.getClientsetOrFail(c)
	if err != nil {
		return
	}

	setupLogStreamHeaders(c)

	var hadStream bool
	var lastKeepalive time.Time
	streamedContainers := make(map[string]map[string]bool)
	completedPods := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pods, err := listBuildLogPods(ctx, cs, namespace, ib)
		if err != nil {
			if _, writeErr := fmt.Fprintf(c.Writer, "\n[Error listing pods: %v]\n", err); writeErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to write error message: %v\n", writeErr)
			}
			c.Writer.Flush()
			time.Sleep(2 * time.Second)
			continue
		}

		if len(pods.Items) == 0 {
			if isBuildTerminal(ctx, k8sClient, name, namespace, ib) {
				break
			}
			if !hadStream {
				_, _ = c.Writer.Write([]byte("."))
				c.Writer.Flush()
			}
			time.Sleep(2 * time.Second)
			continue
		}

		sortPodsByStartTime(pods.Items)

		allPodsComplete := true
		for _, pod := range pods.Items {
			if completedPods[pod.Name] {
				continue
			}

			if streamedContainers[pod.Name] == nil {
				streamedContainers[pod.Name] = make(map[string]bool)
			}

			processPodLogs(ctx, c, cs, pod, namespace, sinceTime, streamedContainers[pod.Name], &hadStream)

			stepNames := getStepContainerNames(pod)
			if len(streamedContainers[pod.Name]) == len(stepNames) &&
				isPodTerminal(pod.Status.Phase) {
				completedPods[pod.Name] = true
			} else {
				allPodsComplete = false
			}
		}

		if shouldExitLogStream(ctx, k8sClient, name, namespace, ib, allPodsComplete) {
			break
		}

		time.Sleep(2 * time.Second)

		if !hadStream {
			_, _ = c.Writer.Write([]byte("."))
			if f, ok := c.Writer.(http.Flusher); ok {
				f.Flush()
			}
		} else if allPodsComplete {
			now := time.Now()
			if now.Sub(lastKeepalive) >= 30*time.Second {
				_, _ = c.Writer.Write([]byte("[Waiting for remaining pipeline tasks...]\n"))
				if f, ok := c.Writer.(http.Flusher); ok {
					f.Flush()
				}
				lastKeepalive = now
			}
		}
	}

	writeLogStreamFooter(c, hadStream)
}

func listBuildLogPods(ctx context.Context, cs kubernetes.Interface, namespace string, ib *automotivev1alpha1.ImageBuild) (*corev1.PodList, error) {
	pods := &corev1.PodList{}
	selectors := buildLogPodSelectors(ib)
	for _, selector := range selectors {
		found, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return nil, err
		}
		pods.Items = append(pods.Items, found.Items...)
	}
	return pods, nil
}

func buildLogPodSelectors(ib *automotivev1alpha1.ImageBuild) []string {
	selectors := []string{}
	pipelineRun := strings.TrimSpace(ib.Status.PipelineRunName)
	sourceTaskRun := strings.TrimSpace(ib.Status.SourceTaskRunName)
	if pipelineRun != "" {
		selectors = append(selectors, "tekton.dev/pipelineRun="+pipelineRun+",tekton.dev/memberOf=tasks")
	}
	if sourceTaskRun != "" {
		selectors = append(selectors, "tekton.dev/taskRun="+sourceTaskRun)
	}
	return selectors
}

func shouldExitLogStream(
	ctx context.Context,
	k8sClient client.Client,
	name, namespace string,
	ib *automotivev1alpha1.ImageBuild,
	allPodsComplete bool,
) bool {
	terminal := isBuildTerminal(ctx, k8sClient, name, namespace, ib)
	return terminal && allPodsComplete
}

func writeLogStreamFooter(c *gin.Context, hadStream bool) {
	if !hadStream {
		_, _ = c.Writer.Write([]byte("\n[No logs available]\n"))
	} else {
		_, _ = c.Writer.Write([]byte("\n[Log streaming completed]\n"))
	}
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}
}
