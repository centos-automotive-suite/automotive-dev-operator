package buildapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
)

var (
	safeFilenameRe       = regexp.MustCompile(`^[a-zA-Z0-9.\-_/@]+$`)
	errTotalSizeExceeded = fmt.Errorf("total upload size exceeded")
)

func safeFilename(filename string) bool {
	return filename != "" && safeFilenameRe.MatchString(filename)
}

type uploadContext struct {
	ctx       context.Context
	restCfg   *rest.Config
	namespace string
	podName   string
	container string
	limits    *APILimits
}

type processFilePartResult struct {
	bytesWritten int64
}

func validateDestPath(dest string) (string, error) {
	if dest == "" {
		return "", fmt.Errorf("missing destination filename")
	}
	if !safeFilename(dest) {
		return "", fmt.Errorf("invalid destination filename: %s", dest)
	}
	// Root the path so path.Clean resolves all ".." without escaping,
	// then strip the leading "/" to make it relative to /workspace/shared/.
	cleanDest := strings.TrimPrefix(path.Clean("/"+dest), "/")
	if cleanDest == "" || cleanDest == "." {
		return "", fmt.Errorf("invalid destination path: %s", dest)
	}
	return cleanDest, nil
}

func (a *APIServer) processFilePart(part *multipart.Part, pendingPath string, uctx *uploadContext, remainingBytes int64) (processFilePartResult, error) {
	dest := pendingPath
	if dest == "" {
		dest = strings.TrimSpace(part.FileName())
	}

	cleanDest, err := validateDestPath(dest)
	if err != nil {
		return processFilePartResult{}, err
	}

	tmp, err := os.CreateTemp("", "upload-*")
	if err != nil {
		return processFilePartResult{}, err
	}
	tmpName := tmp.Name()
	defer func() {
		if closeErr := tmp.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close temp file: %v\n", closeErr)
		}
	}()
	defer func() {
		if removeErr := os.Remove(tmpName); removeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp file: %v\n", removeErr)
		}
	}()

	limitedReader := io.LimitReader(part, uctx.limits.MaxUploadFileSize+1)
	n, err := io.Copy(tmp, limitedReader)
	if err != nil {
		return processFilePartResult{}, err
	}
	if n > uctx.limits.MaxUploadFileSize {
		return processFilePartResult{}, fmt.Errorf("file %s exceeds maximum size (%d bytes)", dest, uctx.limits.MaxUploadFileSize)
	}
	if n > remainingBytes {
		return processFilePartResult{}, fmt.Errorf("%w: maximum %d bytes", errTotalSizeExceeded, uctx.limits.MaxTotalUploadSize)
	}

	destPath := "/workspace/shared/" + cleanDest
	if err := a.exec.copyFileToPod(uctx.ctx, uctx.restCfg, uctx.namespace, uctx.podName, uctx.container, tmpName, destPath); err != nil {
		return processFilePartResult{}, fmt.Errorf("stream to pod failed: %w", err)
	}

	return processFilePartResult{bytesWritten: n}, nil
}

func findRunningUploadPod(ctx context.Context, k8sClient client.Client, namespace, buildName string) (*corev1.Pod, error) {
	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList,
		client.InNamespace(namespace),
		client.MatchingLabels{
			labels.ImageBuildName: buildName,
			labels.Name:           "upload-pod",
		},
	); err != nil {
		return nil, fmt.Errorf("error listing upload pods: %w", err)
	}
	for i := range podList.Items {
		p := &podList.Items[i]
		if p.Status.Phase == corev1.PodRunning {
			return p, nil
		}
	}
	return nil, nil
}

// UploadPodReady reports whether a Running upload pod exists for the build. The
// controller uses it to defer starting a background workspace hydrate until the
// destination pod is available.
func UploadPodReady(ctx context.Context, k8sClient client.Client, namespace, buildName string) (bool, error) {
	pod, err := findRunningUploadPod(ctx, k8sClient, namespace, buildName)
	if err != nil {
		return false, err
	}
	return pod != nil, nil
}

func (a *APIServer) uploadFiles(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := a.getK8sClientOrFail(c)
	if err != nil {
		return
	}
	build := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(c.Request.Context(), c, k8sClient, name, namespace, build, "build"); err != nil {
		return
	}
	uploadPod, err := findRunningUploadPod(c.Request.Context(), k8sClient, namespace, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if uploadPod == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upload pod not ready"})
		return
	}

	if c.Request.ContentLength > a.limits.MaxTotalUploadSize {
		errMsg := fmt.Sprintf("upload too large (max %d bytes)", a.limits.MaxTotalUploadSize)
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": errMsg})
		return
	}

	reader, err := c.Request.MultipartReader()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid multipart: %v", err)})
		return
	}

	restCfg, err := a.deps.getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("rest config: %v", err)})
		return
	}

	uctx := &uploadContext{
		ctx:       c.Request.Context(),
		restCfg:   restCfg,
		namespace: namespace,
		podName:   uploadPod.Name,
		container: uploadPod.Spec.Containers[0].Name,
		limits:    &a.limits,
	}

	var totalBytesUploaded int64
	var filesProcessed int
	var pendingPath string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("read part: %v", err)})
			return
		}

		// Handle "path" field - stores the destination path for the next file
		if part.FormName() == "path" {
			const maxPathFieldSize = 4096
			pathBytes, err := io.ReadAll(io.LimitReader(part, maxPathFieldSize+1))
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("read path: %v", err)})
				return
			}
			if len(pathBytes) > maxPathFieldSize {
				c.JSON(http.StatusBadRequest, gin.H{"error": "path field too large"})
				return
			}
			pendingPath = strings.TrimSpace(string(pathBytes))
			continue
		}

		if part.FormName() != "file" {
			continue
		}

		remainingBytes := a.limits.MaxTotalUploadSize - totalBytesUploaded
		result, err := a.processFilePart(part, pendingPath, uctx, remainingBytes)
		pendingPath = ""
		if err != nil {
			if errors.Is(err, errTotalSizeExceeded) {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			}
			return
		}

		totalBytesUploaded += result.bytesWritten
		filesProcessed++
	}

	if filesProcessed == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one file part is required"})
		return
	}

	original := build
	patched := original.DeepCopy()
	if patched.Annotations == nil {
		patched.Annotations = map[string]string{}
	}
	patched.Annotations[labels.UploadsComplete] = labels.ValueTrue
	if err := k8sClient.Patch(c.Request.Context(), patched, client.MergeFrom(original)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("mark complete failed: %v", err)})
		return
	}
	writeJSON(c, http.StatusOK, map[string]string{"status": "ok"})
}
