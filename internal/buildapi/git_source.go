package buildapi

import (
	"context"
	"fmt"
	"net/http"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func validateGitCredentials(ctx context.Context, c client.Client, namespace, requester string, source *api.GitSource) *httpError {
	if source == nil || source.CredentialsSecretRef == "" {
		return nil
	}
	secret, httpErr := requesterSecret(ctx, c, namespace, requester, source.CredentialsSecretRef, "git credentials")
	if httpErr != nil {
		return httpErr
	}
	if err := api.ValidateGitCredentialsSecret(source, secret); err != nil {
		return &httpError{code: http.StatusForbidden, message: err.Error()}
	}
	return nil
}

// requesterSecret returns the Secret a request names, if it was created for
// that requester. The API reads Secrets as its own ServiceAccount, so without
// this a request could hand a job it controls any Secret in the namespace:
// another user's, or the operator's own, such as the API's token-signing key.
// A missing Secret gets the same answer as someone else's, so requests cannot
// probe which Secrets exist.
func requesterSecret(ctx context.Context, c client.Client, namespace, requester, name, what string) (*corev1.Secret, *httpError) {
	forbidden := &httpError{code: http.StatusForbidden, message: fmt.Sprintf(
		"%s Secret %q must exist and have annotation %s matching the requesting user", what, name, labels.RequestedBy)}
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, forbidden
		}
		return nil, &httpError{code: http.StatusInternalServerError, message: fmt.Sprintf("failed to read %s Secret: %v", what, err)}
	}
	if requester == "" || secret.Annotations[labels.RequestedBy] != requester {
		return nil, forbidden
	}
	return secret, nil
}
