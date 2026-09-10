package caibcommon

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	buildapi "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

func LoadBuildCallback(callbackURL, secretFile string) (*buildapi.BuildCallback, error) {
	hasURL := strings.TrimSpace(callbackURL) != ""
	hasSecret := strings.TrimSpace(secretFile) != ""
	if hasURL != hasSecret {
		return nil, fmt.Errorf("--callback-url and --callback-secret-file must be used together")
	}
	if !hasURL {
		return nil, nil
	}
	secret, err := os.ReadFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("read callback secret file: %w", err)
	}
	if len(secret) < 32 || len(secret) > 4096 {
		return nil, fmt.Errorf("callback secret file must contain 32 to 4096 bytes")
	}
	return &buildapi.BuildCallback{
		URL:    callbackURL,
		Secret: base64.StdEncoding.EncodeToString(secret),
	}, nil
}
