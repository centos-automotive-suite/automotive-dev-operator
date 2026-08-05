#!/bin/bash
# shellcheck shell=bash
# NOTE: common.sh is prepended to this script at embed time.

set -euo pipefail

# S3_BUCKET, S3_PREFIX, S3_ENDPOINT, S3_REGION, S3_INSECURE, and
# ARTIFACT_FILE are passed via step env vars (set in the Tekton Task
# definition) to avoid shell-injection from unvalidated param strings.
ARTIFACT_FILE="$(echo -n "$ARTIFACT_FILE" | tr -d '\n\r')"
PARTS_DIR="${ARTIFACT_FILE}-parts"

cd /workspace/shared || exit

echo "=== S3 Push Configuration ==="
echo "  Bucket:   $S3_BUCKET"
echo "  Prefix:   $S3_PREFIX"
echo "  Region:   $S3_REGION"
echo "  Endpoint: ${S3_ENDPOINT:-<default>}"
echo "  Artifact: $ARTIFACT_FILE"
echo "============================"

# Install AWS CLI if not present
if ! command -v aws >/dev/null 2>&1; then
  echo "Installing AWS CLI..."

  # Detect architecture
  case "$(uname -m)" in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
      echo "ERROR: Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac

  AWS_CLI_URL="https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip"

  # Download AWS CLI zip
  curl -sL "$AWS_CLI_URL" -o "awscliv2.zip"

  # If unzip not available, use Python's zipfile module
  if ! command -v unzip >/dev/null 2>&1; then
    echo "Using Python to extract AWS CLI..."
    python3 -c "import zipfile; zipfile.ZipFile('awscliv2.zip').extractall()"
  else
    unzip -q awscliv2.zip
  fi

  # Ensure install script and binaries are executable
  chmod +x ./aws/install
  chmod -R +x ./aws/dist/ 2>/dev/null || true

  # Install AWS CLI to a location we can write to
  if [ -w /usr/local/bin ] && [ -w /usr/local ]; then
    # If we have write access, install normally
    ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli
  else
    # Otherwise install to home directory and add to PATH
    mkdir -p "$HOME/.local/bin" "$HOME/.local/aws-cli"
    ./aws/install --bin-dir "$HOME/.local/bin" --install-dir "$HOME/.local/aws-cli" --update
    export PATH="$HOME/.local/bin:$PATH"
    # Ensure installed binaries are executable
    chmod +x "$HOME/.local/bin/aws" 2>/dev/null || true
    chmod -R +x "$HOME/.local/aws-cli/" 2>/dev/null || true
  fi

  rm -rf aws awscliv2.zip

  # Verify installation
  if ! command -v aws >/dev/null 2>&1; then
    echo "ERROR: AWS CLI installation failed" >&2
    exit 1
  fi

  echo "AWS CLI installed successfully: $(aws --version)"
fi

# Configure AWS credentials from mounted secret
if [ -d /workspace/s3-auth ]; then
  if [ -f /workspace/s3-auth/access-key-id ]; then
    AWS_ACCESS_KEY_ID=$(cat /workspace/s3-auth/access-key-id)
    export AWS_ACCESS_KEY_ID
    echo "Loaded AWS_ACCESS_KEY_ID from secret"
  fi
  if [ -f /workspace/s3-auth/secret-access-key ]; then
    AWS_SECRET_ACCESS_KEY=$(cat /workspace/s3-auth/secret-access-key)
    export AWS_SECRET_ACCESS_KEY
    echo "Loaded AWS_SECRET_ACCESS_KEY from secret"
  fi
else
  echo "No S3 credentials workspace mounted, using instance IAM role or environment variables"
fi

# Validate credentials are available
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  echo "WARNING: No AWS credentials found. This may fail if IAM roles are not configured, check both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
fi

# Set AWS region
export AWS_DEFAULT_REGION="$S3_REGION"

# Trust custom CA certificates if mounted
CA_BUNDLE_DIR="/etc/pki/ca-trust/custom"
if [ -d "$CA_BUNDLE_DIR" ] && [ -n "$(ls -A "$CA_BUNDLE_DIR" 2>/dev/null)" ]; then
  # Concatenate all CA certs into a single bundle for the AWS CLI
  CA_BUNDLE="/tmp/ca-bundle.crt"
  cat "$CA_BUNDLE_DIR"/* > "$CA_BUNDLE" 2>/dev/null || true
  if [ -s "$CA_BUNDLE" ]; then
    export AWS_CA_BUNDLE="$CA_BUNDLE"
    echo "Loaded custom CA bundle from $CA_BUNDLE_DIR"
  fi
fi

# Build AWS CLI arguments
AWS_ARGS=()
if [ -n "$S3_ENDPOINT" ]; then
  AWS_ARGS+=(--endpoint-url "$S3_ENDPOINT")
  echo "Using custom S3 endpoint: $S3_ENDPOINT"
fi
if [ "$S3_INSECURE" = "true" ]; then
  AWS_ARGS+=(--no-verify-ssl)
  echo "WARNING: TLS certificate verification disabled"
fi

# Test S3 connectivity
echo "Testing S3 connectivity..."
if ! aws s3 ls "${AWS_ARGS[@]}" "s3://${S3_BUCKET}/" >/dev/null 2>&1; then
  echo "WARNING: Cannot list S3 bucket. Attempting upload anyway..."
fi

# Build an S3 key from prefix and filename, avoiding double slashes
s3_key() {
  if [ -n "$S3_PREFIX" ]; then
    echo "${S3_PREFIX%/}/${1}"
  else
    echo "${1}"
  fi
}

emit_progress "Pushing to S3" 0 1

# Multi-part push (separate partition files)
if [ -d "$PARTS_DIR" ] && [ -n "$(ls -A "$PARTS_DIR" 2>/dev/null)" ]; then
  echo "Pushing multi-part artifact to S3..."

  cd "$PARTS_DIR" || exit

  UPLOADED_FILES=0
  for part_file in *; do
    # Skip .size sidecar files and manifests
    case "$part_file" in
      *.size|aib-manifest.yml)
        continue
        ;;
    esac

    if [ -f "$part_file" ]; then
      S3_KEY="$(s3_key "$part_file")"
      FILE_SIZE=$(stat -f %z "$part_file" 2>/dev/null || stat -c %s "$part_file" 2>/dev/null || echo "unknown")

      echo "Uploading $part_file (${FILE_SIZE} bytes) to s3://${S3_BUCKET}/${S3_KEY}"

      if aws s3 cp "${AWS_ARGS[@]}" \
        --region "$S3_REGION" \
        --storage-class STANDARD \
        "$part_file" \
        "s3://${S3_BUCKET}/${S3_KEY}"; then
        echo "  ✓ Uploaded successfully"
        UPLOADED_FILES=$((UPLOADED_FILES + 1))
      else
        echo "  ✗ Upload failed" >&2
        exit 1
      fi
    fi
  done

  echo "Uploaded ${UPLOADED_FILES} partition files"

  # Also upload the full tarball if it exists
  cd /workspace/shared || exit
  if [ -f "$ARTIFACT_FILE" ]; then
    S3_KEY="$(s3_key "$ARTIFACT_FILE")"
    FILE_SIZE=$(stat -f %z "$ARTIFACT_FILE" 2>/dev/null || stat -c %s "$ARTIFACT_FILE" 2>/dev/null || echo "unknown")

    echo "Uploading full archive (${FILE_SIZE} bytes) to s3://${S3_BUCKET}/${S3_KEY}"

    if aws s3 cp "${AWS_ARGS[@]}" \
      --region "$S3_REGION" \
      --storage-class STANDARD \
      "$ARTIFACT_FILE" \
      "s3://${S3_BUCKET}/${S3_KEY}"; then
      echo "  ✓ Full archive uploaded successfully"
    else
      echo "  ✗ Full archive upload failed" >&2
      exit 1
    fi
  fi

else
  # Single file push
  # Use absolute path to ensure we find the file
  ARTIFACT_PATH="/workspace/shared/${ARTIFACT_FILE}"
  S3_KEY="$(s3_key "$ARTIFACT_FILE")"

  # Debug: show what we're looking for
  echo "Looking for artifact: ${ARTIFACT_PATH}"
  ls -la "${ARTIFACT_PATH}" || ls -la /workspace/shared/

  echo "Uploading ${ARTIFACT_FILE} to s3://${S3_BUCKET}/${S3_KEY}"

  # Upload using absolute path
  if aws s3 cp "${AWS_ARGS[@]}" \
    --region "$S3_REGION" \
    --storage-class STANDARD \
    "${ARTIFACT_PATH}" \
    "s3://${S3_BUCKET}/${S3_KEY}"; then
    echo "  ✓ Uploaded successfully"
  else
    echo "  ✗ Upload failed" >&2
    exit 1
  fi
fi

emit_progress "Pushing to S3" 1 1

# Write Tekton results
S3_URL="s3://${S3_BUCKET}/$(s3_key "$ARTIFACT_FILE")"
echo -n "$S3_URL" > /tekton/results/S3_URL

echo ""
echo "=== S3 Push Complete ==="
echo "Artifact URL: $S3_URL"
echo "========================"
