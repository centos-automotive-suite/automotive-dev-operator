package buildapi

import (
	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func buildAIBSpec(req *BuildRequest, manifest, manifestFileName string, inputFilesServer bool) *automotivev1alpha1.AIBSpec {
	return &automotivev1alpha1.AIBSpec{
		Distro:           string(req.Distro),
		Target:           string(req.Target),
		Mode:             string(req.Mode),
		Manifest:         manifest,
		ManifestFileName: manifestFileName,
		Image:            req.AutomotiveImageBuilder,
		BuilderImage:     req.BuilderImage,
		RebuildBuilder:   req.RebuildBuilder,
		InputFilesServer: inputFilesServer,
		ContainerRef:     req.ContainerRef,
		CustomDefs:       req.CustomDefs,
		AIBExtraArgs:     req.AIBExtraArgs,
		RootPassword:     req.RootPassword,
		OCIRepoImages:    req.OCIRepoImages,
	}
}

func buildExportSpec(req *BuildRequest) *automotivev1alpha1.ExportSpec {
	export := &automotivev1alpha1.ExportSpec{
		Format:                string(req.ExportFormat),
		Compression:           string(req.Compression),
		BuildDiskImage:        req.BuildDiskImage,
		Container:             req.ContainerPush,
		UseServiceAccountAuth: req.UseInternalRegistry,
	}

	// Set disk export if OCI URL or S3 bucket is specified
	if req.ExportOCI != "" || req.S3Bucket != "" {
		export.Disk = &automotivev1alpha1.DiskExport{
			OCI: req.ExportOCI,
		}

		// Add S3 export configuration
		if req.S3Bucket != "" {
			s3Region := req.S3Region
			if s3Region == "" {
				s3Region = "us-east-1" // default
			}

			export.Disk.S3 = &automotivev1alpha1.S3Export{
				Bucket:                req.S3Bucket,
				Prefix:                req.S3Prefix,
				Endpoint:              req.S3Endpoint,
				Region:                s3Region,
				CredentialsSecret:     req.S3CredentialsSecretName,
				InsecureSkipTLSVerify: req.S3InsecureSkipTLSVerify,
			}
		}
	}

	return export
}
