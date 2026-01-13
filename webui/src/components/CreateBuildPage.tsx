import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  PageSection,
  Title,
  Form,
  FormGroup,
  TextInput,
  TextArea,
  Button,
  Alert,
  Card,
  CardBody,
  Grid,
  GridItem,
  FileUpload,
  ExpandableSection,
  Flex,
  FlexItem,
  Stack,
  StackItem,
  Split,
  SplitItem,
  Badge,
  Popover,
  Checkbox,
  Radio,
  Modal,
  ModalVariant,
  Bullseye,
  Spinner,
  Switch,
  NumberInput,


} from "@patternfly/react-core";
import { PlusCircleIcon, TrashIcon, InfoCircleIcon } from "@patternfly/react-icons";
import { useLocation, useNavigate } from "react-router-dom";
import { authFetch, API_BASE } from "../utils/auth";

interface TextFile {
  id: string;
  name: string;
  content: string;
}

interface UploadedFile {
  id: string;
  name: string;
  file: File;
}

interface RegistryCredentials {
  enabled: boolean;
  authType: "username-password" | "token" | "docker-config";
  registryUrl: string;
  username: string;
  password: string;
  token: string;
  dockerConfig: string;
}

interface ManifestWizardData {
  name: string;
  version: string;
  content: {
    rpms: string[];
    enable_repos: string[];
    repos: Array<{
      id: string;
      baseurl: string;
      priority?: number;
    }>;
    container_images: Array<{
      source: string;
      tag?: string;
      digest?: string;
      name?: string;
      "containers-transport"?: "docker" | "containers-storage";
      index?: boolean;
    }>;
    add_files: Array<{
      path: string;
      source_path?: string;
      url?: string;
      text?: string;
      source_glob?: string;
      preserve_path?: boolean;
      max_files?: number;
      allow_empty?: boolean;
    }>;
    chmod_files: Array<{
      path: string;
      mode: string;
      recursive?: boolean;
    }>;
    chown_files: Array<{
      path: string;
      user?: string | number;
      group?: string | number;
      recursive?: boolean;
    }>;
    remove_files: Array<{
      path: string;
    }>;
    make_dirs: Array<{
      path: string;
      mode?: number;
      parents?: boolean;
      exist_ok?: boolean;
    }>;
    systemd?: {
      enabled_services?: string[];
      disabled_services?: string[];
    };
    sbom?: {
      doc_path: string;
    };
  };
  qm?: {
    content: any; // Same structure as content above
    memory_limit?: {
      max?: string;
      high?: string;
    };
    cpu_weight?: string | number;
    container_checksum?: string;
  };
  network?: {
    static?: {
      ip: string;
      ip_prefixlen: number;
      gateway: string;
      dns: string;
      iface?: string;
      load_module?: string;
    };
    dynamic?: {};
  };
  image?: {
    image_size?: string;
    selinux_mode?: "enforcing" | "permissive";
    selinux_policy?: string;
    selinux_booleans?: { [key: string]: boolean };
    partitions?: any; // Complex partition structure
    hostname?: string;
    ostree_ref?: string;
  };
  auth?: {
    root_password?: string | null;
    root_ssh_keys?: string[] | null;
    sshd_config?: {
      PasswordAuthentication?: boolean;
      PermitRootLogin?: boolean | "prohibit-password" | "forced-commands-only";
    };
    users?: { [username: string]: any };
    groups?: { [groupname: string]: any };
  };
  kernel?: {
    debug_logging?: boolean;
    cmdline?: string[];
    kernel_package?: string;
    kernel_version?: string;
    loglevel?: number;
    remove_modules?: string[];
  };
  experimental?: {
    internal_defines?: { [key: string]: any };
  };
}

interface BuildFormData {
  name: string;
  manifest: string;
  manifestFileName: string;
  distro: string;
  target: string;
  architecture: string;
  exportFormat: string;
  mode: string;
  automotiveImageBuilder: string;
  aibExtraArgs: string;
  serveArtifact: boolean;
  compression?: string;
  registryCredentials: RegistryCredentials;
}

interface BuildTemplateResponse {
  name: string;
  manifest: string;
  manifestFileName: string;
  distro: string;
  target: string;
  architecture: string;
  exportFormat: string;
  mode: string;
  automotiveImageBuilder: string;
  aibExtraArgs?: string[];
  serveArtifact: boolean;
  compression?: string;
  sourceFiles?: string[];
  registryCredentials?: RegistryCredentials;
}

const BUILD_MODE_OPTIONS = [
  { value: "image", label: "image" },
  { value: "package", label: "package" },
];

const ARCHITECTURE_OPTIONS = [
  { value: "arm64", label: "arm64 (aarch64)" },
  { value: "amd64", label: "amd64 (x86_64)" },
];

const DISTRO_OPTIONS = [
  { value: "autosd", label: "autosd - Alias of 'autosd9'" },
  { value: "autosd10", label: "autosd10 - AutoSD 9 - based on nightly autosd compose" },
  { value: "autosd10-latest-sig", label: "autosd10-latest-sig - AutoSD 10 - latest cs10 and autosd repos, plus the automotive sig community packages" },
  { value: "autosd10-sig", label: "autosd10-sig - AutoSD 9 - based on nightly autosd compose, plus the automotive sig community packages" },
  { value: "autosd9", label: "autosd9 - AutoSD 9 - based on nightly autosd compose" },
  { value: "autosd9-latest-sig", label: "autosd9-latest-sig - AutoSD 9 - latest cs9 and autosd repos, plus the automotive sig community packages" },
  { value: "autosd9-sig", label: "autosd9-sig - AutoSD 9 - based on nightly autosd compose, plus the automotive sig community packages" },
  { value: "cs9", label: "cs9 - Alias of 'autosd9-latest-sig'" },
  { value: "eln", label: "eln - Fedora ELN" },
  { value: "f40", label: "f40 - Fedora 40" },
  { value: "f41", label: "f41 - Fedora 41" },
  { value: "rhivos", label: "rhivos - Alias of 'rhivos1'" },
  { value: "rhivos1", label: "rhivos1 - RHIVOS 1" },
];

const TARGET_OPTIONS = [
  { value: "_abootqemu", label: "_abootqemu - Implementation of abootqemu.ipp.yml but loaded after derived target" },
  { value: "_abootqemukvm", label: "_abootqemukvm - Implementation of abootqemukvm.ipp.yml but loaded after derived target" },
  { value: "_ridesx4_r3", label: "_ridesx4_r3 - Implementation of ridesx4_r3.ipp.yml but loaded after derived target" },
  { value: "_ridesx4_scmi", label: "_ridesx4_scmi - Implementation of ridesx4_scmi.ipp.yml, but loaded after derived target" },
  { value: "abootqemu", label: "abootqemu - This is a qemu target similar to the regular \"qemu\" target, but using an android boot partition instead of grub." },
  { value: "abootqemukvm", label: "abootqemukvm - This is a qemu target similar to the \"abootqemu\", but using a dtb that enables kvm." },
  { value: "acrn", label: "acrn" },
  { value: "am62sk", label: "am62sk - Target for the TI SK-AM62 Evaluation Board" },
  { value: "am69sk", label: "am69sk - Target for the TI SK-AM69 Evaluation Board" },
  { value: "aws", label: "aws" },
  { value: "azure", label: "azure - Target for Azure images" },
  { value: "beagleplay", label: "beagleplay - Target for the TI BeaglePlay Board" },
  { value: "ccimx93dvk", label: "ccimx93dvk" },
  { value: "imx8qxp_mek", label: "imx8qxp_mek - Target for the Multisensory Enablement Kit i.MX 8QuadXPlus MEK CPU Board" },
  { value: "j784s4evm", label: "j784s4evm - Target for the TI J784S4XEVM Evaluation Board" },
  { value: "pc", label: "pc" },
  { value: "qdrive3", label: "qdrive3" },
  { value: "qemu", label: "qemu - Target for general virtualized images (typically for qemu)" },
  { value: "rcar_s4", label: "rcar_s4 - Target for Renesas R-Car S4 with stock functionality" },
  { value: "rcar_s4_can", label: "rcar_s4_can - Target for Renesas R-Car S4 with CAN bus enablement, requires CAN unlock app running on G4MH cores to boot" },
  { value: "ridesx4", label: "ridesx4 - A target for the QC RIDESX4 board." },
  { value: "ridesx4_r3", label: "ridesx4_r3 - A target for the QC RIDESX4 board, Rev 3." },
  { value: "ridesx4_scmi", label: "ridesx4_scmi - A target for the QC RIDESX4 board flashed with recent firmware using SCMI for drivers resources." },
  { value: "rpi4", label: "rpi4 - Target for the Raspberry Pi 4" },
  { value: "s32g_vnp_rdb3", label: "s32g_vnp_rdb3 - Target for the NXP S32G3 Vehicle Networking Reference Design Board" },
  { value: "tda4vm_sk", label: "tda4vm_sk - Target for the TI SK-TDA4VM Evaluation Board" },
];

const EXPORT_FORMAT_OPTIONS = [
  { value: "aboot", label: "aboot - Aboot image" },
  { value: "aboot.simg", label: "aboot.simg - Aboot image in simg format" },
  { value: "bootc", label: "bootc - Bootc image in local store" },
  { value: "bootc-archive", label: "bootc-archive - Bootc OCI image archive" },
  { value: "container", label: "container - Container image" },
  { value: "ext4", label: "ext4 - Ext4 filesystem image without partitions" },
  { value: "ext4.simg", label: "ext4.simg - Ext4 filesystem partition in simg format" },
  { value: "image", label: "image - Raw disk image" },
  { value: "ostree-commit", label: "ostree-commit - OSTree repo containing a commit" },
  { value: "qcow2", label: "qcow2 - Disk image in qcow2 format" },
  { value: "rootfs", label: "rootfs - Directory with image rootfs files" },
  { value: "rpmlist", label: "rpmlist - List of rpms that are in the image" },
  { value: "simg", label: "simg - Partitioned image in simg format" },
  { value: "tar", label: "tar - Tar archive with files from rootfs" },
];

const PopoverLabel: React.FC<{ label: string; popoverContent: string; isRequired?: boolean }> = ({ label, popoverContent, isRequired }) => (
  <span>
    {label}
    {isRequired && <span style={{ color: "var(--pf-v5-global--danger-color--100)" }}> *</span>}
    <Popover
      aria-label={`${label} information`}
      bodyContent={popoverContent}
    >
      <button
        type="button"
        aria-label={`More info for ${label}`}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--pf-v5-global--Color--200)',
          marginLeft: '4px',
          cursor: 'pointer',
          fontSize: '0.875rem'
        }}
      >
        <InfoCircleIcon />
      </button>
    </Popover>
  </span>
);

const CreateBuildPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [formData, setFormData] = useState<BuildFormData>({
    name: "",
    manifest: "",
    manifestFileName: "manifest.aib.yml",
    distro: "",
    target: "",
    architecture: "",
    exportFormat: "",
    mode: "",
    automotiveImageBuilder:
      "quay.io/centos-sig-automotive/automotive-image-builder:1.0.0",
    aibExtraArgs: "",
    serveArtifact: true,
    compression: "gzip",
    registryCredentials: {
      enabled: false,
      authType: "username-password",
      registryUrl: "",
      username: "",
      password: "",
      token: "",
      dockerConfig: "",
    },
  });

  // Wizard mode state
  const [useWizard, setUseWizard] = useState(false);
  const [wizardData, setWizardData] = useState<ManifestWizardData>({
    name: "",
    version: "",
    content: {
      rpms: [],
      enable_repos: [],
      repos: [],
      container_images: [],
      add_files: [],
      chmod_files: [],
      chown_files: [],
      remove_files: [],
      make_dirs: [],
    },
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [alert, setAlert] = useState<{
    type: "success" | "danger";
    message: string;
  } | null>(null);
  const [textFiles, setTextFiles] = useState<TextFile[]>([]);
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  const [expectedFiles, setExpectedFiles] = useState<string[]>([]);
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [isSystemdOpen, setIsSystemdOpen] = useState(false);
  const [isFilesOpen, setIsFilesOpen] = useState(false);


  // Helper function to convert wizard data to YAML
  const generateYAMLFromWizard = (data: ManifestWizardData): string => {
    // Don't remove the name field even if it's empty, as it's required
    const safeName = data.name || '';
    const safeVersion = data.version || '';

    // Build YAML sections only if they have content
    let yaml = `# Generated from wizard\nname: "${safeName}"`;

    if (safeVersion) {
      yaml += `\nversion: "${safeVersion}"`;
    }

    // Content section
    const hasContent = data.content && (
      (data.content.rpms && data.content.rpms.length > 0) ||
      (data.content.enable_repos && data.content.enable_repos.length > 0) ||
      (data.content.container_images && data.content.container_images.length > 0) ||
      (data.content.add_files && data.content.add_files.length > 0) ||
      (data.content.systemd && (data.content.systemd.enabled_services?.length || data.content.systemd.disabled_services?.length))
    );

    if (hasContent) {
      yaml += `\ncontent:`;

      if (data.content.rpms && data.content.rpms.length > 0) {
        yaml += `\n  rpms:`;
        data.content.rpms.forEach(rpm => {
          yaml += `\n    - "${rpm}"`;
        });
      }

      if (data.content.enable_repos && data.content.enable_repos.length > 0) {
        yaml += `\n  enable_repos:`;
        data.content.enable_repos.forEach(repo => {
          yaml += `\n    - "${repo}"`;
        });
      }

      if (data.content.container_images && data.content.container_images.length > 0) {
        yaml += `\n  container_images:`;
        data.content.container_images.forEach(img => {
          if (img.source) {
            yaml += `\n    - source: "${img.source}"`;
            if (img.tag) yaml += `\n      tag: "${img.tag}"`;
            if (img.digest) yaml += `\n      digest: "${img.digest}"`;
            if (img.name) yaml += `\n      name: "${img.name}"`;
            if (img["containers-transport"]) yaml += `\n      containers-transport: "${img["containers-transport"]}"`;
            if (img.index) yaml += `\n      index: ${img.index}`;
          }
        });
      }

      if (data.content.add_files && data.content.add_files.length > 0) {
        yaml += `\n  add_files:`;
        data.content.add_files.forEach(file => {
          if (file.path) {
            yaml += `\n    - path: "${file.path}"`;
            if (file.source_path) yaml += `\n      source_path: "${file.source_path}"`;
            if (file.url) yaml += `\n      url: "${file.url}"`;
            if (file.text) yaml += `\n      text: |\n        ${file.text.split('\n').join('\n        ')}`;
            if (file.source_glob) {
              yaml += `\n      source_glob: "${file.source_glob}"`;
              if (file.preserve_path !== undefined) yaml += `\n      preserve_path: ${file.preserve_path}`;
              if (file.max_files && file.max_files !== 1000) yaml += `\n      max_files: ${file.max_files}`;
              if (file.allow_empty) yaml += `\n      allow_empty: ${file.allow_empty}`;
            }
          }
        });
      }

      if (data.content.systemd && (data.content.systemd.enabled_services?.length || data.content.systemd.disabled_services?.length)) {
        yaml += `\n  systemd:`;
        if (data.content.systemd.enabled_services?.length) {
          yaml += `\n    enabled_services:`;
          data.content.systemd.enabled_services.forEach(service => {
            yaml += `\n      - "${service}"`;
          });
        }
        if (data.content.systemd.disabled_services?.length) {
          yaml += `\n    disabled_services:`;
          data.content.systemd.disabled_services.forEach(service => {
            yaml += `\n      - "${service}"`;
          });
        }
      }
    }

    // Network section
    if (data.network) {
      if (data.network.static) {
        yaml += `\nnetwork:\n  static:`;
        yaml += `\n    ip: "${data.network.static.ip}"`;
        yaml += `\n    ip_prefixlen: ${data.network.static.ip_prefixlen}`;
        yaml += `\n    gateway: "${data.network.static.gateway}"`;
        yaml += `\n    dns: "${data.network.static.dns}"`;
        if (data.network.static.iface) yaml += `\n    iface: "${data.network.static.iface}"`;
        if (data.network.static.load_module) yaml += `\n    load_module: "${data.network.static.load_module}"`;
      } else if (data.network.dynamic) {
        yaml += `\nnetwork:\n  dynamic: {}`;
      }
    }

    // Image section
    if (data.image && (data.image.image_size || data.image.selinux_mode || data.image.hostname)) {
      yaml += `\nimage:`;
      if (data.image.image_size) yaml += `\n  image_size: "${data.image.image_size}"`;
      if (data.image.selinux_mode) yaml += `\n  selinux_mode: "${data.image.selinux_mode}"`;
      if (data.image.hostname) yaml += `\n  hostname: "${data.image.hostname}"`;
    }

    return yaml;
  };

  // Helper function to sync wizard data to manifest
  const syncWizardToManifest = useCallback(() => {
    if (useWizard) {
      const yamlContent = generateYAMLFromWizard(wizardData);
      setFormData(prev => ({ ...prev, manifest: yamlContent }));
    }
  }, [useWizard, wizardData]);

  // Effect to sync wizard data when it changes
  useEffect(() => {
    if (useWizard) {
      syncWizardToManifest();
    }
  }, [wizardData, useWizard, syncWizardToManifest]);

  const initializedFromTemplate = useRef(false);
  useEffect(() => {
    if (initializedFromTemplate.current) return;
    let t: BuildTemplateResponse | null =
      (location as any)?.state?.template || null;
    if (!t) {
      const raw = sessionStorage.getItem("aib-template");
      if (raw) {
        try {
          t = JSON.parse(raw);
        } catch {
          t = null;
        }
        sessionStorage.removeItem("aib-template");
      }
    }
    if (!t) return;

    setFormData((prev) => ({
      ...prev,
      name: "",
      manifest: t?.manifest ?? prev.manifest,
      manifestFileName: t?.manifestFileName ?? prev.manifestFileName,
      distro: t?.distro ?? prev.distro,
      target: t?.target ?? prev.target,
      architecture: t?.architecture ?? prev.architecture,
      exportFormat: t?.exportFormat ?? prev.exportFormat,
      mode: t?.mode ?? prev.mode,
      automotiveImageBuilder:
        t?.automotiveImageBuilder ?? prev.automotiveImageBuilder,
      aibExtraArgs: (t?.aibExtraArgs ?? []).join(" "),
      serveArtifact: t?.serveArtifact ?? prev.serveArtifact,
      compression: t?.compression ?? prev.compression ?? "gzip",
      registryCredentials: t?.registryCredentials ?? prev.registryCredentials,
    }));

    if (t.sourceFiles && t.sourceFiles.length > 0) {
      const templateFiles = t.sourceFiles
        .map((p) => p.trim())
        .filter((p) => p.length > 0);
      setExpectedFiles(templateFiles);
    }

    initializedFromTemplate.current = true;
  }, [location]);

  const handleInputChange = (
    field: keyof BuildFormData,
    value: string | boolean,
  ) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleRegistryCredentialsChange = (
    field: keyof RegistryCredentials,
    value: string | boolean,
  ) => {
    setFormData((prev) => ({
      ...prev,
      registryCredentials: {
        ...prev.registryCredentials,
        [field]: value,
      },
    }));
  };

  const addTextFile = () => {
    const newFile: TextFile = {
      id: `text-${Date.now()}`,
      name: `file-${textFiles.length + 1}.txt`,
      content: "",
    };
    setTextFiles((prev) => [...prev, newFile]);
  };

  const updateTextFile = (
    id: string,
    field: "name" | "content",
    value: string,
  ) => {
    setTextFiles((prev) =>
      prev.map((file) => (file.id === id ? { ...file, [field]: value } : file)),
    );
  };

  const removeTextFile = (id: string) => {
    setTextFiles((prev) => prev.filter((file) => file.id !== id));
  };

  const handleFileUpload = (file: File) => {
    setUploadedFiles((prev) => {
      const existingIndex = prev.findIndex(
        (f) =>
          f.name === file.name &&
          f.file.size === file.size &&
          f.file.lastModified === file.lastModified,
      );

      if (existingIndex !== -1) {
        const updated = prev.slice();
        updated[existingIndex] = {
          id: updated[existingIndex].id,
          name: file.name,
          file,
        };
        return updated;
      }

      const uploadedFile: UploadedFile = {
        id: `upload-${(crypto as any).randomUUID?.() || Date.now()}`,
        name: file.name,
        file,
      };
      return [...prev, uploadedFile];
    });
  };

  const removeUploadedFile = (id: string) => {
    setUploadedFiles((prev) => prev.filter((file) => file.id !== id));
  };

  const uploadFiles = async (buildName: string) => {
    if (textFiles.length === 0 && uploadedFiles.length === 0) return;

    const sleep = (ms: number) =>
      new Promise((resolve) => setTimeout(resolve, ms));
    const maxAttempts = 60; // ~2 minutes with 2s delay
    const delayMs = 2000;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const formData = new FormData();

        textFiles.forEach((textFile) => {
          const blob = new Blob([textFile.content], { type: "text/plain" });
          formData.append("file", blob, textFile.name);
        });

        uploadedFiles.forEach((uploadedFile) => {
          formData.append("file", uploadedFile.file, uploadedFile.name);
        });

        const response = await authFetch(
          `${API_BASE}/v1/builds/${buildName}/uploads`,
          {
            method: "POST",
            body: formData,
          },
        );

        if (response.ok) {
          return;
        }

        if (response.status === 503) {
          if (attempt < maxAttempts) {
            await sleep(delayMs);
            continue;
          }
          const msg = await response.text();
          throw new Error(`Upload pod not ready: ${msg}`);
        }

        const msg = await response.text();
        throw new Error(`Failed to upload files: ${response.status} ${msg}`);
      } catch (error) {
        if (attempt >= maxAttempts) {
          console.error("File upload error:", error);
          setAlert({
            type: "danger",
            message: `Error uploading files: ${error}`,
          });
          return;
        }
        await sleep(delayMs);
      }
    }
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);
    setAlert(null);

    try {
      const payload = {
        name: formData.name,
        manifest: formData.manifest,
        manifestFileName: formData.manifestFileName,
        distro: formData.distro,
        target: formData.target,
        architecture: formData.architecture,
        exportFormat: formData.exportFormat,
        mode: formData.mode,
        automotiveImageBuilder: formData.automotiveImageBuilder,
        compression: formData.compression || "lz4",
        aibExtraArgs: formData.aibExtraArgs
          ? formData.aibExtraArgs.split(" ").filter((arg) => arg.trim())
          : [],
        serveArtifact: formData.serveArtifact,
        registryCredentials: formData.registryCredentials.enabled ? formData.registryCredentials : undefined,
      };

      const response = await authFetch(`${API_BASE}/v1/builds`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        const result = await response.json();

        if (textFiles.length > 0 || uploadedFiles.length > 0) {
          await uploadFiles(formData.name);
        }

        setAlert({
          type: "success",
          message: `Build "${result.name}" created successfully!`,
        });

        setIsRedirecting(true);

        setFormData({
          name: "",
          manifest: "",
          manifestFileName: "manifest.aib.yml",
          distro: "",
          target: "",
          architecture: "",
          exportFormat: "",
          mode: "",
          automotiveImageBuilder:
            "quay.io/centos-sig-automotive/automotive-image-builder:1.0.0",
          aibExtraArgs: "",
          serveArtifact: true,
          compression: "gzip",
          registryCredentials: {
            enabled: false,
            authType: "username-password",
            registryUrl: "",
            username: "",
            password: "",
            token: "",
            dockerConfig: "",
          },
        });
        setTextFiles([]);
        setUploadedFiles([]);
        setExpectedFiles([]);

        setTimeout(() => {
          navigate("/builds");
        }, 2000);
      } else {
        const error = await response.text();
        setAlert({ type: "danger", message: `Error creating build: ${error}` });
      }
    } catch (error) {
      setAlert({ type: "danger", message: `Network error: ${error}` });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
    <PageSection>
      <Stack hasGutter>
        <StackItem>
          <Title headingLevel="h1" size="2xl">
            Create New Image Build
          </Title>
        </StackItem>

        {alert && (
          <StackItem>
            <Alert
              variant={alert.type}
              title={alert.message}
              isInline
            />
          </StackItem>
        )}

        <StackItem>
          <Form onSubmit={handleSubmit}>
            <Stack hasGutter>
              {/* Basic Build Information */}
              <StackItem>
                <Card>
                  <CardBody>
                    <Stack hasGutter>
                      <StackItem>
                        <Title headingLevel="h2" size="lg">
                          Basic Information
                        </Title>
                      </StackItem>
                      <StackItem>
                        <Grid hasGutter>
                          <GridItem span={6}>
                            <FormGroup
                              label={<PopoverLabel label="Build Name" popoverContent="A unique identifier for your build" isRequired />} 
                              fieldId="name"
                            >
                              <TextInput
                                id="name"
                                value={formData.name}
                                onChange={(_event, value) =>
                                  handleInputChange("name", value)
                                }
                                placeholder="Enter a unique name for this build"
                                isRequired
                              />
                            </FormGroup>
                          </GridItem>
                          <GridItem span={12}>
                            <FormGroup
                              label={<PopoverLabel label="Manifest Content" popoverContent="YAML configuration that defines your build requirements" isRequired />}
                              fieldId="manifest"
                            >
                              <Stack hasGutter>
                                <StackItem>
                                  <Flex alignItems={{ default: "alignItemsCenter" }}>
                                    <FlexItem>
                                      <Switch
                                        id="wizard-toggle"
                                        label={useWizard ? "Wizard" : "YAML"}
                                        isChecked={useWizard}
                                        onChange={(_event, checked) => {
                                          setUseWizard(checked);
                                          if (!checked) {
                                            syncWizardToManifest();
                                          }
                                        }}
                                      />
                                    </FlexItem>
                                  </Flex>
                                </StackItem>
                                {!useWizard && (
                                  <StackItem>
                                    <TextArea
                                      id="manifest"
                                      value={formData.manifest}
                                      onChange={(_event, value) =>
                                        handleInputChange("manifest", value)
                                      }
                                      placeholder="Enter your YAML manifest content here..."
                                      rows={12}
                                      isRequired
                                    />
                                  </StackItem>
                                )}
                              </Stack>
                            </FormGroup>
                          </GridItem>
                        </Grid>
                      </StackItem>
                    </Stack>
                  </CardBody>
                </Card>
              </StackItem>

              {/* Wizard Form Sections */}
              {useWizard && (
                <>
                  {/* Basic Manifest Information */}
                  <StackItem>
                    <Card>
                      <CardBody>
                        <Stack hasGutter>
                          <StackItem>
                            <Title headingLevel="h2" size="lg">
                              Manifest Information
                            </Title>
                          </StackItem>
                          <StackItem>
                            <Grid hasGutter>
                              <GridItem span={6}>
                                <FormGroup
                                  label={<PopoverLabel label="Manifest Name" popoverContent="Name identifier for your manifest" isRequired />} 
                                  fieldId="wizard-name"
                                >
                                  <TextInput
                                    id="wizard-name"
                                    value={wizardData.name}
                                    onChange={(_event, value) =>
                                      setWizardData(prev => ({ ...prev, name: value }))
                                    }
                                    placeholder="Enter manifest name"
                                    isRequired
                                  />
                                </FormGroup>
                              </GridItem>
                              <GridItem span={6}>
                                <FormGroup
                                  label={<PopoverLabel label="Version" popoverContent="Version of your manifest (optional)" />} 
                                  fieldId="wizard-version"
                                >
                                  <TextInput
                                    id="wizard-version"
                                    value={wizardData.version}
                                    onChange={(_event, value) =>
                                      setWizardData(prev => ({ ...prev, version: value }))
                                    }
                                    placeholder="e.g., 1.0.0"
                                  />
                                </FormGroup>
                              </GridItem>
                            </Grid>
                          </StackItem>
                        </Stack>
                      </CardBody>
                    </Card>
                  </StackItem>

                  {/* Content Section */}
                  <StackItem>
                    <Card>
                      <CardBody>
                        <Stack hasGutter>
                          <StackItem>
                            <Title headingLevel="h2" size="lg">
                              Content
                            </Title>
                          </StackItem>

                          <StackItem>
                            <FormGroup
                              label={<PopoverLabel label="RPM Packages" popoverContent="List of RPM packages to install (one per line)" />} 
                              fieldId="wizard-rpms"
                            >
                              <TextArea
                                id="wizard-rpms"
                                value={wizardData.content.rpms.join('\n')}
                                onChange={(_event, value) =>
                                  setWizardData(prev => ({
                                    ...prev,
                                    content: {
                                      ...prev.content,
                                      rpms: value.split('\n').filter(rpm => rpm.trim())
                                    }
                                  }))
                                }
                                placeholder="Enter RPM package names, one per line&#10;Example:&#10;vim&#10;git&#10;htop"
                                rows={4}
                              />
                            </FormGroup>
                          </StackItem>

                          <StackItem>
                            <FormGroup
                              label={<PopoverLabel label="Enable Repositories" popoverContent="Enable predefined repositories (debug, devel)" />}
                              fieldId="wizard-enable-repos"
                            >
                              <Stack hasGutter>
                                <StackItem>
                                  <Checkbox
                                    id="enable-debug-repo"
                                    label="debug - Enable debug repository"
                                    isChecked={wizardData.content.enable_repos.includes('debug')}
                                    onChange={(_event, checked) => {
                                      setWizardData(prev => ({
                                        ...prev,
                                        content: {
                                          ...prev.content,
                                          enable_repos: checked
                                            ? [...prev.content.enable_repos, 'debug']
                                            : prev.content.enable_repos.filter(r => r !== 'debug')
                                        }
                                      }));
                                    }}
                                  />
                                </StackItem>
                                <StackItem>
                                  <Checkbox
                                    id="enable-devel-repo"
                                    label="devel - Enable development repository"
                                    isChecked={wizardData.content.enable_repos.includes('devel')}
                                    onChange={(_event, checked) => {
                                      setWizardData(prev => ({
                                        ...prev,
                                        content: {
                                          ...prev.content,
                                          enable_repos: checked
                                            ? [...prev.content.enable_repos, 'devel']
                                            : prev.content.enable_repos.filter(r => r !== 'devel')
                                        }
                                      }));
                                    }}
                                  />
                                </StackItem>
                              </Stack>
                            </FormGroup>
                          </StackItem>

                          <StackItem>
                            <FormGroup
                              label={<PopoverLabel label="Container Images" popoverContent="Container images to embed in the image" />}
                              fieldId="wizard-containers"
                            >
                              <Stack hasGutter>
                                {wizardData.content.container_images.map((img, index) => (
                                  <StackItem key={index}>
                                    <Card isPlain>
                                      <CardBody>
                                        <Stack hasGutter>
                                          <StackItem>
                                            <Split hasGutter>
                                              <SplitItem isFilled>
                                                <Title headingLevel="h4" size="md">
                                                  Container Image {index + 1}
                                                </Title>
                                              </SplitItem>
                                              <SplitItem>
                                                <Button
                                                  variant="plain"
                                                  size="sm"
                                                  onClick={() => {
                                                    setWizardData(prev => ({
                                                      ...prev,
                                                      content: {
                                                        ...prev.content,
                                                        container_images: prev.content.container_images.filter((_, i) => i !== index)
                                                      }
                                                    }));
                                                  }}
                                                  icon={<TrashIcon />}
                                                />
                                              </SplitItem>
                                            </Split>
                                          </StackItem>
                                          <StackItem>
                                            <Grid hasGutter>
                                              <GridItem span={6}>
                                                <FormGroup label="Source" fieldId={`container-source-${index}`} isRequired>
                                                  <TextInput
                                                    id={`container-source-${index}`}
                                                    value={img.source}
                                                    onChange={(_event, value) => {
                                                      setWizardData(prev => ({
                                                        ...prev,
                                                        content: {
                                                          ...prev.content,
                                                          container_images: prev.content.container_images.map((c, i) => 
                                                            i === index ? { ...c, source: value } : c
                                                          )
                                                        }
                                                      }));
                                                    }}
                                                    placeholder="quay.io/fedora/fedora"
                                                    isRequired
                                                  />
                                                </FormGroup>
                                              </GridItem>
                                              <GridItem span={3}>
                                                <FormGroup label="Tag" fieldId={`container-tag-${index}`}>
                                                  <TextInput
                                                    id={`container-tag-${index}`}
                                                    value={img.tag || ''}
                                                    onChange={(_event, value) => {
                                                      setWizardData(prev => ({
                                                        ...prev,
                                                        content: {
                                                          ...prev.content,
                                                          container_images: prev.content.container_images.map((c, i) => 
                                                            i === index ? { ...c, tag: value || undefined } : c
                                                          )
                                                        }
                                                      }));
                                                    }}
                                                    placeholder="latest"
                                                  />
                                                </FormGroup>
                                              </GridItem>
                                              <GridItem span={3}>
                                                <FormGroup label="Name" fieldId={`container-name-${index}`}>
                                                  <TextInput
                                                    id={`container-name-${index}`}
                                                    value={img.name || ''}
                                                    onChange={(_event, value) => {
                                                      setWizardData(prev => ({
                                                        ...prev,
                                                        content: {
                                                          ...prev.content,
                                                          container_images: prev.content.container_images.map((c, i) => 
                                                            i === index ? { ...c, name: value || undefined } : c
                                                          )
                                                        }
                                                      }));
                                                    }}
                                                    placeholder="Custom name"
                                                  />
                                                </FormGroup>
                                              </GridItem>
                                            </Grid>
                                          </StackItem>
                                        </Stack>
                                      </CardBody>
                                    </Card>
                                  </StackItem>
                                ))}
                                <StackItem>
                                  <Button
                                    variant="link"
                                    size="sm"
                                    onClick={() => {
                                      setWizardData(prev => ({
                                        ...prev,
                                        content: {
                                          ...prev.content,
                                          container_images: [...prev.content.container_images, { source: '' }]
                                        }
                                      }));
                                    }}
                                    icon={<PlusCircleIcon />}
                                  >
                                    Add Container Image
                                  </Button>
                                </StackItem>
                              </Stack>
                            </FormGroup>
                          </StackItem>

                          {/* Files Section */}
                          <StackItem>
                            <ExpandableSection
                              toggleText="Files"
                              isExpanded={isFilesOpen}
                              onToggle={(_event, expanded) => setIsFilesOpen(expanded as boolean)}
                            >
                              <Stack hasGutter style={{ paddingTop: "16px" }}>
                                {wizardData.content.add_files.map((file, index) => (
                                  <StackItem key={index}>
                                    <Card isPlain>
                                      <CardBody>
                                        <Stack hasGutter>
                                          <StackItem>
                                            <Split hasGutter>
                                              <SplitItem isFilled>
                                                <Title headingLevel="h4" size="md">
                                                  Add File {index + 1}
                                                </Title>
                                              </SplitItem>
                                              <SplitItem>
                                                <Button
                                                  variant="plain"
                                                  size="sm"
                                                  onClick={() => {
                                                    setWizardData(prev => ({
                                                      ...prev,
                                                      content: {
                                                        ...prev.content,
                                                        add_files: prev.content.add_files.filter((_, i) => i !== index)
                                                      }
                                                    }));
                                                  }}
                                                  icon={<TrashIcon />}
                                                />
                                              </SplitItem>
                                            </Split>
                                          </StackItem>
                                          <StackItem>
                                            <Grid hasGutter>
                                              <GridItem span={6}>
                                                <FormGroup label="Destination Path" fieldId={`file-path-${index}`} isRequired>
                                                  <TextInput
                                                    id={`file-path-${index}`}
                                                    value={file.path}
                                                    onChange={(_event, value) => {
                                                      setWizardData(prev => ({
                                                        ...prev,
                                                        content: {
                                                          ...prev.content,
                                                          add_files: prev.content.add_files.map((f, i) => 
                                                            i === index ? { ...f, path: value } : f
                                                          )
                                                        }
                                                      }));
                                                    }}
                                                    placeholder="/etc/myconfig.conf"
                                                    isRequired
                                                  />
                                                </FormGroup>
                                              </GridItem>
                                              <GridItem span={6}>
                                                <FormGroup label="File Type" fieldId={`file-type-${index}`}>
                                                  <div>
                                                    <Radio
                                                      id={`file-type-source-${index}`}
                                                      name={`fileType-${index}`}
                                                      label="Local File"
                                                      isChecked={!!file.source_path}
                                                      onChange={() => {
                                                        setWizardData(prev => ({
                                                          ...prev,
                                                          content: {
                                                            ...prev.content,
                                                            add_files: prev.content.add_files.map((f, i) =>
                                                              i === index ? {
                                                                path: f.path,
                                                                source_path: f.source_path || ''
                                                              } : f
                                                            )
                                                          }
                                                        }));
                                                      }}
                                                    />
                                                    <Radio
                                                      id={`file-type-url-${index}`}
                                                      name={`fileType-${index}`}
                                                      label="URL"
                                                      isChecked={!!file.url}
                                                      onChange={() => {
                                                        setWizardData(prev => ({
                                                          ...prev,
                                                          content: {
                                                            ...prev.content,
                                                            add_files: prev.content.add_files.map((f, i) =>
                                                              i === index ? {
                                                                path: f.path,
                                                                url: f.url || ''
                                                              } : f
                                                            )
                                                          }
                                                        }));
                                                      }}
                                                    />
                                                    <Radio
                                                      id={`file-type-text-${index}`}
                                                      name={`fileType-${index}`}
                                                      label="Inline Text"
                                                      isChecked={!!file.text}
                                                      onChange={() => {
                                                        setWizardData(prev => ({
                                                          ...prev,
                                                          content: {
                                                            ...prev.content,
                                                            add_files: prev.content.add_files.map((f, i) =>
                                                              i === index ? {
                                                                path: f.path,
                                                                text: f.text || ''
                                                              } : f
                                                            )
                                                          }
                                                        }));
                                                      }}
                                                    />
                                                    <Radio
                                                      id={`file-type-glob-${index}`}
                                                      name={`fileType-${index}`}
                                                      label="Glob Pattern"
                                                      isChecked={!!file.source_glob}
                                                      onChange={() => {
                                                        setWizardData(prev => ({
                                                          ...prev,
                                                          content: {
                                                            ...prev.content,
                                                            add_files: prev.content.add_files.map((f, i) =>
                                                              i === index ? {
                                                                path: f.path,
                                                                source_glob: f.source_glob || '',
                                                                preserve_path: false,
                                                                max_files: 1000,
                                                                allow_empty: false
                                                              } : f
                                                            )
                                                          }
                                                        }));
                                                      }}
                                                    />
                                                  </div>
                                                </FormGroup>
                                              </GridItem>
                                            </Grid>
                                          </StackItem>

                                          {file.source_path !== undefined && (
                                            <StackItem>
                                              <Stack hasGutter>
                                                <StackItem>
                                                  <FormGroup label="Source Type" fieldId={`file-source-type-${index}`}>
                                                    <div>
                                                      <Radio
                                                        id={`file-source-path-${index}`}
                                                        name={`sourceType-${index}`}
                                                        label="File Path"
                                                        isChecked={!file.source_path?.startsWith('__uploaded__')}
                                                        onChange={() => {
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, source_path: '' } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                      />
                                                      <Radio
                                                        id={`file-source-upload-${index}`}
                                                        name={`sourceType-${index}`}
                                                        label="Upload File"
                                                        isChecked={!!file.source_path?.startsWith('__uploaded__')}
                                                        onChange={() => {
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, source_path: '__uploaded__' } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                      />
                                                    </div>
                                                  </FormGroup>
                                                </StackItem>

                                                {!file.source_path?.startsWith('__uploaded__') ? (
                                                  <StackItem>
                                                    <FormGroup label="Source Path" fieldId={`file-source-path-input-${index}`} isRequired>
                                                      <TextInput
                                                        id={`file-source-path-input-${index}`}
                                                        value={file.source_path || ''}
                                                        onChange={(_event, value) => {
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, source_path: value } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                        placeholder="./myfile.conf or /absolute/path/to/file"
                                                        isRequired
                                                      />
                                                    </FormGroup>
                                                  </StackItem>
                                                ) : (
                                                  <StackItem>
                                                    <FormGroup label="Upload File" fieldId={`file-upload-${index}`} isRequired>
                                                      <FileUpload
                                                        id={`file-upload-${index}`}
                                                        type="dataURL"
                                                        value=""
                                                        filename=""
                                                        filenamePlaceholder="Click to browse or drag and drop"
                                                        onFileInputChange={(_event, uploadedFile) => {
                                                          if (uploadedFile) {
                                                            // Add to uploaded files list
                                                            handleFileUpload(uploadedFile);

                                                            // Update wizard data to reference the uploaded file
                                                            setWizardData(prev => ({
                                                              ...prev,
                                                              content: {
                                                                ...prev.content,
                                                                add_files: prev.content.add_files.map((f, i) =>
                                                                  i === index ? { ...f, source_path: uploadedFile.name } : f
                                                                )
                                                              }
                                                            }));
                                                          }
                                                        }}
                                                        browseButtonText="Browse"
                                                        clearButtonText="Clear"
                                                      />
                                                      {file.source_path && file.source_path !== '__uploaded__' && (
                                                        <div style={{ marginTop: "8px", fontSize: "0.875rem", color: "var(--pf-v5-global--success-color--100)" }}>
                                                          ✓ File selected: {file.source_path}
                                                        </div>
                                                      )}
                                                    </FormGroup>
                                                  </StackItem>
                                                )}
                                              </Stack>
                                            </StackItem>
                                          )}

                                          {/* URL Input */}
                                          {file.url !== undefined && (
                                            <StackItem>
                                              <FormGroup label="URL" fieldId={`file-url-${index}`} isRequired>
                                                <TextInput
                                                  id={`file-url-${index}`}
                                                  value={file.url}
                                                  onChange={(_event, value) => {
                                                    setWizardData(prev => ({
                                                      ...prev,
                                                      content: {
                                                        ...prev.content,
                                                        add_files: prev.content.add_files.map((f, i) =>
                                                          i === index ? { ...f, url: value } : f
                                                        )
                                                      }
                                                    }));
                                                  }}
                                                  placeholder="https://example.com/myfile.conf"
                                                  isRequired
                                                />
                                              </FormGroup>
                                            </StackItem>
                                          )}

                                          {/* Text Input */}
                                          {file.text !== undefined && (
                                            <StackItem>
                                              <FormGroup label="File Content" fieldId={`file-text-${index}`} isRequired>
                                                <TextArea
                                                  id={`file-text-${index}`}
                                                  value={file.text}
                                                  onChange={(_event, value) => {
                                                    setWizardData(prev => ({
                                                      ...prev,
                                                      content: {
                                                        ...prev.content,
                                                        add_files: prev.content.add_files.map((f, i) =>
                                                          i === index ? { ...f, text: value } : f
                                                        )
                                                      }
                                                    }));
                                                  }}
                                                  placeholder="Enter file content here..."
                                                  rows={6}
                                                  isRequired
                                                />
                                              </FormGroup>
                                            </StackItem>
                                          )}

                                          {/* Glob Pattern Input */}
                                          {file.source_glob !== undefined && (
                                            <>
                                              <StackItem>
                                                <FormGroup label="Source Glob Pattern" fieldId={`file-glob-${index}`} isRequired>
                                                  <TextInput
                                                    id={`file-glob-${index}`}
                                                    value={file.source_glob}
                                                    onChange={(_event, value) => {
                                                      setWizardData(prev => ({
                                                        ...prev,
                                                        content: {
                                                          ...prev.content,
                                                          add_files: prev.content.add_files.map((f, i) =>
                                                            i === index ? { ...f, source_glob: value } : f
                                                          )
                                                        }
                                                      }));
                                                    }}
                                                    placeholder="./config/**/*.conf"
                                                    isRequired
                                                  />
                                                </FormGroup>
                                              </StackItem>
                                              <StackItem>
                                                <Grid hasGutter>
                                                  <GridItem span={4}>
                                                    <FormGroup fieldId={`file-preserve-path-${index}`}>
                                                      <Checkbox
                                                        id={`file-preserve-path-${index}`}
                                                        label="Preserve directory structure"
                                                        isChecked={file.preserve_path || false}
                                                        onChange={(_event, checked) => {
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, preserve_path: checked } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                      />
                                                    </FormGroup>
                                                  </GridItem>
                                                  <GridItem span={4}>
                                                    <FormGroup label="Max Files" fieldId={`file-max-files-${index}`}>
                                                      <NumberInput
                                                        id={`file-max-files-${index}`}
                                                        value={file.max_files || 1000}
                                                        onMinus={() => {
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, max_files: Math.max(1, (f.max_files || 1000) - 1) } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                        onPlus={() => {
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, max_files: (f.max_files || 1000) + 1 } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                        onChange={(event) => {
                                                          const value = parseInt((event.target as HTMLInputElement).value) || 1000;
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, max_files: Math.max(1, value) } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                        min={1}
                                                      />
                                                    </FormGroup>
                                                  </GridItem>
                                                  <GridItem span={4}>
                                                    <FormGroup fieldId={`file-allow-empty-${index}`}>
                                                      <Checkbox
                                                        id={`file-allow-empty-${index}`}
                                                        label="Allow empty matches"
                                                        isChecked={file.allow_empty || false}
                                                        onChange={(_event, checked) => {
                                                          setWizardData(prev => ({
                                                            ...prev,
                                                            content: {
                                                              ...prev.content,
                                                              add_files: prev.content.add_files.map((f, i) =>
                                                                i === index ? { ...f, allow_empty: checked } : f
                                                              )
                                                            }
                                                          }));
                                                        }}
                                                      />
                                                    </FormGroup>
                                                  </GridItem>
                                                </Grid>
                                              </StackItem>
                                            </>
                                          )}
                                        </Stack>
                                      </CardBody>
                                    </Card>
                                  </StackItem>
                                ))}
                                <StackItem>
                                  <Button
                                    variant="link"
                                    size="sm"
                                    onClick={() => {
                                      setWizardData(prev => ({
                                        ...prev,
                                        content: {
                                          ...prev.content,
                                          add_files: [...prev.content.add_files, { path: '', source_path: '' }]
                                        }
                                      }));
                                    }}
                                    icon={<PlusCircleIcon />}
                                  >
                                    Add File
                                  </Button>
                                </StackItem>

                                {uploadedFiles.length > 0 && (
                                  <StackItem>
                                    <Card isPlain>
                                      <CardBody>
                                        <Stack hasGutter>
                                          <StackItem>
                                            <Title headingLevel="h4" size="md">
                                              Available Uploaded Files
                                            </Title>
                                          </StackItem>
                                          <StackItem>
                                            <p style={{ fontSize: "0.875rem", color: "var(--pf-v5-global--Color--200)" }}>
                                              These files are uploaded and can be referenced in your file entries above.
                                            </p>
                                          </StackItem>
                                          <StackItem>
                                            <Stack hasGutter>
                                              {uploadedFiles.map((uploadedFile) => {
                                                const isReferenced = wizardData.content.add_files.some(f => f.source_path === uploadedFile.name);
                                                return (
                                                  <StackItem key={uploadedFile.id}>
                                                    <div style={{
                                                      display: 'flex',
                                                      alignItems: 'center',
                                                      padding: '8px',
                                                      border: '1px solid var(--pf-v5-global--BorderColor--100)',
                                                      borderRadius: '4px',
                                                      backgroundColor: isReferenced ? 'var(--pf-v5-global--success-color--50)' : 'transparent'
                                                    }}>
                                                      <span style={{ flex: 1 }}>
                                                        <strong>{uploadedFile.name}</strong>
                                                        <span style={{ marginLeft: '8px', fontSize: '0.875rem', color: 'var(--pf-v5-global--Color--200)' }}>
                                                          ({(uploadedFile.file.size / 1024).toFixed(1)} KB)
                                                        </span>
                                                        {isReferenced && (
                                                          <Badge style={{ marginLeft: '8px' }}>Referenced</Badge>
                                                        )}
                                                      </span>
                                                    </div>
                                                  </StackItem>
                                                );
                                              })}
                                            </Stack>
                                          </StackItem>
                                        </Stack>
                                      </CardBody>
                                    </Card>
                                  </StackItem>
                                )}
                              </Stack>
                            </ExpandableSection>
                          </StackItem>

                          <StackItem>
                            <ExpandableSection
                              toggleText="Systemd Services"
                              isExpanded={isSystemdOpen}
                              onToggle={(_event, expanded) => setIsSystemdOpen(expanded as boolean)}
                            >
                              <Grid hasGutter style={{ paddingTop: "16px" }}>
                                <GridItem span={6}>
                                  <FormGroup 
                                    label={<PopoverLabel label="Enabled Services" popoverContent="Systemd services to enable (one per line)" />}
                                    fieldId="wizard-enabled-services"
                                  >
                                    <TextArea
                                      id="wizard-enabled-services"
                                      value={wizardData.content.systemd?.enabled_services?.join('\n') || ''}
                                      onChange={(_event, value) =>
                                        setWizardData(prev => ({
                                          ...prev,
                                          content: {
                                            ...prev.content,
                                            systemd: {
                                              ...prev.content.systemd,
                                              enabled_services: value.split('\n').filter(s => s.trim())
                                            }
                                          }
                                        }))
                                      }
                                      placeholder="service1.service&#10;service2.service"
                                      rows={4}
                                    />
                                  </FormGroup>
                                </GridItem>
                                <GridItem span={6}>
                                  <FormGroup
                                    label={<PopoverLabel label="Disabled Services" popoverContent="Systemd services to disable (one per line)" />}
                                    fieldId="wizard-disabled-services"
                                  >
                                    <TextArea
                                      id="wizard-disabled-services"
                                      value={wizardData.content.systemd?.disabled_services?.join('\n') || ''}
                                      onChange={(_event, value) =>
                                        setWizardData(prev => ({
                                          ...prev,
                                          content: {
                                            ...prev.content,
                                            systemd: {
                                              ...prev.content.systemd,
                                              disabled_services: value.split('\n').filter(s => s.trim())
                                            }
                                          }
                                        }))
                                      }
                                      placeholder="service3.service&#10;service4.service"
                                      rows={4}
                                    />
                                  </FormGroup>
                                </GridItem>
                              </Grid>
                            </ExpandableSection>
                          </StackItem>
                        </Stack>
                      </CardBody>
                    </Card>
                  </StackItem>

                  {/* Network Configuration */}
                  <StackItem>
                    <Card>
                      <CardBody>
                        <Stack hasGutter>
                          <StackItem>
                            <Title headingLevel="h2" size="lg">
                              Network Configuration
                            </Title>
                          </StackItem>
                          <StackItem>
                            <FormGroup label="Network Type" fieldId="network-type">
                              <div>
                                <Radio
                                  id="network-dynamic"
                                  name="networkType"
                                  label="Dynamic (DHCP)"
                                  isChecked={!wizardData.network || !!wizardData.network.dynamic}
                                  onChange={() => {
                                    setWizardData(prev => ({
                                      ...prev,
                                      network: { dynamic: {} }
                                    }));
                                  }}
                                />
                                <Radio
                                  id="network-static"
                                  name="networkType"
                                  label="Static IP"
                                  isChecked={!!wizardData.network?.static}
                                  onChange={() => {
                                    setWizardData(prev => ({
                                      ...prev,
                                      network: { 
                                        static: {
                                          ip: '',
                                          ip_prefixlen: 24,
                                          gateway: '',
                                          dns: ''
                                        }
                                      }
                                    }));
                                  }}
                                />
                              </div>
                            </FormGroup>
                          </StackItem>
                          {wizardData.network?.static && (
                            <StackItem>
                              <Grid hasGutter>
                                <GridItem span={3}>
                                  <FormGroup label="IP Address" fieldId="static-ip" isRequired>
                                    <TextInput
                                      id="static-ip"
                                      value={wizardData.network.static.ip}
                                      onChange={(_event, value) => {
                                        setWizardData(prev => ({
                                          ...prev,
                                          network: {
                                            ...prev.network,
                                            static: {
                                              ...prev.network!.static!,
                                              ip: value
                                            }
                                          }
                                        }));
                                      }}
                                      placeholder="192.168.1.100"
                                      isRequired
                                    />
                                  </FormGroup>
                                </GridItem>
                                <GridItem span={3}>
                                  <FormGroup label="Prefix Length" fieldId="static-prefixlen" isRequired>
                                    <NumberInput
                                      id="static-prefixlen"
                                      value={wizardData.network.static.ip_prefixlen}
                                      onMinus={() => {
                                        setWizardData(prev => ({
                                          ...prev,
                                          network: {
                                            ...prev.network,
                                            static: {
                                              ...prev.network!.static!,
                                              ip_prefixlen: Math.max(1, prev.network!.static!.ip_prefixlen - 1)
                                            }
                                          }
                                        }));
                                      }}
                                      onPlus={() => {
                                        setWizardData(prev => ({
                                          ...prev,
                                          network: {
                                            ...prev.network,
                                            static: {
                                              ...prev.network!.static!,
                                              ip_prefixlen: Math.min(32, prev.network!.static!.ip_prefixlen + 1)
                                            }
                                          }
                                        }));
                                      }}
                                      onChange={(event) => {
                                        const value = parseInt((event.target as HTMLInputElement).value) || 24;
                                        setWizardData(prev => ({
                                          ...prev,
                                          network: {
                                            ...prev.network,
                                            static: {
                                              ...prev.network!.static!,
                                              ip_prefixlen: Math.min(32, Math.max(1, value))
                                            }
                                          }
                                        }));
                                      }}
                                      min={1}
                                      max={32}
                                    />
                                  </FormGroup>
                                </GridItem>
                                <GridItem span={3}>
                                  <FormGroup label="Gateway" fieldId="static-gateway" isRequired>
                                    <TextInput
                                      id="static-gateway"
                                      value={wizardData.network.static.gateway}
                                      onChange={(_event, value) => {
                                        setWizardData(prev => ({
                                          ...prev,
                                          network: {
                                            ...prev.network,
                                            static: {
                                              ...prev.network!.static!,
                                              gateway: value
                                            }
                                          }
                                        }));
                                      }}
                                      placeholder="192.168.1.1"
                                      isRequired
                                    />
                                  </FormGroup>
                                </GridItem>
                                <GridItem span={3}>
                                  <FormGroup label="DNS" fieldId="static-dns" isRequired>
                                    <TextInput
                                      id="static-dns"
                                      value={wizardData.network.static.dns}
                                      onChange={(_event, value) => {
                                        setWizardData(prev => ({
                                          ...prev,
                                          network: {
                                            ...prev.network,
                                            static: {
                                              ...prev.network!.static!,
                                              dns: value
                                            }
                                          }
                                        }));
                                      }}
                                      placeholder="8.8.8.8"
                                      isRequired
                                    />
                                  </FormGroup>
                                </GridItem>
                              </Grid>
                            </StackItem>
                          )}
                        </Stack>
                      </CardBody>
                    </Card>
                  </StackItem>

                  {/* Image Configuration */}
                  <StackItem>
                    <Card>
                      <CardBody>
                        <Stack hasGutter>
                          <StackItem>
                            <Title headingLevel="h2" size="lg">
                              Image Configuration
                            </Title>
                          </StackItem>
                          <StackItem>
                            <Grid hasGutter>
                              <GridItem span={4}>
                                <FormGroup 
                                  label={<PopoverLabel label="Image Size" popoverContent="Total size of the image (e.g., 8 GB, 4 GiB)" />}
                                  fieldId="wizard-image-size"
                                >
                                  <TextInput
                                    id="wizard-image-size"
                                    value={wizardData.image?.image_size || ''}
                                    onChange={(_event, value) =>
                                      setWizardData(prev => ({
                                        ...prev,
                                        image: {
                                          ...prev.image,
                                          image_size: value || undefined
                                        }
                                      }))
                                    }
                                    placeholder="8 GB"
                                  />
                                </FormGroup>
                              </GridItem>
                              <GridItem span={4}>
                                <FormGroup 
                                  label={<PopoverLabel label="SELinux Mode" popoverContent="SELinux enforcement mode" />}
                                  fieldId="wizard-selinux-mode"
                                >
                                  <TextInput
                                    id="wizard-selinux-mode"
                                    value={wizardData.image?.selinux_mode || ''}
                                    onChange={(_event, value) =>
                                      setWizardData(prev => ({
                                        ...prev,
                                        image: {
                                          ...prev.image,
                                          selinux_mode: value as "enforcing" | "permissive" || undefined
                                        }
                                      }))
                                    }
                                    placeholder="enforcing"
                                    list="selinux-mode-options"
                                  />
                                  <datalist id="selinux-mode-options">
                                    <option value="enforcing" />
                                    <option value="permissive" />
                                  </datalist>
                                </FormGroup>
                              </GridItem>
                              <GridItem span={4}>
                                <FormGroup 
                                  label={<PopoverLabel label="Hostname" popoverContent="Network hostname for the system" />}
                                  fieldId="wizard-hostname"
                                >
                                  <TextInput
                                    id="wizard-hostname"
                                    value={wizardData.image?.hostname || ''}
                                    onChange={(_event, value) =>
                                      setWizardData(prev => ({
                                        ...prev,
                                        image: {
                                          ...prev.image,
                                          hostname: value || undefined
                                        }
                                      }))
                                    }
                                    placeholder="my-system"
                                  />
                                </FormGroup>
                              </GridItem>
                            </Grid>
                          </StackItem>
                        </Stack>
                      </CardBody>
                    </Card>
                  </StackItem>
                </>
              )}

              {/* Build Configuration */}
              <StackItem>
                <Card style={{ overflow: "visible" }}>
                  <CardBody style={{ overflow: "visible" }}>
                    <Stack hasGutter>
                      <StackItem>
                        <Title headingLevel="h2" size="lg">
                          Build Configuration
                        </Title>
                      </StackItem>
                      <StackItem>
                        <Grid hasGutter>
                          <GridItem xl={4} lg={6} md={12}>
                            <FormGroup label={<PopoverLabel label="Distribution" popoverContent="Target distribution (e.g., autosd, cs9)" />} fieldId="distro">
                              <TextInput
                                id="distro"
                                value={formData.distro}
                                onChange={(_event, value) =>
                                  handleInputChange("distro", value)
                                }
                                placeholder="Select or type a distribution..."
                                list="distro-options"
                              />
                              <datalist id="distro-options">
                                {DISTRO_OPTIONS.map((option, index) => (
                                  <option key={index} value={option.value} title={option.label.split(' - ')[1]} />
                                ))}
                              </datalist>
                            </FormGroup>
                          </GridItem>

                          <GridItem xl={4} lg={6} md={12}>
                            <FormGroup label={<PopoverLabel label="Target Platform" popoverContent="target (e.g., qemu, ridesx4)" />} fieldId="target">
                              <TextInput
                                id="target"
                                value={formData.target}
                                onChange={(_event, value) =>
                                  handleInputChange("target", value)
                                }
                                placeholder="Select or type a target platform..."
                                list="target-options"
                              />
                              <datalist id="target-options">
                                {TARGET_OPTIONS.map((option, index) => (
                                  <option key={index} value={option.value} title={option.label.split(' - ')[1]} />
                                ))}
                              </datalist>
                            </FormGroup>
                          </GridItem>

                          <GridItem xl={4} lg={6} md={12}>
                            <FormGroup label={<PopoverLabel label="Architecture" popoverContent="CPU architecture (arm64, amd64)" isRequired />} fieldId="architecture">
                              <TextInput
                                id="architecture"
                                value={formData.architecture}
                                onChange={(_event, value) =>
                                  handleInputChange("architecture", value)
                                }
                                placeholder="Select or type an architecture..."
                                list="architecture-options"
                                isRequired
                              />
                              <datalist id="architecture-options">
                                {ARCHITECTURE_OPTIONS.map((option, index) => (
                                  <option key={index} value={option.value} title={option.label.split(' - ')[1]} />
                                ))}
                              </datalist>
                            </FormGroup>
                          </GridItem>

                          <GridItem xl={6} lg={6} md={12}>
                            <FormGroup label={<PopoverLabel label="Export Format" popoverContent="format (e.g., image, qcow2)" />} fieldId="exportFormat">
                              <TextInput
                                id="exportFormat"
                                value={formData.exportFormat}
                                onChange={(_event, value) =>
                                  handleInputChange("exportFormat", value)
                                }
                                placeholder="Select or type an export format..."
                                list="export-format-options"
                              />
                              <datalist id="export-format-options">
                                {EXPORT_FORMAT_OPTIONS.map((option, index) => (
                                  <option key={index} value={option.value} title={option.label.split(' - ')[1]} />
                                ))}
                              </datalist>
                            </FormGroup>
                          </GridItem>

                          <GridItem xl={6} lg={6} md={12}>
                            <FormGroup label={<PopoverLabel label="Build Mode" popoverContent="Build mode (image, package)" />} fieldId="mode">
                              <TextInput
                                id="mode"
                                value={formData.mode}
                                onChange={(_event, value) =>
                                  handleInputChange("mode", value)
                                }
                                placeholder="Select or type a build mode..."
                                list="mode-options"
                              />
                              <datalist id="mode-options">
                                {BUILD_MODE_OPTIONS.map((option, index) => (
                                  <option key={index} value={option.value} />
                                ))}
                              </datalist>
                            </FormGroup>
                          </GridItem>

                          <GridItem xl={12} lg={12} md={12}>
                            <FormGroup
                              label={<PopoverLabel label="Automotive Image Builder Container" popoverContent="Container image used for building" />}
                              fieldId="automotiveImageBuilder"
                            >
                              <TextInput
                                id="automotiveImageBuilder"
                                value={formData.automotiveImageBuilder}
                                onChange={(_event, value) =>
                                  handleInputChange("automotiveImageBuilder", value)
                                }
                                placeholder="quay.io/centos-sig-automotive/automotive-image-builder:1.0.0"
                              />
                            </FormGroup>
                          </GridItem>
                          <GridItem span={12}>
                            <ExpandableSection
                              toggleText="Advanced Build Options"
                              isExpanded={isAdvancedOpen}
                              onToggle={(_event, expanded) =>
                                setIsAdvancedOpen(expanded as boolean)
                              }
                              style={{ overflow: "visible" }}
                            >
                              <Grid hasGutter style={{ paddingTop: "16px" }}>
                                  <GridItem span={6}>
                                    <FormGroup
                                      label={<PopoverLabel label="AIB Extra Arguments" popoverContent="Additional arguments for automotive-image-builder (e.g., --fusa, --define)" />}
                                      fieldId="aibExtraArgs"
                                    >
                                      <TextInput
                                        id="aibExtraArgs"
                                        value={formData.aibExtraArgs}
                                        onChange={(_event, value) =>
                                          handleInputChange("aibExtraArgs", value)
                                        }
                                        placeholder=""
                                      />
                                    </FormGroup>
                                  </GridItem>

                                  <GridItem span={6}>
                                    <FormGroup label={<PopoverLabel label="Compression" popoverContent="Compression algorithm for artifacts (lz4, gzip)" />} fieldId="compression">
                                      <TextInput
                                        id="compression"
                                        value={formData.compression || ""}
                                        onChange={(_event, value) =>
                                          handleInputChange("compression", value)
                                        }
                                        placeholder="lz4 or gzip"
                                        list="compression-options"
                                      />
                                      <datalist id="compression-options">
                                        <option value="lz4" />
                                        <option value="gzip" />
                                      </datalist>
                                    </FormGroup>
                                  </GridItem>

                                  <GridItem span={12}>
                                    <FormGroup
                                      label={<PopoverLabel label="Private Registry Authentication" popoverContent="Configure authentication for private container registries used during the build process" />}
                                      fieldId="registryCredentials"
                                    >
                                      <Checkbox
                                        id="enable-registry-auth"
                                        label="Enable private registry authentication"
                                        isChecked={formData.registryCredentials.enabled}
                                        onChange={(_event, checked) =>
                                          handleRegistryCredentialsChange("enabled", checked)
                                        }
                                      />
                                      {formData.registryCredentials.enabled && (
                                        <div style={{ marginTop: "16px", padding: "16px", border: "1px solid var(--pf-v5-global--BorderColor--100)", borderRadius: "4px" }}>
                                          <Stack hasGutter>
                                            <StackItem>
                                              <FormGroup label="Authentication Type" fieldId="authType">
                                                <div>
                                                  <Radio
                                                    id="auth-username-password"
                                                    name="authType"
                                                    label="Username & Password"
                                                    isChecked={formData.registryCredentials.authType === "username-password"}
                                                    onChange={() => handleRegistryCredentialsChange("authType", "username-password")}
                                                  />
                                                  <Radio
                                                    id="auth-token"
                                                    name="authType"
                                                    label="Token"
                                                    isChecked={formData.registryCredentials.authType === "token"}
                                                    onChange={() => handleRegistryCredentialsChange("authType", "token")}
                                                  />
                                                  <Radio
                                                    id="auth-docker-config"
                                                    name="authType"
                                                    label="Docker Config JSON"
                                                    isChecked={formData.registryCredentials.authType === "docker-config"}
                                                    onChange={() => handleRegistryCredentialsChange("authType", "docker-config")}
                                                  />
                                                </div>
                                              </FormGroup>
                                            </StackItem>

                                            {formData.registryCredentials.authType !== "docker-config" && (
                                              <StackItem>
                                                <FormGroup label="Registry URL" fieldId="registryUrl" isRequired>
                                                  <TextInput
                                                    id="registryUrl"
                                                    value={formData.registryCredentials.registryUrl}
                                                    onChange={(_event, value) =>
                                                      handleRegistryCredentialsChange("registryUrl", value)
                                                    }
                                                    placeholder="quay.io/my-org"
                                                    isRequired
                                                  />
                                                </FormGroup>
                                              </StackItem>
                                            )}

                                            {formData.registryCredentials.authType === "username-password" && (
                                              <>
                                                <StackItem>
                                                  <Grid hasGutter>
                                                    <GridItem span={6}>
                                                      <FormGroup label="Username" fieldId="username" isRequired>
                                                        <TextInput
                                                          id="username"
                                                          value={formData.registryCredentials.username}
                                                          onChange={(_event, value) =>
                                                            handleRegistryCredentialsChange("username", value)
                                                          }
                                                          placeholder="myusername"
                                                          isRequired
                                                        />
                                                      </FormGroup>
                                                    </GridItem>
                                                    <GridItem span={6}>
                                                      <FormGroup label="Password" fieldId="password" isRequired>
                                                        <TextInput
                                                          id="password"
                                                          type="password"
                                                          value={formData.registryCredentials.password}
                                                          onChange={(_event, value) =>
                                                            handleRegistryCredentialsChange("password", value)
                                                          }
                                                          placeholder="••••••••"
                                                          isRequired
                                                        />
                                                      </FormGroup>
                                                    </GridItem>
                                                  </Grid>
                                                </StackItem>
                                              </>
                                            )}

                                            {formData.registryCredentials.authType === "token" && (
                                              <StackItem>
                                                <FormGroup label="Token" fieldId="token" isRequired>
                                                  <TextInput
                                                    id="token"
                                                    type="password"
                                                    value={formData.registryCredentials.token}
                                                    onChange={(_event, value) =>
                                                      handleRegistryCredentialsChange("token", value)
                                                    }
                                                    placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                                                    isRequired
                                                  />
                                                </FormGroup>
                                              </StackItem>
                                            )}

                                            {formData.registryCredentials.authType === "docker-config" && (
                                              <StackItem>
                                                <FormGroup
                                                  label="Docker Config JSON"
                                                  fieldId="dockerConfig"
                                                  isRequired
                                                >
                                                  <TextArea
                                                    id="dockerConfig"
                                                    value={formData.registryCredentials.dockerConfig}
                                                    onChange={(_event, value) =>
                                                      handleRegistryCredentialsChange("dockerConfig", value)
                                                    }
                                                    placeholder='{"auths":{"registry.example.com":{"auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}}'
                                                    rows={6}
                                                    isRequired
                                                  />
                                                  <div style={{ fontSize: "0.875rem", color: "var(--pf-v5-global--Color--200)", marginTop: "4px" }}>
                                                    Paste the contents of your ~/.docker/config.json file
                                                  </div>
                                                </FormGroup>
                                              </StackItem>
                                            )}
                                          </Stack>
                                        </div>
                                      )}
                                    </FormGroup>
                                  </GridItem>
                              </Grid>
                            </ExpandableSection>
                          </GridItem>
                        </Grid>
                      </StackItem>
                    </Stack>
                  </CardBody>
                </Card>
              </StackItem>

              {/* Files Section */}
              <StackItem>
                <Card>
                  <CardBody>
                    <Stack hasGutter>
                      <StackItem>
                        <Split hasGutter>
                          <SplitItem>
                            <Title headingLevel="h2" size="lg">
                              Files
                            </Title>
                          </SplitItem>
                          <SplitItem isFilled />
                          <SplitItem>
                            <Flex spaceItems={{ default: "spaceItemsSm" }}>
                              {textFiles.length > 0 && (
                                <FlexItem>
                                  <Badge isRead>
                                    {textFiles.length} text file{textFiles.length !== 1 ? 's' : ''}
                                  </Badge>
                                </FlexItem>
                              )}
                              {uploadedFiles.length > 0 && (
                                <FlexItem>
                                  <Badge isRead>
                                    {uploadedFiles.length} uploaded file{uploadedFiles.length !== 1 ? 's' : ''}
                                  </Badge>
                                </FlexItem>
                              )}
                            </Flex>
                          </SplitItem>
                        </Split>
                      </StackItem>
                      <StackItem>
                        <p style={{ color: "var(--pf-v5-global--Color--200)", margin: 0 }}>
                          Upload files to include in your build, or create text files directly in the interface.
                        </p>
                      </StackItem>
                      {expectedFiles.length > 0 && (
                        <StackItem>
                          <Alert
                            variant="info"
                            title="Template expects these files"
                            isInline
                          >
                            <ul style={{ margin: "8px 0 0 0", paddingLeft: "20px" }}>
                              {expectedFiles.map((filename, index) => (
                                <li key={index} style={{ margin: "4px 0" }}>
                                  <code>{filename}</code>
                                </li>
                              ))}
                            </ul>
                            <p style={{ margin: "8px 0 0 0" }}>
                              Please upload or create these files to match the template configuration.
                            </p>
                          </Alert>
                        </StackItem>
                      )}
                      <StackItem>
                        <Card isPlain>
                          <CardBody>
                            <Stack hasGutter>
                              <StackItem>
                                <Title headingLevel="h3" size="md">
                                  Upload Files
                                </Title>
                              </StackItem>
                              <StackItem>
                                <FileUpload
                                  id="file-upload"
                                  type="dataURL"
                                  value=""
                                  filename=""
                                  filenamePlaceholder="Drag and drop files here or click to browse"
                                  onFileInputChange={(_event, file) => {
                                    if (file) {
                                      handleFileUpload(file);
                                    }
                                  }}
                                  browseButtonText="Browse files"
                                  clearButtonText="Clear"
                                />
                              </StackItem>
                            </Stack>
                          </CardBody>
                        </Card>
                      </StackItem>
                      <StackItem>
                        <Split hasGutter>
                          <SplitItem>
                            <p style={{ color: "var(--pf-v5-global--Color--200)", margin: 0, fontSize: "0.875rem" }}>
                              Or create text files directly in the interface:
                            </p>
                          </SplitItem>
                          <SplitItem isFilled />
                          <SplitItem>
                            <Button
                              variant="link"
                              size="sm"
                              onClick={addTextFile}
                              icon={<PlusCircleIcon />}
                            >
                              Add Text File
                            </Button>
                          </SplitItem>
                        </Split>
                      </StackItem>

                      {textFiles.length > 0 && (
                        <StackItem>
                          <Stack hasGutter>
                            <StackItem>
                              <Title headingLevel="h3" size="md">
                                Text Files
                              </Title>
                            </StackItem>
                            <StackItem>
                              <Stack hasGutter>
                                {textFiles.map((file) => (
                                  <StackItem key={file.id}>
                                    <Card>
                                      <CardBody>
                                        <Stack hasGutter>
                                          <StackItem>
                                            <Split hasGutter>
                                              <SplitItem isFilled>
                                                <FormGroup label="File Name" fieldId={`filename-${file.id}`}>
                                                  <TextInput
                                                    id={`filename-${file.id}`}
                                                    value={file.name}
                                                    onChange={(_event, value) => updateTextFile(file.id, "name", value)}
                                                    placeholder="Enter file name"
                                                  />
                                                </FormGroup>
                                              </SplitItem>
                                              <SplitItem>
                                                <Button
                                                  variant="danger"
                                                  size="sm"
                                                  onClick={() => removeTextFile(file.id)}
                                                  icon={<TrashIcon />}
                                                  style={{ marginTop: "24px" }}
                                                >
                                                  Remove
                                                </Button>
                                              </SplitItem>
                                            </Split>
                                          </StackItem>
                                          <StackItem>
                                            <FormGroup label="File Content" fieldId={`content-${file.id}`}>
                                              <TextArea
                                                id={`content-${file.id}`}
                                                value={file.content}
                                                onChange={(_event, value) => updateTextFile(file.id, "content", value)}
                                                placeholder="Enter file content"
                                                rows={8}
                                              />
                                            </FormGroup>
                                          </StackItem>
                                        </Stack>
                                      </CardBody>
                                    </Card>
                                  </StackItem>
                                ))}
                              </Stack>
                            </StackItem>
                          </Stack>
                        </StackItem>
                      )}

                      {uploadedFiles.length > 0 && (
                        <StackItem>
                          <Stack hasGutter>
                            <StackItem>
                              <Title headingLevel="h3" size="md">
                                Uploaded Files
                              </Title>
                            </StackItem>
                            <StackItem>
                              <Stack hasGutter>
                                {uploadedFiles.map((file) => (
                                  <StackItem key={file.id}>
                                    <Card isPlain>
                                      <CardBody>
                                        <Split hasGutter>
                                          <SplitItem isFilled>
                                            <Flex direction={{ default: "column" }}>
                                              <FlexItem>
                                                <strong>{file.name}</strong>
                                              </FlexItem>
                                              <FlexItem>
                                                <small>
                                                  Size: {(file.file.size / 1024).toFixed(1)} KB
                                                </small>
                                              </FlexItem>
                                            </Flex>
                                          </SplitItem>
                                          <SplitItem>
                                            <Button
                                              variant="plain"
                                              size="sm"
                                              onClick={() => removeUploadedFile(file.id)}
                                              icon={<TrashIcon />}
                                              aria-label="Remove file"
                                            />
                                          </SplitItem>
                                        </Split>
                                      </CardBody>
                                    </Card>
                                  </StackItem>
                                ))}
                              </Stack>
                            </StackItem>
                          </Stack>
                        </StackItem>
                      )}
                    </Stack>
                  </CardBody>
                </Card>
              </StackItem>

              <StackItem>
                <Card>
                  <CardBody>
                    <Split hasGutter>
                      <SplitItem>
                        <Button
                          variant="primary"
                          type="submit"
                          size="lg"
                          isLoading={isSubmitting}
                          isDisabled={!formData.name || !formData.manifest || !formData.architecture}
                        >
                          {isSubmitting ? "Creating Build..." : "Create Build"}
                        </Button>
                      </SplitItem>
                      <SplitItem>
                        <Button variant="link" onClick={() => navigate("/builds")}>
                          Cancel
                        </Button>
                      </SplitItem>
                      <SplitItem isFilled />
                      {(!formData.name || (!formData.manifest && formData.name) || (!formData.architecture && formData.name && formData.manifest)) && (
                        <SplitItem>
                          <Alert
                            variant="warning"
                            title={
                              !formData.name 
                                ? "Build name required"
                                : !formData.manifest && formData.name
                                  ? "Manifest content required"
                                  : "Architecture required"
                            }
                            isInline
                            isPlain
                          />
                        </SplitItem>
                      )}
                    </Split>
                  </CardBody>
                </Card>
              </StackItem>
            </Stack>
          </Form>
        </StackItem>
      </Stack>
    </PageSection>
    <Modal
      variant={ModalVariant.small}
      title="Redirecting"
      isOpen={isRedirecting}
      onClose={() => {}}
    >
      <Bullseye style={{ height: '120px' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Spinner size="lg" />
          <span style={{ marginLeft: 12 }}>Submitting build...</span>
        </div>
      </Bullseye>
    </Modal>
    </>
  );
};

export default CreateBuildPage;
