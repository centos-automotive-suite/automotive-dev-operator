export type Distro = string;
export type Target = string;
export type Architecture = string;
export type ExportFormat = string;
export type BuildMode = 'bootc' | 'image' | 'package' | 'disk';

export interface RegistryCredentials {
  enabled: boolean;
  authType: 'username-password' | 'token' | 'docker-config';
  registryUrl: string;
  username?: string;
  password?: string;
  token?: string;
  dockerConfig?: string;
}

export interface BuildRequest {
  name: string;
  manifest?: string;
  manifestFileName?: string;
  containerRef?: string;
  distro: Distro;
  target: Target;
  architecture: Architecture;
  exportFormat: ExportFormat;
  mode: BuildMode;
  automotiveImageBuilder?: string;
  storageClass?: string;
  customDefs?: string[];
  aibExtraArgs?: string[];
  aibOverrideArgs?: string[];
  serveArtifact?: boolean;
  compression?: 'gzip' | 'lz4';
  registryCredentials?: RegistryCredentials;
  pushRepository?: string;
  containerPush?: string;
  buildDiskImage?: boolean;
  exportOci?: string;
  builderImage?: string;
}

export interface BuildResponse {
  name: string;
  phase: string;
  message: string;
  requestedBy?: string;
  artifactURL?: string;
  artifactFileName?: string;
  startTime?: string;
  completionTime?: string;
}

export interface BuildListItem {
  name: string;
  phase: string;
  message: string;
  requestedBy?: string;
  createdAt: string;
  startTime?: string;
  completionTime?: string;
}

export interface BuildTemplateResponse extends BuildRequest {
  sourceFiles?: string[];
}

export interface ArtifactItem {
  name: string;
  sizeBytes: string;
}

export interface ArtifactsListResponse {
  items: ArtifactItem[];
}

export type BuildPhase = 'Pending' | 'Uploading' | 'Building' | 'Pushing' | 'Completed' | 'Failed';

export const DISTROS = ['autosd', 'autosd10', 'autosd10-latest-sig', 'autosd10-sig', 'autosd9', 'autosd9-latest-sig', 'autosd9-sig', 'cs9', 'eln', 'f40', 'f41', 'rhivos', 'rhivos1', 'rhivos2'] as const;
export const TARGETS = ['abootqemu', 'abootqemukvm', 'acrn', 'am62sk', 'am69sk', 'aws', 'azure', 'beagleplay', 'ccimx93dvk', 'ebbr', 'imx8qxp_mek', 'j784s4evm', 'pc', 'qdrive3', 'qemu', 'rcar_s4', 'rcar_s4_can', 'ridesx4', 'ridesx4_r3', 'ridesx4_scmi', 'ridesx4_scmi_r3', 'rpi4', 's32g_vnp_rdb3', 'tda4vm_sk'] as const;
export const ARCHITECTURES = ['x86_64', 'aarch64'] as const;
export const EXPORT_FORMATS = ['raw', 'qcow2', 'simg'] as const;
export const BUILD_MODES: BuildMode[] = ['bootc', 'image', 'package', 'disk'];
