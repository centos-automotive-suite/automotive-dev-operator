import { consoleFetchJSON, consoleFetchText } from '@openshift-console/dynamic-plugin-sdk';
import {
  BuildRequest,
  BuildResponse,
  BuildListItem,
  BuildTemplateResponse,
  ArtifactsListResponse,
} from './types';

const API_BASE = '/api/proxy/plugin/automotive-dev-console-plugin/build-api/v1';

export async function listBuilds(): Promise<BuildListItem[]> {
  return consoleFetchJSON(`${API_BASE}/builds`);
}

export async function getBuild(name: string): Promise<BuildResponse> {
  return consoleFetchJSON(`${API_BASE}/builds/${encodeURIComponent(name)}`);
}

export async function createBuild(request: BuildRequest): Promise<BuildResponse> {
  const response = await fetch(`${API_BASE}/builds`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(error.error || response.statusText);
  }
  return response.json();
}

export async function getBuildTemplate(name: string): Promise<BuildTemplateResponse> {
  return consoleFetchJSON(`${API_BASE}/builds/${encodeURIComponent(name)}/template`);
}

export async function listArtifacts(name: string): Promise<ArtifactsListResponse> {
  return consoleFetchJSON(`${API_BASE}/builds/${encodeURIComponent(name)}/artifacts`);
}

export function getArtifactDownloadUrl(buildName: string): string {
  return `${API_BASE}/builds/${encodeURIComponent(buildName)}/artifact`;
}

export function getArtifactPartDownloadUrl(buildName: string, fileName: string): string {
  return `${API_BASE}/builds/${encodeURIComponent(buildName)}/artifacts/${encodeURIComponent(fileName)}`;
}

export async function streamLogs(
  name: string,
  onChunk: (text: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const url = `${API_BASE}/builds/${encodeURIComponent(name)}/logs`;
  const response = await consoleFetchText(url);

  if (typeof response === 'string') {
    onChunk(response);
    return;
  }

  const reader = (response as Response).body?.getReader();
  if (!reader) {
    throw new Error('Failed to get response reader');
  }

  const decoder = new TextDecoder();
  try {
    while (true) {
      if (signal?.aborted) break;
      const { done, value } = await reader.read();
      if (done) break;
      onChunk(decoder.decode(value, { stream: true }));
    }
  } finally {
    reader.releaseLock();
  }
}

export async function uploadFiles(name: string, files: File[]): Promise<void> {
  const formData = new FormData();
  files.forEach((file) => {
    formData.append('file', file, file.name);
  });

  const response = await fetch(`${API_BASE}/builds/${encodeURIComponent(name)}/uploads`, {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(error.error || response.statusText);
  }
}
