import * as React from 'react';
import { listBuilds, getBuild, getBuildTemplate, listArtifacts } from '../api/buildApi';
import {
  BuildListItem,
  BuildResponse,
  BuildTemplateResponse,
  ArtifactsListResponse,
} from '../api/types';

interface UseBuildsResult {
  builds: BuildListItem[];
  loading: boolean;
  error: Error | null;
  refresh: () => void;
}

export function useBuilds(pollingInterval = 5000): UseBuildsResult {
  const [builds, setBuilds] = React.useState<BuildListItem[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<Error | null>(null);

  const fetchBuilds = React.useCallback(async () => {
    try {
      const data = await listBuilds();
      setBuilds(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    fetchBuilds();
    const interval = setInterval(fetchBuilds, pollingInterval);
    return () => clearInterval(interval);
  }, [fetchBuilds, pollingInterval]);

  return { builds, loading, error, refresh: fetchBuilds };
}

interface UseBuildResult {
  build: BuildResponse | null;
  loading: boolean;
  error: Error | null;
  refresh: () => void;
}

export function useBuild(name: string, pollingInterval = 3000): UseBuildResult {
  const [build, setBuild] = React.useState<BuildResponse | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<Error | null>(null);

  const fetchBuild = React.useCallback(async () => {
    if (!name) return;
    try {
      const data = await getBuild(name);
      setBuild(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [name]);

  React.useEffect(() => {
    fetchBuild();
    const shouldPoll = build?.phase !== 'Completed' && build?.phase !== 'Failed';
    if (shouldPoll || loading) {
      const interval = setInterval(fetchBuild, pollingInterval);
      return () => clearInterval(interval);
    }
  }, [fetchBuild, pollingInterval, build?.phase, loading]);

  return { build, loading, error, refresh: fetchBuild };
}

interface UseBuildTemplateResult {
  template: BuildTemplateResponse | null;
  loading: boolean;
  error: Error | null;
}

export function useBuildTemplate(name: string): UseBuildTemplateResult {
  const [template, setTemplate] = React.useState<BuildTemplateResponse | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<Error | null>(null);

  React.useEffect(() => {
    if (!name) return;
    getBuildTemplate(name)
      .then((data) => {
        setTemplate(data);
        setError(null);
      })
      .catch((err) => {
        setError(err instanceof Error ? err : new Error(String(err)));
      })
      .finally(() => {
        setLoading(false);
      });
  }, [name]);

  return { template, loading, error };
}

interface UseArtifactsResult {
  artifacts: ArtifactsListResponse | null;
  loading: boolean;
  error: Error | null;
  refresh: () => void;
}

export function useArtifacts(name: string): UseArtifactsResult {
  const [artifacts, setArtifacts] = React.useState<ArtifactsListResponse | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<Error | null>(null);

  const fetchArtifacts = React.useCallback(async () => {
    if (!name) return;
    try {
      const data = await listArtifacts(name);
      setArtifacts(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [name]);

  React.useEffect(() => {
    fetchArtifacts();
  }, [fetchArtifacts]);

  return { artifacts, loading, error, refresh: fetchArtifacts };
}
