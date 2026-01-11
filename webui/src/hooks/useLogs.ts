import * as React from 'react';
import { streamLogs } from '../api/buildApi';

interface UseLogsResult {
  logs: string;
  loading: boolean;
  error: Error | null;
  isStreaming: boolean;
}

export function useLogs(buildName: string, enabled = true): UseLogsResult {
  const [logs, setLogs] = React.useState('');
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<Error | null>(null);
  const [isStreaming, setIsStreaming] = React.useState(false);

  React.useEffect(() => {
    if (!buildName || !enabled) {
      setLoading(false);
      return;
    }

    const controller = new AbortController();
    setIsStreaming(true);
    setLogs('');
    setError(null);

    streamLogs(
      buildName,
      (chunk) => {
        setLogs((prev) => prev + chunk);
        setLoading(false);
      },
      controller.signal,
    )
      .catch((err) => {
        if (err.name !== 'AbortError') {
          setError(err instanceof Error ? err : new Error(String(err)));
        }
      })
      .finally(() => {
        setIsStreaming(false);
        setLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [buildName, enabled]);

  return { logs, loading, error, isStreaming };
}
