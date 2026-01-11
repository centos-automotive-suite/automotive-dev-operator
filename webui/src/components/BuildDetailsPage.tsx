import * as React from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams, useHistory } from 'react-router-dom';
import {
  PageSection,
  Title,
  Tabs,
  Tab,
  TabTitleText,
  Card,
  CardBody,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  Label,
  Spinner,
  Bullseye,
  Alert,
  Button,
  Split,
  SplitItem,
  Breadcrumb,
  BreadcrumbItem,
  CodeBlock,
  CodeBlockCode,
  EmptyState,
  EmptyStateBody,
} from '@patternfly/react-core';
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';
import {
  CheckCircleIcon,
  ExclamationCircleIcon,
  InProgressIcon,
  PendingIcon,
  DownloadIcon,
  ArrowLeftIcon,
  CubesIcon,
} from '@patternfly/react-icons';
import { useBuild, useArtifacts } from '../hooks/useBuilds';
import { useLogs } from '../hooks/useLogs';
import { getArtifactDownloadUrl, getArtifactPartDownloadUrl } from '../api/buildApi';
import { BuildPhase } from '../api/types';
import './BuildDetailsPage.css';

const PHASE_LABELS: Record<BuildPhase, { color: 'green' | 'red' | 'blue' | 'grey'; icon: React.ReactNode }> = {
  Pending: { color: 'grey', icon: <PendingIcon /> },
  Uploading: { color: 'blue', icon: <InProgressIcon /> },
  Building: { color: 'blue', icon: <InProgressIcon /> },
  Pushing: { color: 'blue', icon: <InProgressIcon /> },
  Completed: { color: 'green', icon: <CheckCircleIcon /> },
  Failed: { color: 'red', icon: <ExclamationCircleIcon /> },
};

function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return '-';
  try {
    return new Date(dateStr).toLocaleString();
  } catch {
    return dateStr;
  }
}

function formatBytes(bytes: string | number): string {
  const numBytes = typeof bytes === 'string' ? parseInt(bytes, 10) : bytes;
  if (isNaN(numBytes)) return bytes.toString();
  if (numBytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(numBytes) / Math.log(k));
  return parseFloat((numBytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function PhaseLabel({ phase }: { phase: string }): React.ReactElement {
  const phaseConfig = PHASE_LABELS[phase as BuildPhase] || { color: 'grey', icon: null };
  return (
    <Label color={phaseConfig.color} icon={phaseConfig.icon}>
      {phase}
    </Label>
  );
}

function DetailsTab({ build }: { build: NonNullable<ReturnType<typeof useBuild>['build']> }): React.ReactElement {
  const { t } = useTranslation('plugin__automotive-dev-console-plugin');

  return (
    <Card>
      <CardBody>
        <DescriptionList columnModifier={{ default: '2Col' }}>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Name')}</DescriptionListTerm>
            <DescriptionListDescription>{build.name}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Status')}</DescriptionListTerm>
            <DescriptionListDescription>
              <PhaseLabel phase={build.phase} />
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Message')}</DescriptionListTerm>
            <DescriptionListDescription>{build.message || '-'}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Requested By')}</DescriptionListTerm>
            <DescriptionListDescription>{build.requestedBy || '-'}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Start Time')}</DescriptionListTerm>
            <DescriptionListDescription>{formatDate(build.startTime)}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Completion Time')}</DescriptionListTerm>
            <DescriptionListDescription>{formatDate(build.completionTime)}</DescriptionListDescription>
          </DescriptionListGroup>
          {build.artifactFileName && (
            <DescriptionListGroup>
              <DescriptionListTerm>{t('Artifact')}</DescriptionListTerm>
              <DescriptionListDescription>{build.artifactFileName}</DescriptionListDescription>
            </DescriptionListGroup>
          )}
          {build.artifactURL && (
            <DescriptionListGroup>
              <DescriptionListTerm>{t('Artifact URL')}</DescriptionListTerm>
              <DescriptionListDescription>
                <a href={build.artifactURL} target="_blank" rel="noopener noreferrer">
                  {build.artifactURL}
                </a>
              </DescriptionListDescription>
            </DescriptionListGroup>
          )}
        </DescriptionList>
      </CardBody>
    </Card>
  );
}

function LogsTab({ buildName, phase }: { buildName: string; phase: string }): React.ReactElement {
  const { t } = useTranslation('plugin__automotive-dev-console-plugin');
  const logsEndRef = React.useRef<HTMLDivElement>(null);
  const shouldStreamLogs = phase !== 'Pending';
  const { logs, loading, error, isStreaming } = useLogs(buildName, shouldStreamLogs);

  React.useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  if (phase === 'Pending') {
    return (
      <EmptyState
        titleText={t('Waiting for build to start')}
        headingLevel="h4"
        icon={PendingIcon}
      >
        <EmptyStateBody>
          {t('Logs will be available once the build starts.')}
        </EmptyStateBody>
      </EmptyState>
    );
  }

  if (loading && !logs) {
    return (
      <Bullseye>
        <Spinner size="lg" />
      </Bullseye>
    );
  }

  if (error) {
    return (
      <Alert variant="danger" title={t('Error loading logs')} isInline>
        {error.message}
      </Alert>
    );
  }

  return (
    <div className="automotive-dev__logs-container">
      {isStreaming && (
        <Alert variant="info" title={t('Streaming logs...')} isInline className="automotive-dev__logs-alert" />
      )}
      <CodeBlock className="automotive-dev__logs-block">
        <CodeBlockCode>
          {logs || t('No logs available yet.')}
        </CodeBlockCode>
      </CodeBlock>
      <div ref={logsEndRef} />
    </div>
  );
}

function ArtifactsTab({ buildName, phase }: { buildName: string; phase: string }): React.ReactElement {
  const { t } = useTranslation('plugin__automotive-dev-console-plugin');
  const { artifacts, loading, error } = useArtifacts(buildName);

  if (phase !== 'Completed') {
    return (
      <EmptyState
        titleText={t('Artifacts not available')}
        headingLevel="h4"
        icon={CubesIcon}
      >
        <EmptyStateBody>
          {t('Artifacts will be available after the build completes successfully.')}
        </EmptyStateBody>
      </EmptyState>
    );
  }

  if (loading) {
    return (
      <Bullseye>
        <Spinner size="lg" />
      </Bullseye>
    );
  }

  if (error) {
    return (
      <Alert variant="danger" title={t('Error loading artifacts')} isInline>
        {error.message}
      </Alert>
    );
  }

  const hasArtifactParts = artifacts?.items && artifacts.items.length > 0;

  return (
    <Card>
      <CardBody>
        <Split hasGutter>
          <SplitItem>
            <Button
              variant="primary"
              icon={<DownloadIcon />}
              component="a"
              href={getArtifactDownloadUrl(buildName)}
              target="_blank"
            >
              {t('Download Artifact')}
            </Button>
          </SplitItem>
        </Split>

        {hasArtifactParts && (
          <>
            <Title headingLevel="h4" className="automotive-dev__artifacts-title">
              {t('Artifact Parts')}
            </Title>
            <Table aria-label={t('Artifact parts table')} variant="compact">
              <Thead>
                <Tr>
                  <Th>{t('File Name')}</Th>
                  <Th>{t('Size')}</Th>
                  <Th>{t('Actions')}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {artifacts.items.map((item) => (
                  <Tr key={item.name}>
                    <Td dataLabel={t('File Name')}>{item.name}</Td>
                    <Td dataLabel={t('Size')}>{formatBytes(item.sizeBytes)}</Td>
                    <Td dataLabel={t('Actions')}>
                      <Button
                        variant="link"
                        icon={<DownloadIcon />}
                        component="a"
                        href={getArtifactPartDownloadUrl(buildName, item.name)}
                        target="_blank"
                      >
                        {t('Download')}
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </>
        )}
      </CardBody>
    </Card>
  );
}

export default function BuildDetailsPage(): React.ReactElement {
  const { t } = useTranslation('plugin__automotive-dev-console-plugin');
  const history = useHistory();
  const { name } = useParams<{ name: string }>();
  const [activeTab, setActiveTab] = React.useState<string | number>('details');
  const { build, loading, error } = useBuild(name);

  if (loading && !build) {
    return (
      <Bullseye>
        <Spinner size="xl" />
      </Bullseye>
    );
  }

  if (error) {
    return (
      <PageSection>
        <Alert variant="danger" title={t('Error loading build')}>
          {error.message}
        </Alert>
      </PageSection>
    );
  }

  if (!build) {
    return (
      <PageSection>
        <Alert variant="warning" title={t('Build not found')}>
          {t('The requested build could not be found.')}
        </Alert>
      </PageSection>
    );
  }

  return (
    <>
      <PageSection>
        <Breadcrumb>
          <BreadcrumbItem>
            <Link to="/automotive-dev/builds">{t('Image Builds')}</Link>
          </BreadcrumbItem>
          <BreadcrumbItem isActive>{build.name}</BreadcrumbItem>
        </Breadcrumb>
        <Split hasGutter className="automotive-dev__details-header">
          <SplitItem>
            <Button
              variant="link"
              icon={<ArrowLeftIcon />}
              onClick={() => history.push('/automotive-dev/builds')}
            >
              {t('Back')}
            </Button>
          </SplitItem>
          <SplitItem isFilled>
            <Title headingLevel="h1">
              {build.name} <PhaseLabel phase={build.phase} />
            </Title>
          </SplitItem>
        </Split>
      </PageSection>
      <PageSection>
        <Tabs activeKey={activeTab} onSelect={(_, key) => setActiveTab(key)}>
          <Tab eventKey="details" title={<TabTitleText>{t('Details')}</TabTitleText>}>
            <div className="automotive-dev__tab-content">
              <DetailsTab build={build} />
            </div>
          </Tab>
          <Tab eventKey="logs" title={<TabTitleText>{t('Logs')}</TabTitleText>}>
            <div className="automotive-dev__tab-content">
              <LogsTab buildName={build.name} phase={build.phase} />
            </div>
          </Tab>
          <Tab eventKey="artifacts" title={<TabTitleText>{t('Artifacts')}</TabTitleText>}>
            <div className="automotive-dev__tab-content">
              <ArtifactsTab buildName={build.name} phase={build.phase} />
            </div>
          </Tab>
        </Tabs>
      </PageSection>
    </>
  );
}
