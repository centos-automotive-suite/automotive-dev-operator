import * as React from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useHistory } from 'react-router-dom';
import {
  PageSection,
  Title,
  Button,
  EmptyState,
  EmptyStateBody,
  Spinner,
  Label,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Alert,
  Bullseye,
  EmptyStateActions,
  EmptyStateFooter,
} from '@patternfly/react-core';
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';
import {
  CubesIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  InProgressIcon,
  PendingIcon,
  PlusCircleIcon,
  SyncAltIcon,
} from '@patternfly/react-icons';
import { useBuilds } from '../hooks/useBuilds';
import { BuildListItem, BuildPhase } from '../api/types';
import './BuildListPage.css';

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

function PhaseLabel({ phase }: { phase: string }): React.ReactElement {
  const phaseConfig = PHASE_LABELS[phase as BuildPhase] || { color: 'grey', icon: null };
  return (
    <Label color={phaseConfig.color} icon={phaseConfig.icon}>
      {phase}
    </Label>
  );
}

export default function BuildListPage(): React.ReactElement {
  const { t } = useTranslation('plugin__automotive-dev-console-plugin');
  const history = useHistory();
  const { builds, loading, error, refresh } = useBuilds();

  const handleRowClick = (build: BuildListItem) => {
    history.push(`/automotive-dev/builds/${build.name}`);
  };

  if (loading && builds.length === 0) {
    return (
      <Bullseye>
        <Spinner size="xl" />
      </Bullseye>
    );
  }

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">{t('Image Builds')}</Title>
      </PageSection>
      <PageSection>
        {error && (
          <Alert variant="danger" title={t('Error loading builds')} isInline>
            {error.message}
          </Alert>
        )}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Button
                variant="primary"
                component={(props) => <Link {...props} to="/automotive-dev/builds/~new" />}
                icon={<PlusCircleIcon />}
              >
                {t('Create Build')}
              </Button>
            </ToolbarItem>
            <ToolbarItem>
              <Button variant="plain" onClick={refresh} icon={<SyncAltIcon />}>
                {t('Refresh')}
              </Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>

        {builds.length === 0 ? (
          <EmptyState
            titleText={t('No builds found')}
            headingLevel="h4"
            icon={CubesIcon}
          >
            <EmptyStateBody>
              {t('Create an image build to get started with automotive OS images.')}
            </EmptyStateBody>
            <EmptyStateFooter>
              <EmptyStateActions>
                <Button
                  variant="primary"
                  component={(props) => <Link {...props} to="/automotive-dev/builds/~new" />}
                >
                  {t('Create Build')}
                </Button>
              </EmptyStateActions>
            </EmptyStateFooter>
          </EmptyState>
        ) : (
          <Table aria-label={t('Image builds table')} variant="compact">
            <Thead>
              <Tr>
                <Th>{t('Name')}</Th>
                <Th>{t('Status')}</Th>
                <Th>{t('Message')}</Th>
                <Th>{t('Created')}</Th>
                <Th>{t('Started')}</Th>
                <Th>{t('Completed')}</Th>
                <Th>{t('Requested By')}</Th>
              </Tr>
            </Thead>
            <Tbody>
              {builds.map((build) => (
                <Tr
                  key={build.name}
                  isClickable
                  onRowClick={() => handleRowClick(build)}
                  className="automotive-dev__build-row"
                >
                  <Td dataLabel={t('Name')}>
                    <Link to={`/automotive-dev/builds/${build.name}`}>{build.name}</Link>
                  </Td>
                  <Td dataLabel={t('Status')}>
                    <PhaseLabel phase={build.phase} />
                  </Td>
                  <Td dataLabel={t('Message')}>{build.message || '-'}</Td>
                  <Td dataLabel={t('Created')}>{formatDate(build.createdAt)}</Td>
                  <Td dataLabel={t('Started')}>{formatDate(build.startTime)}</Td>
                  <Td dataLabel={t('Completed')}>{formatDate(build.completionTime)}</Td>
                  <Td dataLabel={t('Requested By')}>{build.requestedBy || '-'}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </PageSection>
    </>
  );
}
