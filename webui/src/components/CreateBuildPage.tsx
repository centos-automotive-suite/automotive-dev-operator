import * as React from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useHistory } from 'react-router-dom';
import {
  PageSection,
  Title,
  Form,
  FormGroup,
  TextInput,
  TextArea,
  FormSelect,
  FormSelectOption,
  Switch,
  Button,
  ActionGroup,
  Alert,
  Card,
  CardBody,
  Breadcrumb,
  BreadcrumbItem,
  ExpandableSection,
  FormHelperText,
  HelperText,
  HelperTextItem,
  Split,
  SplitItem,
} from '@patternfly/react-core';
import { createBuild } from '../api/buildApi';
import {
  BuildRequest,
  BuildMode,
  DISTROS,
  TARGETS,
  ARCHITECTURES,
  EXPORT_FORMATS,
  BUILD_MODES,
} from '../api/types';
import './CreateBuildPage.css';

const DEFAULT_MANIFEST = ``;

export default function CreateBuildPage(): React.ReactElement {
  const { t } = useTranslation('plugin__automotive-dev-console-plugin');
  const history = useHistory();

  const [name, setName] = React.useState('');
  const [mode, setMode] = React.useState<BuildMode>('bootc');
  const [distro, setDistro] = React.useState('cs9');
  const [target, setTarget] = React.useState('qemu');
  const [architecture, setArchitecture] = React.useState('aarch64');
  const [exportFormat, setExportFormat] = React.useState('image');
  const [manifest, setManifest] = React.useState(DEFAULT_MANIFEST);
  const [containerRef, setContainerRef] = React.useState('');
  const [serveArtifact, _setServeArtifact] = React.useState(true);
  const [compression, setCompression] = React.useState<'gzip' | 'lz4'>('gzip');

  // Advanced options
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [storageClass, setStorageClass] = React.useState('');
  const [containerPush, setContainerPush] = React.useState('');
  const [buildDiskImage, setBuildDiskImage] = React.useState(false);
  const [exportOci, setExportOci] = React.useState('');

  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    const request: BuildRequest = {
      name,
      mode,
      distro,
      target,
      architecture,
      exportFormat,
      serveArtifact,
      compression,
    };

    if (mode === 'disk') {
      request.containerRef = containerRef;
    } else {
      request.manifest = manifest;
    }

    if (storageClass) {
      request.storageClass = storageClass;
    }
    if (containerPush) {
      request.containerPush = containerPush;
    }
    if (buildDiskImage) {
      request.buildDiskImage = buildDiskImage;
    }
    if (exportOci) {
      request.exportOci = exportOci;
    }

    try {
      await createBuild(request);
      history.push(`/automotive-dev/builds/${name}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  };

  const isDiskMode = mode === 'disk';

  return (
    <>
      <PageSection>
        <Breadcrumb>
          <BreadcrumbItem>
            <Link to="/automotive-dev/builds">{t('Image Builds')}</Link>
          </BreadcrumbItem>
          <BreadcrumbItem isActive>{t('Create Build')}</BreadcrumbItem>
        </Breadcrumb>
        <Title headingLevel="h1" className="automotive-dev__create-title">
          {t('Create Image Build')}
        </Title>
      </PageSection>
      <PageSection>
        <Card>
          <CardBody>
            {error && (
              <Alert variant="danger" title={t('Error creating build')} isInline className="automotive-dev__form-error">
                {error}
              </Alert>
            )}
            <Form onSubmit={handleSubmit}>
              <FormGroup label={t('Build Name')} isRequired fieldId="build-name">
                <TextInput
                  id="build-name"
                  value={name}
                  onChange={(_, value) => setName(value)}
                  isRequired
                  placeholder={t('my-build')}
                />
                <FormHelperText>
                  <HelperText>
                    <HelperTextItem>{t('A unique name for this build. Use lowercase letters, numbers, and hyphens.')}</HelperTextItem>
                  </HelperText>
                </FormHelperText>
              </FormGroup>

              <FormGroup label={t('Build Mode')} isRequired fieldId="build-mode">
                <FormSelect
                  id="build-mode"
                  value={mode}
                  onChange={(_, value) => setMode(value as BuildMode)}
                >
                  {BUILD_MODES.map((m) => (
                    <FormSelectOption key={m} value={m} label={t(getModeLabel(m))} />
                  ))}
                </FormSelect>
                <FormHelperText>
                  <HelperText>
                    <HelperTextItem>{t(getModeDescription(mode))}</HelperTextItem>
                  </HelperText>
                </FormHelperText>
              </FormGroup>

              <Split hasGutter>
                <SplitItem isFilled>
                  <FormGroup label={t('Distribution')} isRequired fieldId="distro">
                    <FormSelect
                      id="distro"
                      value={distro}
                      onChange={(_, value) => setDistro(value)}
                    >
                      {DISTROS.map((d) => (
                        <FormSelectOption key={d} value={d} label={d} />
                      ))}
                    </FormSelect>
                  </FormGroup>
                </SplitItem>
                <SplitItem isFilled>
                  <FormGroup label={t('Target')} isRequired fieldId="target">
                    <FormSelect
                      id="target"
                      value={target}
                      onChange={(_, value) => setTarget(value)}
                    >
                      {TARGETS.map((tgt) => (
                        <FormSelectOption key={tgt} value={tgt} label={tgt} />
                      ))}
                    </FormSelect>
                  </FormGroup>
                </SplitItem>
              </Split>

              <Split hasGutter>
                <SplitItem isFilled>
                  <FormGroup label={t('Architecture')} isRequired fieldId="architecture">
                    <FormSelect
                      id="architecture"
                      value={architecture}
                      onChange={(_, value) => setArchitecture(value)}
                    >
                      {ARCHITECTURES.map((arch) => (
                        <FormSelectOption key={arch} value={arch} label={arch} />
                      ))}
                    </FormSelect>
                  </FormGroup>
                </SplitItem>
                <SplitItem isFilled>
                  <FormGroup label={t('Export Format')} isRequired fieldId="export-format">
                    <FormSelect
                      id="export-format"
                      value={exportFormat}
                      onChange={(_, value) => setExportFormat(value)}
                    >
                      {EXPORT_FORMATS.map((fmt) => (
                        <FormSelectOption key={fmt} value={fmt} label={fmt} />
                      ))}
                    </FormSelect>
                  </FormGroup>
                </SplitItem>
              </Split>

              {isDiskMode ? (
                <FormGroup label={t('Container Reference')} isRequired fieldId="container-ref">
                  <TextInput
                    id="container-ref"
                    value={containerRef}
                    onChange={(_, value) => setContainerRef(value)}
                    isRequired
                    placeholder={t('quay.io/my-org/my-bootc-image:latest')}
                  />
                  <FormHelperText>
                    <HelperText>
                      <HelperTextItem>{t('The bootc container image to convert to a disk image.')}</HelperTextItem>
                    </HelperText>
                  </FormHelperText>
                </FormGroup>
              ) : (
                <FormGroup label={t('Manifest')} isRequired fieldId="manifest">
                  <TextArea
                    id="manifest"
                    value={manifest}
                    onChange={(_, value) => setManifest(value)}
                    isRequired
                    rows={15}
                    className="automotive-dev__manifest-input"
                  />
                  <FormHelperText>
                    <HelperText>
                      <HelperTextItem>{t('The AIB manifest YAML that defines the image configuration.')}</HelperTextItem>
                    </HelperText>
                  </FormHelperText>
                </FormGroup>
              )}

              <Split hasGutter>
                <SplitItem>
                  <FormGroup label={t('Compression')} fieldId="compression">
                    <FormSelect
                      id="compression"
                      value={compression}
                      onChange={(_, value) => setCompression(value as 'gzip' | 'lz4')}
                    >
                      <FormSelectOption value="gzip" label="gzip" />
                      <FormSelectOption value="lz4" label="lz4" />
                    </FormSelect>
                  </FormGroup>
                </SplitItem>
              </Split>

              <ExpandableSection
                toggleText={showAdvanced ? t('Hide advanced options') : t('Show advanced options')}
                onToggle={(_, expanded) => setShowAdvanced(expanded)}
                isExpanded={showAdvanced}
              >
                <div className="automotive-dev__advanced-section">
                  <FormGroup label={t('Storage Class')} fieldId="storage-class">
                    <TextInput
                      id="storage-class"
                      value={storageClass}
                      onChange={(_, value) => setStorageClass(value)}
                      placeholder={t('Leave empty for default')}
                    />
                  </FormGroup>

                  {mode === 'bootc' && (
                    <>
                      <FormGroup label={t('Container Push Registry')} fieldId="container-push">
                        <TextInput
                          id="container-push"
                          value={containerPush}
                          onChange={(_, value) => setContainerPush(value)}
                          placeholder={t('quay.io/my-org/my-image:tag')}
                        />
                        <FormHelperText>
                          <HelperText>
                            <HelperTextItem>{t('Optional: Push the built bootc container to this registry.')}</HelperTextItem>
                          </HelperText>
                        </FormHelperText>
                      </FormGroup>

                      <FormGroup fieldId="build-disk-image">
                        <Switch
                          id="build-disk-image"
                          label={t('Also build disk image from container')}
                          isChecked={buildDiskImage}
                          onChange={(_, checked) => setBuildDiskImage(checked)}
                        />
                      </FormGroup>

                      <FormGroup label={t('Export OCI Artifact')} fieldId="export-oci">
                        <TextInput
                          id="export-oci"
                          value={exportOci}
                          onChange={(_, value) => setExportOci(value)}
                          placeholder={t('quay.io/my-org/my-disk:tag')}
                        />
                        <FormHelperText>
                          <HelperText>
                            <HelperTextItem>{t('Optional: Push the disk image as an OCI artifact to this registry.')}</HelperTextItem>
                          </HelperText>
                        </FormHelperText>
                      </FormGroup>
                    </>
                  )}
                </div>
              </ExpandableSection>

              <ActionGroup>
                <Button variant="primary" type="submit" isLoading={submitting} isDisabled={submitting}>
                  {t('Create Build')}
                </Button>
                <Button variant="link" onClick={() => history.push('/automotive-dev/builds')}>
                  {t('Cancel')}
                </Button>
              </ActionGroup>
            </Form>
          </CardBody>
        </Card>
      </PageSection>
    </>
  );
}

function getModeLabel(mode: BuildMode): string {
  switch (mode) {
    case 'bootc':
      return 'bootc';
    case 'image':
      return 'Image';
    case 'package':
      return 'Package';
    case 'disk':
      return 'Disk';
    default:
      return mode;
  }
}

function getModeDescription(mode: BuildMode): string {
  switch (mode) {
    case 'bootc':
      return 'Creates immutable, container-based OS images using bootc. This is the recommended mode for modern automotive systems.';
    case 'image':
      return 'Creates traditional ostree-based disk images.';
    case 'package':
      return 'Creates traditional, mutable, package-based disk images.';
    case 'disk':
      return 'Creates a disk image from an existing bootc container. Specify the container reference below.';
    default:
      return '';
  }
}
