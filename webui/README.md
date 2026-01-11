# Centos Automotive Suite Console Plugin

OpenShift Console plugin for the Centos Automotive Suite. This plugin provides a web interface for managing automotive OS image builds directly from the OpenShift Console.

## Features

- **Build List**: View all image builds with status, timestamps, and filtering
- **Create Builds**: Start new builds from a manifest with support for:
  - bootc
  - Traditional ostree-based images
  - Package-based disk images
- **Build Details**: View build configuration, logs, and download artifacts
- **Real-time Logs**: Stream build logs as they're generated
- **Artifact Download**: Download completed build artifacts

## Development

### Prerequisites

- Node.js 18+
- npm or yarn
- Access to an OpenShift cluster with the Centos Automotive Suite installed

### Local Development

1. Install dependencies:
   ```sh
   npm install
   ```

2. Start the development server:
   ```sh
   npm run start
   ```

3. In another terminal, log into your OpenShift cluster and start the console:
   ```sh
   oc login
   ./start-console.sh
   ```

4. Navigate to http://localhost:9000/automotive-dev/builds

### Building

Build for production:
```sh
npm run build
```

Build for development:
```sh
npm run build-dev
```

## Docker Image

Build the container image:
```sh
docker build -t quay.io/my-repository/automotive-dev-console-plugin:latest .
# For Apple Silicon: add --platform=linux/amd64
```

Push the image:
```sh
docker push quay.io/my-repository/automotive-dev-console-plugin:latest
```

## Deployment

Deploy using Helm:

```sh
helm upgrade -i automotive-dev-console-plugin charts/openshift-console-plugin \
  -n automotive-dev-system \
  --create-namespace \
  --set plugin.image=quay.io/my-repository/automotive-dev-console-plugin:latest
```

### Helm Configuration

Key values:
- `plugin.image`: Container image location (required)
- `plugin.proxy[0].service.name`: Name of the build-api service (default: `build-api`)
- `plugin.proxy[0].service.port`: Port of the build-api service (default: `8080`)

See [values.yaml](charts/openshift-console-plugin/values.yaml) for all options.

## Project Structure

```
src/
  api/
    buildApi.ts       # API client for build-api
    types.ts          # TypeScript types for API
  components/
    BuildListPage.tsx     # Main build list view
    BuildDetailsPage.tsx  # Build details with logs and artifacts
    CreateBuildPage.tsx   # Form to create new builds
  hooks/
    useBuilds.ts      # Data fetching hooks for builds
    useLogs.ts        # Log streaming hook
console-extensions.json   # Plugin extension declarations
package.json              # Plugin metadata
charts/                   # Helm chart for deployment
```

## i18n

Translations are in `locales/en/plugin__automotive-dev-console-plugin.json`.

After adding new translatable strings, run:
```sh
npm run i18n
```
