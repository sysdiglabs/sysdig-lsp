# Sysdig LSP Features

Sysdig LSP provides tools to integrate container security checks into your development workflow.

## [Scan Base Image](./scan_base_image.md)
- Scans the runtime base image specified in your Dockerfile for vulnerabilities.
- Supports single-stage and multi-stage Dockerfiles (final runtime stage only).

## [Code Lens Support](./code_lens.md)
- Displays actionable commands directly within the editor (e.g., initiating base image scans).
- Enables quick access to frequently performed actions.

## [Build and Scan](./build_and_scan.md)
- Builds and scans the entire final Dockerfile image used in production.
- Supports multi-stage Dockerfiles, analyzing final stage and explicitly copied artifacts from intermediate stages.

## [Layered Analysis](./layered_analysis.md)
- Scans each Dockerfile layer individually for precise vulnerability identification.
- Supports detailed analysis in single-stage and multi-stage Dockerfiles.

## [Docker-compose Image Analysis](./docker_compose_image_analysis.md)
- Scans the images defined in your `docker-compose.yml` files for vulnerabilities.

## [Kubernetes Manifest Image Analysis](./k8s_manifest_image_analysis.md)
- Scans container images defined in Kubernetes manifest files for vulnerabilities.
- Supports Pods, Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs.

## [Vulnerability Explanation](./vulnerability_explanation.md)
- Displays a detailed summary of scan results when hovering over a scanned image name.
- Provides immediate feedback on vulnerabilities, severities, and available fixes.

See the linked documents for more details.
