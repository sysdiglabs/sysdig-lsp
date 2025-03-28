# Scan Base Image

Sysdig LSP scans the base image defined in your Dockerfile to identify vulnerabilities early in your development workflow.

> [!IMPORTANT]
> Sysdig LSP analyzes only the final FROM instruction(s), as this specifies the runtime base image for your container.
>
> Intermediate stages defined in multi-stage Dockerfiles (e.g., builder images) are intentionally ignored because they don't
> form part of the final runtime environment.

![Sysdig LSP executing base image scan in the Helix editor](./scan_base_image.gif)

## Examples

### Single-stage Dockerfile (scanned)

```dockerfile
# Base image used for this Dockerfile
FROM alpine:latest
```

### Multi-stage Dockerfile (only the final stage is scanned)

```dockerfile
# Build stage (ignored by Sysdig LSP)
FROM golang:1.19 AS build
RUN go build -o app main.go

# Final image (scanned by Sysdig LSP)
FROM alpine:3.17
COPY --from=build /app /app
ENTRYPOINT ["/app"]
```

In this multi-stage Dockerfile, Sysdig LSP scans only the final stage (`alpine:3.17`).
