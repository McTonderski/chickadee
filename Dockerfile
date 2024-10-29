# Step 1: Build the Go application
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git curl

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to the container
COPY go.mod go.sum ./

# Download all Go dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app
RUN go build -o docker-sbom .

# Step 2: Final image
FROM alpine:3.20.3
WORKDIR /home/app
# Install runtime dependencies: curl, syft, grype, and docker-cli (to use Docker socket)
RUN apk add --no-cache curl docker-cli

# Install Syft (for SBOM generation)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype (for CVE scanning)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY config.yaml /home/app/config.yaml
# Copy the Go binary from the builder
COPY --from=builder /app/docker-sbom /usr/local/bin/docker-sbom

# Expose Docker socket for interaction with the host's Docker daemon
VOLUME /var/run/docker.sock

# Set the entry point for the application
ENTRYPOINT ["docker-sbom"]