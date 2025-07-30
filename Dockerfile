# Use a base image with necessary tools. Ubuntu is a common choice.
FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    openssl \
    jq \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Set environment variables with default values.
# These can be overridden at build time using --build-arg or at run time using -e.
ENV CONTAINER_NAME="shadowbox"
ENV SHADOWBOX_DIR="/opt/outline"
ENV SB_IMAGE="quay.io/outline/shadowbox:stable"
ENV WATCHTOWER_REFRESH_SECONDS="3600"
ENV ACCESS_CONFIG="${SHADOWBOX_DIR}/access.txt"
# SENTRY_LOG_FILE is typically not set in a Dockerfile as it's for external logging during install.
ENV SENTRY_LOG_FILE=""

# Expose the default API port and a common range for access keys.
# Users should adjust these based on their actual configuration.
EXPOSE 8081/tcp
EXPOSE 49152-65535/tcp
EXPOSE 49152-65535/udp

# Create the Outline directory and set permissions.
RUN mkdir -p "${SHADOWBOX_DIR}" && \
    chmod u+s,ug+rwx,o-rwx "${SHADOWBOX_DIR}"

# Create a directory for persistent state within the SHADOWBOX_DIR.
RUN mkdir -p "${SHADOWBOX_DIR}/persisted-state" && \
    chmod ug+rwx,g+s,o-rwx "${SHADOWBOX_DIR}/persisted-state"

# Copy the entrypoint script into the container.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set the entrypoint for the container.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]