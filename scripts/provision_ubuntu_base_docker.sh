#!/usr/bin/env bash
set -Eeuo pipefail

if (( EUID != 0 )); then
  printf 'Run this script with sudo inside the trusted Ubuntu base VM.\n' >&2
  exit 1
fi

# This is a trusted base-image setup script, never a project-provided recipe.
# No target repository is copied into or run in the base VM.
source /etc/os-release
if [[ "${ID:-}" != ubuntu || "${VERSION_ID:-}" != 24.04 || "$(dpkg --print-architecture)" != amd64 ]]; then
  printf 'Expected Ubuntu 24.04 amd64; refusing to modify this guest.\n' >&2
  exit 1
fi

conflicts=(docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc)
for package in "${conflicts[@]}"; do
  if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" == 'install ok installed' ]]; then
    printf 'Conflicting package is installed: %s. Review it before continuing.\n' "$package" >&2
    exit 1
  fi
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
apt-get install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

cat > /etc/apt/sources.list.d/docker.sources <<'EOF'
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker info >/dev/null

printf 'Docker Engine: '
docker version --format '{{.Server.Version}}'
printf 'Docker Compose: '
docker compose version --short
printf 'Docker service: '
systemctl is-active docker
if [[ -f /var/run/reboot-required ]]; then
  printf 'A reboot is required before saving the provisioned base checkpoint.\n'
fi
printf 'Do not add the login user to the docker group; use sudo for Docker administration.\n'
