#!/usr/bin/env bash
# Bootstrap the stack on a fresh Ubuntu EC2 instance.
#
# Usage (on EC2):
#   git clone <repo> secmon && cd secmon
#   cp .env.example .env && $EDITOR .env      # set real secrets
#   sudo bash scripts/deploy_ec2.sh
#
# What it does:
#   1. Installs Docker + Compose plugin if missing
#   2. Opens port 8000 in the local ufw (or warns about Security Group)
#   3. Builds and starts the stack detached
#   4. Waits for /healthz
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo bash scripts/deploy_ec2.sh)" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

echo "==> installing docker + compose plugin if needed"
if ! command -v docker >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi

echo "==> opening local firewall (ufw) if active"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then
  ufw allow 8000/tcp || true
fi
echo "    >> Remember to open 8000/tcp in the EC2 Security Group too."

echo "==> building + starting stack"
docker compose up -d --build

echo "==> waiting for api to become healthy"
for i in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
    echo "==> api is healthy"
    curl -s http://127.0.0.1:8000/healthz; echo
    exit 0
  fi
  sleep 2
done

echo "api did not become healthy in time — inspect: docker compose logs api" >&2
exit 1
