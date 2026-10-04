#!/bin/bash
# Remove the disposable Samba AD DC container (the domain is lost with it).
set -euo pipefail
CONTAINER="${CONTAINER:-vouch-samba-test}"
podman rm -f -t 5 "${CONTAINER}" >/dev/null 2>&1 || true
echo "stop: ${CONTAINER} removed"
