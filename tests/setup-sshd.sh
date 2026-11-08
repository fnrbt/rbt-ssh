#!/usr/bin/env bash
# Provision the OpenSSH server the Rbt.Ssh client tests run against.
# Idempotent: re-running recreates the container and the client keys.
#
#   - sshd on 127.0.0.1:${RBT_SSH_PORT:-52222}, user tester (password "secret")
#   - client keys tests/keys/id_ed25519 and tests/keys/id_rsa (no passphrase),
#     both in tester's authorized_keys
#   - the server's ed25519 host key fingerprint in tests/keys/host_ed25519.fp
set -euo pipefail

NAME="${RBT_SSH_CONTAINER:-rbt-ssh-test}"
IMAGE="${RBT_SSH_IMAGE:-docker.io/library/alpine:3.20}"
PORT="${RBT_SSH_PORT:-52222}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS="$ROOT/tests/keys"
mkdir -p "$KEYS"
rm -f "$KEYS"/id_ed25519* "$KEYS"/id_rsa* "$KEYS"/host_ed25519.fp
ssh-keygen -q -t ed25519 -N "" -C rbt-ssh-test -f "$KEYS/id_ed25519"
ssh-keygen -q -t rsa -b 3072 -N "" -C rbt-ssh-test -f "$KEYS/id_rsa"

podman rm -f "$NAME" >/dev/null 2>&1 || true
podman run -d --name "$NAME" -p "127.0.0.1:${PORT}:22" "$IMAGE" sh -c '
  apk add --no-cache openssh >/dev/null &&
  ssh-keygen -A >/dev/null &&
  adduser -D tester && echo "tester:secret" | chpasswd &&
  mkdir -p /home/tester/.ssh && chmod 700 /home/tester/.ssh &&
  touch /home/tester/.ssh/authorized_keys && chmod 600 /home/tester/.ssh/authorized_keys &&
  chown -R tester:tester /home/tester/.ssh &&
  sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config &&
  touch /ready && exec /usr/sbin/sshd -D -e' >/dev/null

for _ in $(seq 1 60); do
  podman exec "$NAME" test -f /ready 2>/dev/null && break
  sleep 1
done
podman exec "$NAME" test -f /ready || { echo "sshd did not start" >&2; podman logs "$NAME" >&2; exit 1; }
cat "$KEYS/id_ed25519.pub" "$KEYS/id_rsa.pub" | podman exec -i "$NAME" sh -c 'cat > /home/tester/.ssh/authorized_keys'
podman exec "$NAME" ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}' > "$KEYS/host_ed25519.fp"
echo "done: $NAME on 127.0.0.1:${PORT} (user tester); host key $(cat "$KEYS/host_ed25519.fp")"
