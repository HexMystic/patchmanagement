#!/bin/sh
# Lab target entrypoint: install the operator public key with correct perms,
# ensure host keys exist, then run sshd in the foreground.
set -e

USER_HOME=/home/labadmin
mkdir -p "$USER_HOME/.ssh"

if [ -f /pubkey/authorized_key.pub ]; then
  cp /pubkey/authorized_key.pub "$USER_HOME/.ssh/authorized_keys"
else
  echo "WARNING: no public key mounted at /pubkey/authorized_key.pub — key auth will fail" >&2
fi

chown -R labadmin:labadmin "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
chmod 600 "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || true

# Ensure host keys exist (Debian images ship without them).
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# sshd path differs slightly across distros; prefer the standard location.
if [ -x /usr/sbin/sshd ]; then
  exec /usr/sbin/sshd -D -e
else
  exec sshd -D -e
fi
