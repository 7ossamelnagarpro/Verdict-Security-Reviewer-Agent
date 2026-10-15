#!/usr/bin/env bash
set -Eeuo pipefail

# The base VM can still be booted for maintenance without an exchange disk.
# Only a disposable clone with the SRPILOT disk enters the automatic scan.
for _ in {1..60}; do
  [[ -e /dev/disk/by-label/SRPILOT ]] && break
  sleep 1
done
[[ -e /dev/disk/by-label/SRPILOT ]] || exit 0

install -d -m 0700 /mnt/sr-pilot
mount -t vfat -o uid=0,gid=0,umask=077 /dev/disk/by-label/SRPILOT /mnt/sr-pilot

finish() {
  local status=$?
  trap - EXIT
  sync
  umount /mnt/sr-pilot || true
  systemctl poweroff --no-block || /usr/sbin/poweroff
  exit "$status"
}
trap finish EXIT

/usr/bin/python3 -B /opt/security-reviewer/hyperv_autoscan_guest.py --exchange /mnt/sr-pilot
