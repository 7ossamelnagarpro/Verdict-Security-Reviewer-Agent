#!/usr/bin/env bash
set -Eeuo pipefail

if (( EUID != 0 )); then
  printf 'Run with sudo inside the trusted Ubuntu base VM.\n' >&2
  exit 1
fi
source /etc/os-release
if [[ "${ID:-}" != ubuntu || "${VERSION_ID:-}" != 24.04 || "$(dpkg --print-architecture)" != amd64 ]]; then
  printf 'Expected Ubuntu 24.04 amd64.\n' >&2
  exit 1
fi
if [[ -e /dev/disk/by-label/SRPILOT ]]; then
  printf 'Refusing to install while a pilot exchange disk is attached.\n' >&2
  exit 1
fi
if ! getent passwd nobody >/dev/null; then
  printf 'The unprivileged nobody account is unavailable.\n' >&2
  exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for required in hyperv_autoscan_guest.py hyperv_pilot_guest.py web_runtime.py scan_tt_authorization.py hyperv_autoscan_entry.sh hyperv-autoscan.service; do
  [[ -f "$script_dir/$required" ]] || { printf 'Missing trusted install file: %s\n' "$required" >&2; exit 1; }
done

install -d -m 0755 /opt/security-reviewer
for script in hyperv_autoscan_guest.py hyperv_pilot_guest.py web_runtime.py scan_tt_authorization.py; do
  install -m 0644 "$script_dir/$script" "/opt/security-reviewer/$script"
done
install -m 0755 "$script_dir/hyperv_autoscan_entry.sh" /usr/local/sbin/hyperv-autoscan-entry
install -m 0644 "$script_dir/hyperv-autoscan.service" /etc/systemd/system/hyperv-autoscan.service
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/hyperv-autoscan.service
systemctl enable hyperv-autoscan.service
systemctl is-enabled hyperv-autoscan.service
printf 'Auto-scan service installed. Do not create the ready checkpoint until this base VM is Off and network-disconnected.\n'
