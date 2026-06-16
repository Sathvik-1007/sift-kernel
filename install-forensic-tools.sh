#!/bin/bash
# Install SIFT forensic tools on CachyOS/Arch
# Run with: sudo bash install-forensic-tools.sh

set -e

echo "Installing forensic packages from official repos..."
pacman -S --noconfirm sleuthkit volatility3 wireshark-cli foremost hashdeep 2>/dev/null || {
  echo "pacman failed, trying individual packages..."
  pacman -S --noconfirm sleuthkit || true
  pacman -S --noconfirm volatility3 || true  
  pacman -S --noconfirm wireshark-cli || true
  pacman -S --noconfirm foremost || true
  pacman -S --noconfirm hashdeep || true
}

echo ""
echo "Checking installed tools:"
for tool in fls mmls icat istat vol tshark foremost hashdeep yara strings; do
  if which "$tool" >/dev/null 2>&1; then
    echo "  ✓ $tool"
  else
    echo "  ✗ $tool (not found)"
  fi
done

echo ""
echo "Done. Missing tools (evtxexport, rip.pl, plaso) are AUR or custom builds."
echo "For full SIFT compatibility, use: paru -S libevtx plaso-git"
