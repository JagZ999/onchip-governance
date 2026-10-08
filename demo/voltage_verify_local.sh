#!/usr/bin/env bash
# Laptop side: verify the proofs archive with the connector.  Usage: demo/voltage_verify_local.sh proofs_<stamp>.tgz
set -euo pipefail
ARCH="${1:?proofs archive}"; HERE="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$(tar tzf "$ARCH" | head -1 | cut -d/ -f1)"; DATE="$(echo "$DIR" | sed 's/proofs_//' | cut -c1-8)"
DEST="$HERE/evidence/voltagegpu_own_${DATE}"; mkdir -p "$DEST"; tar xzf "$ARCH" -C "$DEST" --strip-components=1
cd "$DEST"; sha256sum -c SHA256SUMS --ignore-missing 2>/dev/null || shasum -a 256 -c SHA256SUMS --ignore-missing
python3 "$HERE/tee_attestation_connector.py" \
  --nras nras_api_shape.json --jwks jwks_snapshot.json --tdx-quote quote.bin \
  --model-digest "$(cat model.sha256)" --max-age-days 30 \
  --provider "VoltageGPU confidential VM, own tenant run, verified on the laptop" \
  --environment "Intel TDX CVM + NVIDIA GPU in CC mode, captured $(grep captured_at PROVENANCE.txt | cut -d= -f2)" \
  --out-prefix "$DEST/onchip_voltage_own"
echo; echo "Report: $DEST/onchip_voltage_own.md"
