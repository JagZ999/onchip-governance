#!/usr/bin/env bash
# Two proofs, bound to a model, from INSIDE a confidential VM (Intel TDX + NVIDIA GPU in CC mode).
#
# What it produces (all in $OUT, then packed to /tmp/proofs_<stamp>.tgz):
#   model.sha256          SHA-256 of the model artefact the operator deploys       (the "one line")
#   challenge.hex         32 random bytes chosen on this run                       (freshness)
#   report_data.bin       64 bytes = SHA-256(model) || challenge                   -> into the TDX quote
#   quote.bin             Intel TDX v4 quote from the kernel configfs TSM interface (report_data at offset 568)
#   sdk_token.json        raw nv_attestation_sdk output (SDK wrapper + NVIDIA NRAS tokens), nonce = SHA-256(model)
#   nras_api_shape.json   the NVIDIA-issued tokens only, in NRAS API shape [["JWT", overall], {"GPU-0": jwt}]
#   gpu_evidence.json     the GPU evidence list the SDK sent to NRAS
#   jwks_snapshot.json    NVIDIA's verification keys at run time (they rotate within days; keep this with the tokens)
#   environment.txt       kernel, driver, nvidia-smi conf-compute, TSM provider
#   PROVENANCE.txt, SHA256SUMS
#   bundle.json/manifest.json  optional voltage-verify cross-check bundle (best effort)
#
# Run from the laptop against the VM (SSH command is on the pod page):
#   ssh -p <port> ubuntu@<ip> 'bash -s' < demo/voltage_two_proofs_in_vm.sh
# Then: scp -P <port> ubuntu@<ip>:/tmp/proofs_*.tgz .   and run demo/voltage_verify_local.sh on it.
#
# Nothing here is provider-specific: it reads the kernel TSM interface and calls NVIDIA's own SDK.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HOME/proofs_$STAMP"; mkdir -p "$OUT"; cd "$OUT"
MODEL_URL="${MODEL_URL:-https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf}"
NRAS_URLS="${NRAS_URLS:-https://nras.attestation.nvidia.com/v3/attest/gpu https://nras.attestation.nvidia.com/v4/attest/gpu}"
log(){ printf '\n== %s\n' "$*"; }

log "0. environment"
{ echo "stamp=$STAMP"; echo "host=$(hostname)"; uname -a; ls -l /dev/tdx_guest 2>&1; systemd-detect-virt 2>&1 || true
  nvidia-smi --query-gpu=name,driver_version,vbios_version --format=csv,noheader 2>&1
  nvidia-smi conf-compute -q 2>&1 || true
  for d in /sys/kernel/config/tsm/report/*/; do [ -d "$d" ] || continue; echo "tsm provider: $(cat "$d/provider" 2>/dev/null)"; done
  true
} | tee environment.txt
CC_STATE="$(nvidia-smi conf-compute -q 2>/dev/null | awk -F: '/CC State/{gsub(/ /,"",$2);print $2;exit}')"
if [ "${CC_STATE:-}" != "ON" ]; then echo "ABORT: GPU confidential-computing state is '${CC_STATE:-unknown}', not ON. Release the VM, do not pay for more time." >&2; exit 2; fi
[ -e /dev/tdx_guest ] || { echo "ABORT: /dev/tdx_guest missing; this is not a TDX guest." >&2; exit 2; }

log "1. python tooling (image ships without pip)"
python3 -m pip --version >/dev/null 2>&1 || { curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py; python3 /tmp/get-pip.py --user --break-system-packages -q; }
python3 -m pip install --user --break-system-packages -q "nv-attestation-sdk" "voltage-verify[attest]" || python3 -m pip install --user --break-system-packages -q "nv-attestation-sdk"
python3 -c 'import nv_attestation_sdk, importlib.metadata as m; print("nv_attestation_sdk", m.version("nv-attestation-sdk"))'
USP="$(python3 -c 'import site;print(site.getusersitepackages())')"

log "2. model artefact -> SHA-256 (the digest an operator binds)"
if curl -fL --retry 3 -o model.gguf "$MODEL_URL"; then echo "model_url=$MODEL_URL" > model.txt
else echo "WARN: model download failed; using a labelled placeholder artefact" >&2; head -c 1048576 /dev/urandom > model.gguf; echo "model_url=PLACEHOLDER (download failed): $MODEL_URL" > model.txt; fi
sha256sum model.gguf | awk '{print $1}' > model.sha256; MODEL_DIGEST="$(cat model.sha256)"; ls -l model.gguf; echo "model sha256: $MODEL_DIGEST"

log "3. challenge (32 random bytes, chosen here, now)"
python3 -c 'import secrets;print(secrets.token_hex(32))' > challenge.hex; CHALLENGE="$(cat challenge.hex)"; echo "challenge: $CHALLENGE"
python3 - "$MODEL_DIGEST" "$CHALLENGE" <<'PY'
import sys; open('report_data.bin','wb').write(bytes.fromhex(sys.argv[1])+bytes.fromhex(sys.argv[2]))
PY
echo "report_data = sha256(model) || challenge  ($(stat -c %s report_data.bin) bytes)"

log "4. Intel TDX quote via configfs TSM (report_data bound), as root"
sudo bash -euo pipefail -c '
  mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
  R=/sys/kernel/config/tsm/report/unprompted_$$; mkdir -p "$R"
  cat report_data.bin > "$R/inblob"
  cat "$R/outblob" > quote.bin
  echo "provider=$(cat $R/provider)  generation=$(cat $R/generation)" | tee -a environment.txt
  rmdir "$R" || true
  chown "$SUDO_UID:$SUDO_GID" quote.bin'
python3 - <<'PY'
q=open('quote.bin','rb').read(); rd=open('report_data.bin','rb').read()
print(f"quote bytes={len(q)} version={int.from_bytes(q[0:2],'little')} tee_type={hex(int.from_bytes(q[4:8],'little'))}")
assert q[568:632]==rd, "report_data not found at offset 568"; print("report_data present at offset 568: OK (model digest + challenge are inside the chip-signed quote)")
PY

log "5. NVIDIA GPU attestation via nv_attestation_sdk, nonce = SHA-256(model), as root"
curl -sS https://nras.attestation.nvidia.com/.well-known/jwks.json -o jwks_snapshot.json && python3 -c 'import json;print("jwks keys:",len(json.load(open("jwks_snapshot.json"))["keys"]))'
sudo env PATH="$PATH" PYTHONPATH="$USP" python3 - "$MODEL_DIGEST" "$NRAS_URLS" <<'PY'
import sys, json, os
from nv_attestation_sdk import attestation
nonce, urls = sys.argv[1], [""] + sys.argv[2].split()   # "" = the SDK's own default NRAS endpoint, tried first
last=None
for url in urls:
    try:
        c = attestation.Attestation(); c.set_name("unprompted-demo"); c.set_nonce(nonce)
        c.add_verifier(attestation.Devices.GPU, attestation.Environment.REMOTE, url, "")
        ev = c.get_evidence()
        try: json.dump(ev, open('gpu_evidence.json','w'), default=str)
        except Exception as e: print("evidence not JSON-serialisable:", e)
        ok = c.attest(ev); tok = c.get_token()
        print(f"NRAS endpoint {url or '(SDK default)'}: attest() -> {ok}")
        open('sdk_token.json','w').write(tok if isinstance(tok,str) else json.dumps(tok))
        if ok: break
        last=f"attest returned {ok}"
    except Exception as e:
        last=repr(e); print(f"NRAS endpoint {url} failed: {e!r}")
else:
    sys.exit(f"GPU attestation failed on all endpoints: {last}")
PY
sudo chown "$(id -u):$(id -g)" sdk_token.json gpu_evidence.json 2>/dev/null || true
python3 - "$MODEL_DIGEST" <<'PY'
import json, base64, sys
def dec(seg): seg+='='*(-len(seg)%4); return json.loads(base64.urlsafe_b64decode(seg))
raw=open('sdk_token.json').read()
try: j=json.loads(raw)
except Exception: j=raw
found=[]
def collect(o):
    if isinstance(o,str) and o.count('.')==2: found.append(('overall',o)); return
    if isinstance(o,list) and len(o)==2 and o[0]=='JWT' and isinstance(o[1],str): found.append(('overall',o[1])); return
    if isinstance(o,list): [collect(x) for x in o]
    elif isinstance(o,dict):
        for k,v in o.items():
            if isinstance(v,str) and v.count('.')==2: found.append((k,v))
            else: collect(v)
collect(j)
nras=[(k,t) for k,t in found if dec(t.split('.')[0]).get('alg')!='HS256']
overall=[t for k,t in nras if k=='overall']; gpus={k:t for k,t in nras if k!='overall'}
assert overall and gpus, f"no NVIDIA-issued tokens found; shapes: {[(k,dec(t.split('.')[0]).get('alg')) for k,t in found]}"
json.dump([["JWT",overall[0]],gpus],open('nras_api_shape.json','w'))
c=dec(overall[0].split('.')[1]); print("NRAS overall: iss",c.get('iss'),"| result",c.get('x-nvidia-overall-att-result'),"| eat_nonce",str(c.get('eat_nonce'))[:16]+'…')
assert str(c.get('eat_nonce','')).lower()==sys.argv[1].lower(), "eat_nonce != model digest"
for k,t in gpus.items():
    g=dec(t.split('.')[1]); print(f"  {k}: hwmodel={g.get('hwmodel')} measres={g.get('measres')} secboot={g.get('secboot')} dbgstat={g.get('dbgstat')} nonce-match={g.get('x-nvidia-gpu-attestation-report-nonce-match')} driver={g.get('x-nvidia-gpu-driver-version')}")
print("NVIDIA token carries the model digest as its nonce: OK")
PY

log "6. optional cross-check bundle with voltage-verify (independent tool, best effort)"
if command -v voltage-verify >/dev/null 2>&1; then
  voltage-verify manifest --challenge auto -o manifest.json && \
  sudo env PATH="$PATH" PYTHONPATH="$USP" voltage-verify attest --manifest manifest.json --mode single-gpu -o bundle.json && \
  (voltage-verify verify bundle.json --challenge "$(python3 -c 'import json;print(json.load(open("manifest.json"))["challenge"])')" | tail -3) || echo "voltage-verify cross-check skipped/failed (non-fatal)"
  sudo chown "$(id -u):$(id -g)" bundle.json 2>/dev/null || true
fi

log "7. provenance + checksums + archive"
{ echo "captured_at=$STAMP"; echo "captured_by=tenant, inside the VM, over SSH"; echo "provider=VoltageGPU confidential VM (Intel TDX + NVIDIA CC mode)"
  cat model.txt; echo "model_sha256=$MODEL_DIGEST"; echo "challenge=$CHALLENGE"
  echo "report_data=sha256(model)||challenge (64 bytes) -> TDX quote offset 568"; echo "nras_nonce=sha256(model)"
  echo "tooling: $(python3 -c 'import importlib.metadata as m;print("nv-attestation-sdk",m.version("nv-attestation-sdk"))' 2>/dev/null)"; } > PROVENANCE.txt
rm -f model.gguf   # the artefact is public; keep the digest, not 400 MB
sha256sum * > SHA256SUMS
tar czf "/tmp/proofs_$STAMP.tgz" -C "$HOME" "proofs_$STAMP"
echo; echo "ARCHIVE READY: /tmp/proofs_$STAMP.tgz   (scp it off, then release the VM)"
