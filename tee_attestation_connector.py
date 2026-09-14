#!/usr/bin/env python3
"""
tee_attestation_connector.py  —  open-source TEE attestation → compliance evidence
On-chip governance evidence  →  EU AI Act Annex IV / Art. 15 / SOC 2 / ISO 42001

Reads hardware attestation evidence produced by confidential-computing stacks
and turns it into auditor-ready compliance evidence, following the same pattern
as mlflow_annex4_connector.py and wandb_annex4_connector.py (stdlib only).

Evidence sources (any combination, all optional):
  --nras   FILE   NVIDIA Remote Attestation Service / nvattest output
                  (JWT, or the JSON [["JWT", overall], {"GPU-0": jwt, ...}] shape)
  --ita    FILE   Intel Trust Authority token (JWT; TDX and/or nvgpu composite)
  --maa    FILE   Microsoft Azure Attestation token (JWT; SEV-SNP or TDX CVM)
  --gcs    FILE   Google Confidential Space token (JWT / OIDC)
  --snp-report FILE   raw AMD SEV-SNP ATTESTATION_REPORT (1184 bytes)
  --tdx-quote  FILE   raw Intel TDX quote (v4 or v5)
  --attestation-url URL  published attestation document of a confidential service
                      (e.g. https://inference.tinfoil.sh → /.well-known/tinfoil-attestation)
  --verify-amd        verify raw SEV-SNP reports against AMD KDS (VCEK → ASK → ARK), stdlib only

Reference values (bind the attested machine to the documented AI system):
  --expected-measurement HEX   SEV-SNP launch measurement / TDX MRTD / GCS image digest
  --model-digest HEX           hash of the deployed model artefact (e.g. MLflow model
                               digest). Checked against report_data / runtime data / nonce.
  --jwks FILE|URL              verifier public keys (repeatable). With keys present the
                               connector re-verifies token signatures itself (assurance L3).

Outputs:
  <prefix>.json   structured evidence for Annex IV §1(c), §1(e), §2(h), §3, §6 + Art. 15
  <prefix>.md     human-readable report with ⚠ gap warnings for the auditor
  console         coverage summary with ✓/✗ per on-chip governance check

Run  python tee_attestation_connector.py --selftest  to see the pipeline on synthetic
evidence (no hardware needed).
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import struct
import sys
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

CONNECTOR_VERSION = "0.6.0"

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def b64url_decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def hexs(b: bytes) -> str:
    return b.hex()


def now_utc() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).isoformat()
    except Exception:
        return None


def looks_like_jwt(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", s.strip()))


def read_text_or_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def norm_hex(v: Any) -> Optional[str]:
    """Normalise hex / base64 / base64url encoded digests to lowercase hex."""
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    s = str(v).strip()
    if s.lower().startswith("sha256:"):
        s = s.split(":", 1)[1]
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        return s.lower()
    try:
        return b64url_decode(s).hex()
    except Exception:
        return s.lower()


# ---------------------------------------------------------------------------
# JWT parsing and (optional) signature verification — pure stdlib
# ---------------------------------------------------------------------------

@dataclass
class JWT:
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    signature_verified: Optional[bool] = None   # None = not attempted
    verify_note: str = ""


def parse_jwt(token: str) -> JWT:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT (expected 3 dot-separated segments)")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = b64url_decode(parts[2]) if parts[2] else b""
    return JWT(raw=token.strip(), header=header, payload=payload, signature=sig)


_HASHES = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
_PKCS1_PREFIX = {
    "256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _int_from_b64url(s: str) -> int:
    return int.from_bytes(b64url_decode(s), "big")


def _mgf1(seed: bytes, length: int, h) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += h(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _rsa_verify_pkcs1(n: int, e: int, msg: bytes, sig: bytes, bits: str) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n)
    em = m.to_bytes(k, "big")
    t = _PKCS1_PREFIX[bits] + _HASHES[bits](msg).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expected


def _rsa_verify_pss(n: int, e: int, msg: bytes, sig: bytes, bits: str) -> bool:
    h = _HASHES[bits]
    hlen = h().digest_size
    slen = hlen
    mod_bits = n.bit_length()
    em_len = (mod_bits - 1 + 7) // 8
    k = (mod_bits + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n)
    em = m.to_bytes(k, "big")[-em_len:]
    if em_len < hlen + slen + 2 or em[-1] != 0xBC:
        return False
    masked_db, hh = em[: em_len - hlen - 1], em[em_len - hlen - 1: -1]
    top_bits = 8 * em_len - (mod_bits - 1)
    if top_bits and (masked_db[0] >> (8 - top_bits)) != 0:
        return False
    db_mask = _mgf1(hh, em_len - hlen - 1, h)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    if top_bits:
        db = bytes([db[0] & (0xFF >> top_bits)]) + db[1:]
    pad_len = em_len - hlen - slen - 2
    if any(db[:pad_len]) or db[pad_len] != 0x01:
        return False
    salt = db[-slen:]
    m_prime = b"\x00" * 8 + h(msg).digest() + salt
    return h(m_prime).digest() == hh


_CURVES = {
    "P-256": dict(
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        size=32, hash="256"),
    "P-384": dict(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        size=48, hash="384"),
}


def _ec_add(P, Q, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _ec_mul(k: int, P, p):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, p)
        P = _ec_add(P, P, p)
        k >>= 1
    return R


def _ecdsa_verify(curve: str, qx: int, qy: int, msg: bytes, sig: bytes) -> bool:
    c = _CURVES[curve]
    p, n, size = c["p"], c["n"], c["size"]
    if len(sig) != 2 * size:
        return False
    r, s = int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")
    if not (1 <= r < n and 1 <= s < n):
        return False
    if (qy * qy - (qx ** 3 - 3 * qx + c["b"])) % p != 0:
        return False
    e = int.from_bytes(_HASHES[c["hash"]](msg).digest(), "big")
    w = pow(s, -1, n)
    u1, u2 = (e * w) % n, (r * w) % n
    X = _ec_add(_ec_mul(u1, (c["gx"], c["gy"]), p), _ec_mul(u2, (qx, qy), p), p)
    return X is not None and X[0] % n == r


# --- minimal DER walker to pull a public key out of an x5c certificate -------

def _der_read(buf: bytes, pos: int) -> Tuple[int, bytes, int]:
    tag = buf[pos]
    pos += 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(buf[pos: pos + nbytes], "big")
        pos += nbytes
    return tag, buf[pos: pos + length], pos + length


def _der_children(buf: bytes) -> List[Tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(buf):
        tag, body, pos = _der_read(buf, pos)
        out.append((tag, body))
    return out


_OID_RSA = bytes.fromhex("2a864886f70d010101")
_OID_EC = bytes.fromhex("2a8648ce3d0201")
_OID_P256 = bytes.fromhex("2a8648ce3d030107")
_OID_P384 = bytes.fromhex("2b81040022")


def jwk_from_x5c(cert_b64: str) -> Dict[str, Any]:
    cert = _der_children(base64.b64decode(cert_b64 + "=" * (-len(cert_b64) % 4)))[0][1]
    tbs = _der_children(cert)[0][1]
    fields = _der_children(tbs)
    idx = 1 if fields[0][0] == 0xA0 else 0  # skip explicit version
    spki = fields[idx + 5][1]                # version?, serial, sigalg, issuer, validity, subject, spki
    alg, key = _der_children(spki)
    alg_oids = _der_children(alg[1])
    keybits = key[1][1:]                     # strip unused-bits byte
    if alg_oids[0][1] == _OID_RSA:
        n, e = _der_children(_der_children(keybits)[0][1])
        return {"kty": "RSA", "n": b64url_encode(n[1].lstrip(b"\x00")), "e": b64url_encode(e[1])}
    if alg_oids[0][1] == _OID_EC:
        crv = "P-256" if alg_oids[1][1] == _OID_P256 else "P-384" if alg_oids[1][1] == _OID_P384 else None
        size = _CURVES[crv]["size"] if crv else None
        if crv and keybits[0] == 0x04:
            return {"kty": "EC", "crv": crv,
                    "x": b64url_encode(keybits[1: 1 + size]), "y": b64url_encode(keybits[1 + size:])}
    raise ValueError("unsupported public key type in x5c")


def load_jwks(src: str) -> List[Dict[str, Any]]:
    if src.startswith("http://") or src.startswith("https://"):
        with urllib.request.urlopen(src, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8"))
    else:
        data = read_text_or_json(src)
    if isinstance(data, dict) and "keys" in data:
        return list(data["keys"])
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    raise ValueError(f"could not read JWKS from {src}")


def verify_jwt(jwt: JWT, keys: List[Dict[str, Any]]) -> None:
    alg = str(jwt.header.get("alg", ""))
    kid = jwt.header.get("kid")
    if alg.lower() in ("", "none"):
        jwt.signature_verified = False
        jwt.verify_note = "token is unsigned (alg=none)"
        return
    candidates = [k for k in keys if not kid or k.get("kid") in (None, kid)]
    if "x5c" in jwt.header and jwt.header["x5c"]:
        try:
            candidates.insert(0, jwk_from_x5c(jwt.header["x5c"][0]))
        except Exception as exc:  # pragma: no cover
            jwt.verify_note = f"x5c present but unreadable ({exc}); "
    if not candidates:
        jwt.signature_verified = None
        jwt.verify_note += "no verifier key available (pass --jwks); token accepted as verifier-asserted"
        return
    signed = ".".join(jwt.raw.split(".")[:2]).encode("ascii")
    for k in candidates:
        try:
            if "x5c" in k and k.get("kty") is None:
                k = jwk_from_x5c(k["x5c"][0])
            if alg.startswith("RS") and k.get("kty") == "RSA":
                ok = _rsa_verify_pkcs1(_int_from_b64url(k["n"]), _int_from_b64url(k["e"]), signed, jwt.signature, alg[2:])
            elif alg.startswith("PS") and k.get("kty") == "RSA":
                ok = _rsa_verify_pss(_int_from_b64url(k["n"]), _int_from_b64url(k["e"]), signed, jwt.signature, alg[2:])
            elif alg in ("ES256", "ES384") and k.get("kty") == "EC":
                crv = "P-256" if alg == "ES256" else "P-384"
                if k.get("crv") != crv:
                    continue
                ok = _ecdsa_verify(crv, _int_from_b64url(k["x"]), _int_from_b64url(k["y"]), signed, jwt.signature)
            else:
                continue
        except Exception:
            ok = False
        if ok:
            jwt.signature_verified = True
            jwt.verify_note = f"signature verified locally ({alg}, kid={kid or k.get('kid') or 'x5c'})"
            return
    jwt.signature_verified = False
    jwt.verify_note = f"signature did NOT verify against supplied keys ({alg})"


# ---------------------------------------------------------------------------
# Normalised attestation facts
# ---------------------------------------------------------------------------

@dataclass
class DeviceFacts:
    """One attested component: a CPU TEE (TDX/SEV-SNP VM) or a GPU/NVSwitch."""
    kind: str                       # "cpu-tee" | "gpu" | "switch"
    vendor: str                     # "Intel" | "AMD" | "NVIDIA" | "Google" | ...
    tee: str                        # "TDX" | "SEV-SNP" | "NVIDIA-CC" | "Confidential Space"
    identity: Optional[str] = None  # ueid / chip_id / instance id
    model: Optional[str] = None     # hwmodel
    firmware: Dict[str, Any] = field(default_factory=dict)
    measurements: Dict[str, Any] = field(default_factory=dict)
    debug_enabled: Optional[bool] = None
    secure_boot: Optional[bool] = None
    cc_mode: Optional[str] = None            # ON / OFF / DEVTOOLS
    measurements_match_reference: Optional[bool] = None
    tcb_status: Optional[str] = None
    tcb_up_to_date: Optional[bool] = None
    advisories: List[str] = field(default_factory=list)
    migratable: Optional[bool] = None
    smt_enabled: Optional[bool] = None
    cert_chain_valid: Optional[bool] = None
    nonce_matched: Optional[bool] = None
    report_data: Optional[str] = None        # hex
    runtime_data: Optional[str] = None       # opaque, from verifier
    location: Dict[str, Any] = field(default_factory=dict)
    workload: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceSource:
    source: str                     # "nras" | "ita" | "maa" | "gcs" | "snp-report" | "tdx-quote"
    path: str
    format: str                     # "jwt" | "binary"
    issuer: Optional[str] = None
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    signature_verified: Optional[bool] = None
    verify_note: str = ""
    nonce: Optional[str] = None
    overall_result: Optional[bool] = None
    devices: List[DeviceFacts] = field(default_factory=list)
    raw_claims_sha256: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    extra_verification: Dict[str, Any] = field(default_factory=dict)


def _tri(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("true", "success", "enabled", "on", "valid", "1", "yes", "pass", "passed"):
        return True
    if s in ("false", "fail", "failed", "disabled", "off", "invalid", "0", "no", "disabled-since-boot"):
        return False
    return None


def _all_true(*vals: Any) -> Optional[bool]:
    seen = [_tri(v) for v in vals if v is not None]
    if not seen:
        return None
    return all(seen)


def _jwt_source(name: str, path: str, jwt: JWT) -> EvidenceSource:
    p = jwt.payload
    return EvidenceSource(
        source=name, path=path, format="jwt", issuer=p.get("iss"),
        issued_at=iso(p.get("iat")), expires_at=iso(p.get("exp")),
        signature_verified=jwt.signature_verified, verify_note=jwt.verify_note,
        raw_claims_sha256=hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest(),
    )


# ---------------------------------------------------------------------------
# Parser: NVIDIA NRAS / nvattest (GPU + NVSwitch)
# ---------------------------------------------------------------------------

def _nvidia_device_from_claims(name: str, c: Dict[str, Any]) -> DeviceFacts:
    def chain_ok(key: str) -> Optional[bool]:
        v = c.get(key)
        if isinstance(v, dict):
            return _tri(v.get("x-nvidia-cert-status")) and _tri(v.get("x-nvidia-cert-ocsp-status", True))
        return _tri(c.get(key + "-validated", v))

    rim_ok = _all_true(
        c.get("x-nvidia-gpu-driver-rim-signature-verified"), c.get("x-nvidia-gpu-vbios-rim-signature-verified"),
        c.get("x-nvidia-gpu-driver-rim-measurements-available"), c.get("x-nvidia-gpu-vbios-rim-measurements-available"),
    )
    kind = "switch" if str(c.get("x-nvidia-attestation-type", "GPU")).upper() == "SWITCH" or name.upper().startswith("SWITCH") else "gpu"
    d = DeviceFacts(
        kind=kind, vendor="NVIDIA", tee="NVIDIA-CC", identity=c.get("ueid"), model=c.get("hwmodel"),
        firmware={"driver": c.get("x-nvidia-gpu-driver-version"), "vbios": c.get("x-nvidia-gpu-vbios-version"),
                  "oemid": c.get("oemid")},
        debug_enabled=(lambda v: None if v is None else (str(v).lower() == "enabled"))(c.get("dbgstat")),
        secure_boot=_tri(c.get("secboot")),
        measurements_match_reference=_all_true(c.get("measres"), c.get("x-nvidia-gpu-measurements-match")),
        cert_chain_valid=_all_true(chain_ok("x-nvidia-gpu-attestation-report-cert-chain"),
                                   c.get("x-nvidia-gpu-attestation-report-signature-verified")),
        nonce_matched=_tri(c.get("x-nvidia-gpu-attestation-report-nonce-match")),
        extra={"arch_check": c.get("x-nvidia-gpu-arch-check"), "rim_chain_ok": rim_ok,
               "warning": c.get("x-nvidia-attestation-warning"), "switch_pdis": c.get("x-nvidia-gpu-switch-pdis")},
    )
    # A GPU that produced a signed CC attestation report is, by construction, in CC mode.
    if d.cert_chain_valid:
        d.cc_mode = "ON"
    return d


def parse_nras(path: str, keys: List[Dict[str, Any]]) -> EvidenceSource:
    data = read_text_or_json(path)
    overall: Optional[JWT] = None
    detached: Dict[str, Any] = {}
    if isinstance(data, str) and looks_like_jwt(data):
        overall = parse_jwt(data)
    elif isinstance(data, list):                       # [["JWT", overall], {"GPU-0": jwt}]
        for item in data:
            if isinstance(item, list) and len(item) == 2 and item[0] == "JWT":
                overall = parse_jwt(item[1])
            elif isinstance(item, dict):
                detached.update(item)
    elif isinstance(data, dict):
        if any(k.upper().startswith(("GPU-", "SWITCH-")) for k in data):
            detached = data
        else:                                          # already-decoded claims set
            detached = {"GPU-0": data}
    src = _jwt_source("nras", path, overall) if overall else EvidenceSource(source="nras", path=path, format="jwt")
    if overall:
        verify_jwt(overall, keys)
        src.signature_verified, src.verify_note = overall.signature_verified, overall.verify_note
        src.nonce = overall.payload.get("eat_nonce")
        src.overall_result = _tri(overall.payload.get("x-nvidia-overall-att-result"))
        # v2 tokens carry the GPU claims inline
        if not detached and "measres" in overall.payload:
            detached = {"GPU-0": overall.payload}
    for name, tok in detached.items():
        claims = tok
        if isinstance(tok, str) and looks_like_jwt(tok):
            j = parse_jwt(tok)
            verify_jwt(j, keys)
            claims = j.payload
            if j.signature_verified is False and "unsigned" not in j.verify_note:
                src.warnings.append(f"{name}: detached claims signature failed verification")
        if isinstance(claims, dict):
            src.devices.append(_nvidia_device_from_claims(name, claims))
    if src.overall_result is None and src.devices:
        src.overall_result = all(d.measurements_match_reference and d.cert_chain_valid for d in src.devices)
    return src


# ---------------------------------------------------------------------------
# Parser: Intel Trust Authority (TDX + optional nvgpu composite)
# ---------------------------------------------------------------------------

def parse_ita(path: str, keys: List[Dict[str, Any]]) -> EvidenceSource:
    data = read_text_or_json(path)
    jwt = parse_jwt(data if isinstance(data, str) else data.get("token", ""))
    verify_jwt(jwt, keys)
    c = jwt.payload
    src = _jwt_source("ita", path, jwt)
    src.nonce = c.get("attester_held_data") or c.get("eat_nonce")
    tcb = c.get("attester_tcb_status")
    if str(c.get("attester_type", "")).upper() == "TDX" or "tdx_mrtd" in c:
        attrs = c.get("tdx_td_attributes")
        dbg = c.get("tdx_is_debuggable")
        if dbg is None and isinstance(attrs, str):
            try:
                dbg = bool(int(attrs, 16) & 0x1)
            except ValueError:
                dbg = None
        d = DeviceFacts(
            kind="cpu-tee", vendor="Intel", tee="TDX", model="Intel TDX trust domain",
            firmware={"tdx_module_svn": c.get("tdx_seamsvn"), "mrseam": c.get("tdx_mrseam"),
                      "mrsignerseam": c.get("tdx_mrsignerseam"), "tcb_date": c.get("attester_tcb_date")},
            measurements={"mrtd": norm_hex(c.get("tdx_mrtd")),
                          **{f"rtmr{i}": norm_hex(c.get(f"tdx_rtmr{i}")) for i in range(4) if c.get(f"tdx_rtmr{i}")}},
            debug_enabled=_tri(dbg), migratable=_tri(c.get("tdx_is_migratable")),
            tcb_status=tcb, tcb_up_to_date=(None if tcb is None else str(tcb) == "UpToDate"),
            advisories=list(c.get("attester_advisory_ids") or []),
            report_data=norm_hex(c.get("tdx_report_data")) if c.get("tdx_report_data") else None,
            runtime_data=c.get("attester_runtime_data"),
            cert_chain_valid=True if jwt.signature_verified else None,
            extra={"cvm_compliance_status": c.get("cvm_compliance_status"),
                   "policy_ids_matched": c.get("policy_ids_matched"),
                   "policy_ids_unmatched": c.get("policy_ids_unmatched"), "td_attributes": attrs},
        )
        # RTMRs present means the boot chain was measured into the TD (measured boot)
        if any(k.startswith("rtmr") for k in d.measurements):
            d.secure_boot = True
        src.devices.append(d)
    nv = c.get("nvgpu")
    if isinstance(nv, dict):
        gpus = nv.get("gpus") or nv.get("devices") or ([nv] if "hwmodel" in nv or "measres" in nv else [])
        for i, g in enumerate(gpus):
            src.devices.append(_nvidia_device_from_claims(f"GPU-{i}", g))
    if c.get("policy_ids_unmatched"):
        src.warnings.append(f"Intel Trust Authority policy(ies) unmatched: {c['policy_ids_unmatched']}")
    src.overall_result = (not c.get("policy_ids_unmatched")) and all(
        (d.tcb_up_to_date is not False) and (d.debug_enabled is not True) for d in src.devices)
    return src


# ---------------------------------------------------------------------------
# Parser: Microsoft Azure Attestation (SEV-SNP CVM, TDX CVM)
# ---------------------------------------------------------------------------

def parse_maa(path: str, keys: List[Dict[str, Any]]) -> EvidenceSource:
    data = read_text_or_json(path)
    jwt = parse_jwt(data if isinstance(data, str) else data.get("token", ""))
    verify_jwt(jwt, keys)
    c = jwt.payload
    src = _jwt_source("maa", path, jwt)
    src.nonce = c.get("nonce")
    att_type = str(c.get("x-ms-attestation-type", "")).lower()
    runtime = c.get("x-ms-runtime") or {}
    vmcfg = runtime.get("vm-configuration") or {}
    if att_type == "sevsnpvm" or any(k.startswith("x-ms-sevsnpvm-") for k in c):
        d = DeviceFacts(
            kind="cpu-tee", vendor="AMD", tee="SEV-SNP", model="AMD SEV-SNP confidential VM",
            identity=vmcfg.get("vmUniqueId"),
            firmware={"bootloader_svn": c.get("x-ms-sevsnpvm-bootloader-svn"), "tee_svn": c.get("x-ms-sevsnpvm-tee-svn"),
                      "snpfw_svn": c.get("x-ms-sevsnpvm-snpfw-svn"), "microcode_svn": c.get("x-ms-sevsnpvm-microcode-svn"),
                      "guest_svn": c.get("x-ms-sevsnpvm-guestsvn"), "hcl_family": c.get("x-ms-sevsnpvm-familyId"),
                      "hcl_image": c.get("x-ms-sevsnpvm-imageId")},
            measurements={"launch_measurement": norm_hex(c.get("x-ms-sevsnpvm-launchmeasurement")),
                          "host_data": norm_hex(c.get("x-ms-sevsnpvm-hostdata")),
                          "id_key_digest": norm_hex(c.get("x-ms-sevsnpvm-idkeydigest"))},
            debug_enabled=_tri(c.get("x-ms-sevsnpvm-is-debuggable")),
            migratable=_tri(c.get("x-ms-sevsnpvm-migration-allowed")),
            smt_enabled=_tri(c.get("x-ms-sevsnpvm-smt-allowed")),
            secure_boot=_tri(vmcfg.get("secure-boot")),
            report_data=norm_hex(c.get("x-ms-sevsnpvm-reportdata")) if c.get("x-ms-sevsnpvm-reportdata") else None,
            runtime_data=json.dumps(runtime, sort_keys=True) if runtime else None,
            cert_chain_valid=True if jwt.signature_verified else None,
            measurements_match_reference=(str(c.get("x-ms-compliance-status", "")).lower() == "azure-compliant-cvm") or None,
            extra={"compliance_status": c.get("x-ms-compliance-status"), "vmpl": c.get("x-ms-sevsnpvm-vmpl"),
                   "policy_hash": c.get("x-ms-policy-hash"), "tpm_enabled": vmcfg.get("tpm-enabled")},
        )
        src.devices.append(d)
    elif att_type == "tdxvm" or any(k.startswith("x-ms-tdx-") for k in c):
        d = DeviceFacts(kind="cpu-tee", vendor="Intel", tee="TDX", model="Intel TDX confidential VM (Azure)",
                        measurements={k.replace("x-ms-tdx-", ""): norm_hex(v) for k, v in c.items()
                                      if k.startswith("x-ms-tdx-") and ("mr" in k or "rtmr" in k)},
                        debug_enabled=_tri(c.get("x-ms-tdx-is-debuggable")),
                        secure_boot=_tri(vmcfg.get("secure-boot")),
                        cert_chain_valid=True if jwt.signature_verified else None,
                        extra={"compliance_status": c.get("x-ms-compliance-status")})
        src.devices.append(d)
    src.overall_result = all(d.debug_enabled is not True for d in src.devices) if src.devices else None
    return src


# ---------------------------------------------------------------------------
# Parser: Google Confidential Space token
# ---------------------------------------------------------------------------

_GCP_REGION_JURISDICTION = {
    "europe-": "EU/EEA", "us-": "US", "asia-": "APAC", "australia-": "APAC", "me-": "Middle East",
    "africa-": "Africa", "southamerica-": "LATAM", "northamerica-": "North America",
}


def parse_gcs(path: str, keys: List[Dict[str, Any]]) -> EvidenceSource:
    data = read_text_or_json(path)
    jwt = parse_jwt(data if isinstance(data, str) else data.get("token", ""))
    verify_jwt(jwt, keys)
    c = jwt.payload
    src = _jwt_source("gcs", path, jwt)
    src.nonce = c.get("eat_nonce")
    sub = c.get("submods") or {}
    gce, cont, cs = sub.get("gce") or {}, sub.get("container") or {}, sub.get("confidential_space") or {}
    hw = str(c.get("hwmodel", ""))
    tee = "TDX" if "TDX" in hw else "SEV-SNP" if "SEV" in hw else "Shielded VM"
    zone = gce.get("zone")
    juris = next((v for k, v in _GCP_REGION_JURISDICTION.items() if zone and zone.startswith(k)), None)
    d = DeviceFacts(
        kind="cpu-tee", vendor="Google Cloud / " + ("Intel" if tee == "TDX" else "AMD"), tee="Confidential Space",
        identity=gce.get("instance_id"), model=hw,
        firmware={"swname": c.get("swname"), "swversion": c.get("swversion"),
                  "support_attributes": cs.get("support_attributes")},
        measurements={"container_image_digest": norm_hex(cont.get("image_digest")) if cont.get("image_digest") else None,
                      "container_image_reference": cont.get("image_reference")},
        debug_enabled=(None if c.get("dbgstat") is None else str(c.get("dbgstat")).lower() != "disabled-since-boot"),
        secure_boot=_tri(c.get("secboot")),
        cert_chain_valid=True if jwt.signature_verified else None,
        location={"cloud_zone": zone, "jurisdiction_hint": juris, "project_id": gce.get("project_id"),
                  "instance_name": gce.get("instance_name"), "attested": zone is not None},
        workload={"image_reference": cont.get("image_reference"), "restart_policy": cont.get("restart_policy"),
                  "args": cont.get("args"), "service_accounts": c.get("google_service_accounts")},
        extra={"aud": c.get("aud"), "oemid": c.get("oemid")},
    )
    if cs.get("support_attributes") is not None:
        d.tcb_status = ",".join(cs["support_attributes"])
        d.tcb_up_to_date = "LATEST" in cs["support_attributes"] or "STABLE" in cs["support_attributes"]
    src.devices.append(d)
    ng = sub.get("nvidia_gpu")
    if isinstance(ng, dict):
        for i, g in enumerate(ng.get("gpus") or []):
            gd = DeviceFacts(kind="gpu", vendor="NVIDIA", tee="NVIDIA-CC", identity=g.get("ueid"), model=g.get("hwmodel"),
                             firmware={"driver": g.get("driver_version"), "vbios": g.get("vbios_version")},
                             cc_mode=ng.get("cc_mode"), extra={"cc_feature": ng.get("cc_feature")})
            gd.debug_enabled = None if ng.get("cc_mode") is None else str(ng.get("cc_mode")).upper() == "DEVTOOLS"
            gd.extra["platform_verified"] = True  # Google validates GPU attestation before issuing the token
            src.devices.append(gd)
    src.overall_result = all(d.debug_enabled is not True for d in src.devices)
    return src


# ---------------------------------------------------------------------------
# AMD SEV-SNP report verification against AMD's Key Distribution Service (VCEK → ASK → ARK)
# ---------------------------------------------------------------------------

AMD_KDS_BASE = "https://kdsintf.amd.com/vcek/v1"
_SNP_PRODUCTS = {(0x19, 0x01): "Milan", (0x19, 0x11): "Genoa", (0x19, 0xA1): "Genoa", (0x1A, 0x02): "Turin", (0x1A, 0x11): "Turin"}


def _http_get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"tee-attestation-connector/{CONNECTOR_VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _tlv_spans(buf: bytes) -> List[Tuple[int, bytes, bytes]]:
    """DER walk returning (tag, full TLV bytes, body bytes) for each element."""
    out, pos = [], 0
    while pos < len(buf):
        start = pos
        tag = buf[pos]; pos += 1
        ln = buf[pos]; pos += 1
        if ln & 0x80:
            nb = ln & 0x7F; ln = int.from_bytes(buf[pos: pos + nb], "big"); pos += nb
        out.append((tag, buf[start: pos + ln], buf[pos: pos + ln])); pos += ln
    return out


def _x509_tbs_and_sig(der: bytes) -> Tuple[bytes, bytes]:
    top = _tlv_spans(der)[0][2]
    tbs, _alg, sig = _tlv_spans(top)[:3]
    return tbs[1], sig[2][1:]  # TBS with header; signature BIT STRING without unused-bits byte


def _x509_rsa_key(der: bytes) -> Tuple[int, int]:
    j = jwk_from_x5c(base64.b64encode(der).decode())
    if j.get("kty") != "RSA":
        raise ValueError("expected RSA key in certificate")
    return _int_from_b64url(j["n"]), _int_from_b64url(j["e"])


def snp_product(report: bytes) -> str:
    fam, mod = report[0x188], report[0x189]
    return _SNP_PRODUCTS.get((fam, mod)) or ("Turin" if fam == 0x1A else "Genoa")


def verify_snp_report(report: bytes, kds_base: str = AMD_KDS_BASE, cache_dir: Optional[str] = None,
                      ark_sha256: Optional[str] = None) -> Dict[str, Any]:
    """Fetch the VCEK for this chip/TCB and the ASK/ARK chain from AMD KDS (or a compatible proxy), then verify
    report signature (ECDSA-P384/SHA-384) and certificate chain (RSASSA-PSS SHA-384). Pure stdlib."""
    out: Dict[str, Any] = {"verified": False, "chain": {}, "note": ""}
    r = report[:SNP_REPORT_LEN]
    chip_id = r[0x1A0:0x1E0].hex()
    (reported_tcb,) = struct.unpack_from("<Q", r, 0x180)
    tcb = _tcb(reported_tcb)
    product = snp_product(r)
    vcek_url = f"{kds_base}/{product}/{chip_id}?blSPL={tcb['boot_loader']}&teeSPL={tcb['tee']}&snpSPL={tcb['snp']}&ucodeSPL={tcb['microcode']}"
    chain_url = f"{kds_base}/{product}/cert_chain"
    out.update({"product": product, "vcek_url": vcek_url, "chain_url": chain_url})
    try:
        vcek = None
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
            cp = os.path.join(cache_dir, f"vcek_{chip_id[:16]}_{tcb['boot_loader']}_{tcb['tee']}_{tcb['snp']}_{tcb['microcode']}.der")
            if os.path.exists(cp):
                vcek = open(cp, "rb").read()
        if vcek is None:
            vcek = _http_get(vcek_url)
            if cache_dir:
                open(cp, "wb").write(vcek)
        chain_pem = _http_get(chain_url)
        if cache_dir:
            open(os.path.join(cache_dir, f"{product.lower()}_cert_chain.pem"), "wb").write(chain_pem)
    except Exception as exc:
        out["note"] = f"could not fetch AMD collateral: {exc}"
        return out
    try:
        j = jwk_from_x5c(base64.b64encode(vcek).decode())
        if j.get("kty") != "EC" or j.get("crv") != "P-384":
            raise ValueError("VCEK is not a P-384 key")
        sigblk = r[0x2A0:0x4A0]
        rr, ss = int.from_bytes(sigblk[0:72], "little"), int.from_bytes(sigblk[72:144], "little")
        sig = rr.to_bytes(48, "big") + ss.to_bytes(48, "big")
        out["report_signature_ok"] = _ecdsa_verify("P-384", _int_from_b64url(j["x"]), _int_from_b64url(j["y"]), r[:0x2A0], sig)
        pems = re.findall(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", chain_pem, re.S)
        ders = [base64.b64decode(b"".join(p.split())) for p in pems]
        if len(ders) < 2:
            raise ValueError("cert_chain did not contain ASK and ARK")
        ask, ark = ders[0], ders[1]
        tbs, sg = _x509_tbs_and_sig(vcek); n, e = _x509_rsa_key(ask); out["chain"]["vcek_by_ask"] = _rsa_verify_pss(n, e, tbs, sg, "384")
        tbs, sg = _x509_tbs_and_sig(ask); n, e = _x509_rsa_key(ark); out["chain"]["ask_by_ark"] = _rsa_verify_pss(n, e, tbs, sg, "384")
        tbs, sg = _x509_tbs_and_sig(ark); n, e = _x509_rsa_key(ark); out["chain"]["ark_self_signed"] = _rsa_verify_pss(n, e, tbs, sg, "384")
        out["ark_sha256"] = hashlib.sha256(ark).hexdigest()
        out["ark_pinned"] = (out["ark_sha256"] == ark_sha256.lower()) if ark_sha256 else None
        out["verified"] = bool(out["report_signature_ok"] and all(out["chain"].values()) and out["ark_pinned"] is not False)
        out["note"] = ("report signature and VCEK→ASK→ARK chain verified locally" + (" (ARK pinned)" if out["ark_pinned"] else " (ARK not pinned; compare fingerprint with AMD's published root)")
                       if out["verified"] else "verification FAILED: " + json.dumps({k: v for k, v in out.items() if k in ("report_signature_ok", "chain", "ark_pinned")}))
    except Exception as exc:
        out["note"] = f"verification error: {exc}"
    return out


def fetch_wellknown_attestation(url: str, cache_dir: Optional[str] = None) -> Tuple[str, str]:
    """Fetch a published attestation document (Tinfoil-style {format, body}) and return (kind, path) where kind is
    'snp-report' or 'tdx-quote'. If url has no path, /.well-known/tinfoil-attestation is appended."""
    if not url.startswith("http"):
        url = "https://" + url
    if url.count("/") <= 2 or url.endswith("/"):
        url = url.rstrip("/") + "/.well-known/tinfoil-attestation"
    raw = _http_get(url)
    doc = json.loads(raw)
    fmt = str(doc.get("format", ""))
    body = doc.get("body", "")
    blob = base64.b64decode(body + "=" * (-len(body) % 4))
    if blob[:2] == b"\x1f\x8b":
        import gzip
        blob = gzip.decompress(blob)
    kind = "tdx-quote" if "tdx" in fmt.lower() else "snp-report"
    folder = cache_dir or "."
    os.makedirs(folder, exist_ok=True)
    host = re.sub(r"[^A-Za-z0-9.-]", "_", url.split("/")[2])
    path = os.path.join(folder, f"{host}.{ 'tdx_quote.bin' if kind == 'tdx-quote' else 'snp_report.bin'}")
    with open(path, "wb") as fh:
        fh.write(blob)
    with open(os.path.join(folder, f"{host}.attestation.json"), "wb") as fh:
        fh.write(raw)
    return kind, path


# ---------------------------------------------------------------------------
# Parser: raw AMD SEV-SNP ATTESTATION_REPORT (SEV-SNP ABI spec, Table "ATTESTATION_REPORT")
# ---------------------------------------------------------------------------

SNP_REPORT_LEN = 0x4A0  # 1184 bytes


def _tcb(v: int) -> Dict[str, int]:
    return {"boot_loader": v & 0xFF, "tee": (v >> 8) & 0xFF, "snp": (v >> 48) & 0xFF, "microcode": (v >> 56) & 0xFF}


def parse_snp_report(path: str, verify: bool = False, kds_base: str = AMD_KDS_BASE, cache_dir: Optional[str] = None,
                     ark_sha256: Optional[str] = None) -> EvidenceSource:
    with open(path, "rb") as fh:
        raw = fh.read()
    src = EvidenceSource(source="snp-report", path=path, format="binary", issuer="AMD Secure Processor (unverified)",
                         raw_claims_sha256=hashlib.sha256(raw[:SNP_REPORT_LEN]).hexdigest())
    if len(raw) < SNP_REPORT_LEN:
        src.warnings.append(f"report is {len(raw)} bytes; expected at least {SNP_REPORT_LEN}")
        return src
    r = raw[:SNP_REPORT_LEN]
    version, guest_svn, policy = struct.unpack_from("<IIQ", r, 0x000)
    family_id, image_id = r[0x010:0x020], r[0x020:0x030]
    vmpl, sig_algo, current_tcb, platform_info, flags = struct.unpack_from("<IIQQI", r, 0x030)
    report_data, measurement, host_data = r[0x050:0x090], r[0x090:0x0C0], r[0x0C0:0x0E0]
    id_key_digest, author_key_digest = r[0x0E0:0x110], r[0x110:0x140]
    report_id, report_id_ma = r[0x140:0x160], r[0x160:0x180]
    (reported_tcb,) = struct.unpack_from("<Q", r, 0x180)
    chip_id = r[0x1A0:0x1E0]
    (committed_tcb,) = struct.unpack_from("<Q", r, 0x1E0)
    cur_build, cur_minor, cur_major = r[0x1E8], r[0x1E9], r[0x1EA]
    com_build, com_minor, com_major = r[0x1EC], r[0x1ED], r[0x1EE]
    (launch_tcb,) = struct.unpack_from("<Q", r, 0x1F0)
    pol = {
        "abi_minor": policy & 0xFF, "abi_major": (policy >> 8) & 0xFF,
        "smt_allowed": bool(policy >> 16 & 1), "migrate_ma": bool(policy >> 18 & 1),
        "debug_allowed": bool(policy >> 19 & 1), "single_socket": bool(policy >> 20 & 1),
        "cxl_allowed": bool(policy >> 21 & 1), "mem_aes_256_xts": bool(policy >> 22 & 1),
        "rapl_disabled": bool(policy >> 23 & 1), "ciphertext_hiding": bool(policy >> 24 & 1),
    }
    signing_key = {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 0x7, "unknown")
    d = DeviceFacts(
        kind="cpu-tee", vendor="AMD", tee="SEV-SNP", identity=hexs(chip_id), model="AMD EPYC (SEV-SNP guest)",
        firmware={"report_version": version, "guest_svn": guest_svn, "current_tcb": _tcb(current_tcb),
                  "reported_tcb": _tcb(reported_tcb), "committed_tcb": _tcb(committed_tcb), "launch_tcb": _tcb(launch_tcb),
                  "fw_current": f"{cur_major}.{cur_minor}.{cur_build}", "fw_committed": f"{com_major}.{com_minor}.{com_build}",
                  "signing_key": signing_key, "signature_algo": sig_algo},
        measurements={"launch_measurement": hexs(measurement), "host_data": hexs(host_data),
                      "id_key_digest": hexs(id_key_digest), "author_key_digest": hexs(author_key_digest),
                      "family_id": hexs(family_id), "image_id": hexs(image_id), "report_id": hexs(report_id)},
        debug_enabled=pol["debug_allowed"], migratable=pol["migrate_ma"],
        smt_enabled=bool(platform_info & 1),
        tcb_up_to_date=(reported_tcb >= committed_tcb) and (current_tcb >= committed_tcb),
        tcb_status="reported TCB ≥ committed TCB" if reported_tcb >= committed_tcb else "reported TCB below committed TCB",
        report_data=hexs(report_data),
        cert_chain_valid=None,  # needs VCEK/VLEK chain from AMD KDS (https://kdsintf.amd.com) — not fetched by design
        extra={"policy": pol, "vmpl": vmpl, "platform_info": {"smt_en": bool(platform_info & 1), "tsme_en": bool(platform_info >> 1 & 1)},
               "report_id_ma": hexs(report_id_ma), "author_key_en": bool(flags & 1)},
    )
    d.model = f"AMD EPYC {snp_product(r)} (SEV-SNP guest)"
    src.devices.append(d)
    if verify:
        v = verify_snp_report(raw, kds_base=kds_base, cache_dir=cache_dir, ark_sha256=ark_sha256)
        src.extra_verification = v
        if v.get("verified"):
            d.cert_chain_valid = True
            src.signature_verified = True
            src.issuer = f"AMD Secure Processor ({v['product']}) — VCEK chain verified to AMD root"
            src.verify_note = v["note"]
        else:
            src.signature_verified = False
            src.verify_note = v.get("note", "verification failed")
            src.warnings.append("raw SEV-SNP report: " + src.verify_note)
    else:
        src.warnings.append("raw SEV-SNP report: signature not verified (pass --verify-amd to fetch the VCEK chain from AMD KDS)")
    src.overall_result = not pol["debug_allowed"]
    return src


# ---------------------------------------------------------------------------
# Parser: raw Intel TDX quote (v4 / v5) — header + TDREPORT body, signature left to a verifier
# ---------------------------------------------------------------------------

def parse_tdx_quote(path: str) -> EvidenceSource:
    with open(path, "rb") as fh:
        raw = fh.read()
    src = EvidenceSource(source="tdx-quote", path=path, format="binary", issuer="Intel TDX module / Quoting Enclave (unverified)",
                         raw_claims_sha256=hashlib.sha256(raw).hexdigest())
    if len(raw) < 48 + 584:
        src.warnings.append(f"quote is {len(raw)} bytes; too short for a TDX quote")
        return src
    version, att_key_type, tee_type = struct.unpack_from("<HHI", raw, 0)
    qe_vendor_id, user_data = raw[16:32], raw[32:52][:20]
    body_off = 48
    if version == 5:
        body_type, body_size = struct.unpack_from("<HI", raw, 48)
        body_off = 54
    b = raw[body_off: body_off + 584]
    off = 0

    def take(n: int) -> bytes:
        nonlocal off
        chunk = b[off: off + n]
        off += n
        return chunk

    tee_tcb_svn, mr_seam, mr_signer_seam = take(16), take(48), take(48)
    seam_attrs, td_attrs, xfam = take(8), take(8), take(8)
    mr_td, mr_config_id, mr_owner, mr_owner_config = take(48), take(48), take(48), take(48)
    rtmrs = [take(48) for _ in range(4)]
    report_data = take(64)
    td_attr_int = int.from_bytes(td_attrs, "little")
    d = DeviceFacts(
        kind="cpu-tee", vendor="Intel", tee="TDX", model="Intel TDX trust domain (raw quote)",
        firmware={"quote_version": version, "attestation_key_type": att_key_type, "tee_type": hex(tee_type),
                  "tee_tcb_svn": hexs(tee_tcb_svn), "mrseam": hexs(mr_seam), "mrsignerseam": hexs(mr_signer_seam),
                  "xfam": hexs(xfam), "qe_vendor_id": hexs(qe_vendor_id)},
        measurements={"mrtd": hexs(mr_td), "mr_config_id": hexs(mr_config_id), "mr_owner": hexs(mr_owner),
                      "mr_owner_config": hexs(mr_owner_config), **{f"rtmr{i}": hexs(v) for i, v in enumerate(rtmrs)}},
        debug_enabled=bool(td_attr_int & 0x1),
        secure_boot=any(any(v) for v in rtmrs) or None,
        report_data=hexs(report_data),
        extra={"td_attributes": hexs(td_attrs), "perfmon": bool(td_attr_int >> 63 & 1), "seam_attributes": hexs(seam_attrs)},
    )
    if tee_type != 0x81:
        src.warnings.append(f"tee_type is {hex(tee_type)}; expected 0x81 (TDX)")
    src.devices.append(d)
    src.warnings.append("raw TDX quote: signature and TCB status not verified (needs Intel PCS collateral); pair with an Intel Trust Authority token")
    src.overall_result = not d.debug_enabled
    return src


# ---------------------------------------------------------------------------
# Location evidence (network-inferred). Honest ceiling: no attestation token carries location today.
# ---------------------------------------------------------------------------

FIBRE_KM_PER_MS_RTT = 100.0   # ~200,000 km/s in fibre → one-way distance ≤ RTT(ms) × 100 km


def _json_get(url: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": f"tee-attestation-connector/{CONNECTOR_VERSION}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _tcp_rtt_ms(ip: str, port: int = 443, n: int = 5) -> Optional[float]:
    import socket, time as _t
    best = None
    for _ in range(n):
        s = socket.socket(); s.settimeout(5)
        t0 = _t.perf_counter()
        try:
            s.connect((ip, port))
        except Exception:
            s.close(); continue
        s.close()
        rtt = (_t.perf_counter() - t0) * 1000
        best = rtt if best is None else min(best, rtt)
    return best


def tls_key_binding(host: str, sources: List[EvidenceSource]) -> Dict[str, Any]:
    """Fetch the live TLS leaf certificate and test whether SHA-256(SubjectPublicKeyInfo) — or the whole cert —
    appears in the REPORT_DATA / report_data of any attested device. If it does, the key that completes a TLS
    handshake with us is a key the hardware-signed report vouches for, so handshake timing bounds the attested machine."""
    import ssl, socket
    out: Dict[str, Any] = {"host": host, "bound": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sk, ctx.wrap_socket(sk, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True); out["tls_version"] = ss.version()
    except Exception as exc:
        out["error"] = f"TLS fetch failed: {exc}"; return out
    top = _tlv_spans(der)[0][2]; tbs = _tlv_spans(top)[0][2]; fields = _tlv_spans(tbs)
    idx = 1 if fields[0][0] == 0xA0 else 0
    spki = fields[idx + 5][1]
    digests = {"sha256(spki)": hashlib.sha256(spki).hexdigest(), "sha256(cert)": hashlib.sha256(der).hexdigest(),
               "sha384(spki)": hashlib.sha384(spki).hexdigest(), "sha512(spki)": hashlib.sha512(spki).hexdigest()}
    out["cert_sha256"] = digests["sha256(cert)"]
    for src in sources:
        for d in src.devices:
            rd = (d.report_data or "").lower()
            for name, hx in digests.items():
                if rd and hx in rd:
                    out.update({"bound": True, "binding": name, "device": f"{d.vendor} {d.tee}", "source": src.source,
                                "signature_verified": src.signature_verified})
                    return out
    out["note"] = "no attested device's report data contains the TLS public-key digest; timing bounds the TLS endpoint, not an attested machine"
    return out


def _tls_handshake_ms(host: str, ip: str, n: int = 5) -> Optional[float]:
    import ssl, socket, time as _t
    best = None
    for _ in range(n):
        try:
            c = ssl.create_default_context()
            sk = socket.socket(); sk.settimeout(5); sk.connect((ip, 443))
            t0 = _t.perf_counter()
            ss = c.wrap_socket(sk, server_hostname=host, do_handshake_on_connect=False); ss.do_handshake()
            d = (_t.perf_counter() - t0) * 1000; ss.close()
            best = d if best is None else min(best, d)
        except Exception:
            continue
    return best


def location_evidence(host: str, sources: List[EvidenceSource], vantage: Optional[str] = None,
                      globalping: bool = False, probe_cities: Optional[List[str]] = None) -> Dict[str, Any]:
    """Assemble every location signal an outside verifier can get today, each with its assurance label.
    L1 platform-asserted (cloud zone claim) > L0.5 network-inferred (registry + RTT bounds) > L0 declared.
    Hardware-attested location (a nonce-bound, chip-signed timed response) is reported as unavailable."""
    import socket
    out: Dict[str, Any] = {"host": host, "signals": [], "assurance": "none",
                           "hardware_attested": {"available": False,
                                                 "note": "No NVIDIA, Intel, AMD, Azure or Google attestation format carries a location claim (checked Sep 2026). "
                                                         "A chip-signed, nonce-bound timed response (delay-based distance bounding rooted in the TEE) exists only as a design."}}
    for src in sources:
        for d in src.devices:
            if d.location.get("attested"):
                out["signals"].append({"level": "L1 platform-asserted", "source": src.source, "zone": d.location.get("cloud_zone"),
                                       "jurisdiction_hint": d.location.get("jurisdiction_hint"),
                                       "note": "cloud provider asserts the zone inside its signed token; not measured by the chip"})
                out["assurance"] = "L1 platform-asserted"
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443)})
    except Exception as exc:
        out["signals"].append({"level": "error", "note": f"DNS failed: {exc}"}); return out
    out["endpoint_ips"] = ips
    if len(ips) > 2:
        out["signals"].append({"level": "warning", "note": f"{len(ips)} addresses; possible CDN/anycast — RTT would bound an edge, not the host"})
    ip = ips[0]
    try:
        pv = _json_get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}")["data"]
        asns = [{"asn": a.get("asn"), "holder": a.get("holder")} for a in pv.get("asns", [])]
        geo = None
        try:
            geo = [g.get("location") for g in _json_get(f"https://stat.ripe.net/data/rir-geo/data.json?resource={ip}")["data"].get("located_resources", [])]
        except Exception:
            pass
        out["signals"].append({"level": "L0.5 network-inferred", "kind": "registry", "prefix": pv.get("resource"), "asns": asns, "rir_registered_country": geo,
                               "note": "who announces the address block and where the registry records it (public routing/RIR data); says who operates the network, not where the chip is"})
        if out["assurance"] == "none":
            out["assurance"] = "L0.5 network-inferred"
    except Exception as exc:
        out["signals"].append({"level": "error", "kind": "registry", "note": str(exc)})
    binding = tls_key_binding(host, sources)
    out["tls_key_binding"] = binding
    rtt = _tcp_rtt_ms(ip)
    tls_ms = _tls_handshake_ms(host, ip) if binding.get("bound") else None
    if rtt is not None:
        sig = {"level": "L0.5 network-inferred", "kind": "rtt-local", "vantage": vantage or "this machine (location not given)",
               "min_rtt_ms": round(rtt, 1), "max_distance_km": round(rtt * FIBRE_KM_PER_MS_RTT),
               "note": "upper bound on distance from the vantage point to the responding endpoint (speed of light in fibre)"}
        if tls_ms is not None:
            sig.update({"level": "L2 attestation-bound", "tls_handshake_ms": round(tls_ms, 1), "tls_over_tcp": round(tls_ms / rtt, 2),
                        "max_distance_km_attested": round(tls_ms * FIBRE_KM_PER_MS_RTT),
                        "note": "TLS 1.3 handshake must be signed by the key bound in the hardware report; its time bounds the attested machine, "
                                "not just the TCP responder. tls_over_tcp near 1 ⇒ no relay between network endpoint and key holder"})
            out["assurance"] = "L2 attestation-bound distance bound"
        out["signals"].append(sig)
    if globalping:
        cities = probe_cities or ["San Jose", "Los Angeles", "Seattle", "Dallas", "Ashburn", "Frankfurt", "Tokyo", "Singapore"]
        try:
            use_http = bool(binding.get("bound"))
            body = ({"type": "http", "target": host, "limit": len(cities), "locations": [{"magic": c} for c in cities],
                     "measurementOptions": {"protocol": "HTTPS", "request": {"method": "HEAD", "path": "/"}}} if use_http else
                    {"type": "ping", "target": ip, "limit": len(cities), "locations": [{"magic": c} for c in cities], "measurementOptions": {"packets": 4}})
            req = urllib.request.Request("https://api.globalping.io/v1/measurements", data=json.dumps(body).encode(),
                                         headers={"User-Agent": f"tee-attestation-connector/{CONNECTOR_VERSION}", "Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as r:
                mid = json.loads(r.read())["id"]
            import time as _t
            m = None
            for _ in range(25):
                _t.sleep(2)
                m = _json_get(f"https://api.globalping.io/v1/measurements/{mid}")
                if m.get("status") == "finished":
                    break
            probes = []
            for res in (m or {}).get("results", []):
                p, rr = res.get("probe", {}), (res.get("result") or {})
                if use_http:
                    t = rr.get("timings") or {}
                    if t.get("tls") is not None and t.get("tcp") is not None:
                        probes.append({"city": p.get("city"), "country": p.get("country"), "network": p.get("network"),
                                       "tcp_ms": t["tcp"], "tls_ms": t["tls"], "min_rtt_ms": t["tcp"],
                                       "max_distance_km": round(t["tcp"] * FIBRE_KM_PER_MS_RTT),
                                       "max_distance_km_attested": round(t["tls"] * FIBRE_KM_PER_MS_RTT),
                                       "tls_over_tcp": round(t["tls"] / t["tcp"], 2) if t["tcp"] else None})
                else:
                    st = rr.get("stats") or {}
                    if st.get("min") is not None:
                        probes.append({"city": p.get("city"), "country": p.get("country"), "network": p.get("network"),
                                       "min_rtt_ms": st["min"], "max_distance_km": round(st["min"] * FIBRE_KM_PER_MS_RTT)})
            probes.sort(key=lambda x: x["min_rtt_ms"])
            anycast = len(probes) >= 4 and all(pr["min_rtt_ms"] < 25 for pr in probes)
            # A relay must forward the handshake to the real key holder, adding at least one extra round trip from the probe
            # nearest the relay. Honest servers show a near-constant (tls - tcp) = signing + one RTT overhead at every probe.
            deltas = sorted(pr["tls_ms"] - pr["tcp_ms"] for pr in probes if pr.get("tls_ms") is not None)
            med = deltas[len(deltas) // 2] if deltas else 0
            relay_suspect = use_http and bool(deltas) and any(d > max(2 * med, med + 20) for d in deltas)
            overhead_note = f"handshake overhead (tls-tcp) {min(deltas):.0f}–{max(deltas):.0f} ms across probes, median {med:.0f} ms" if deltas else ""
            out["signals"].append({"level": "L2 attestation-bound" if use_http else "L0.5 network-inferred", "kind": "rtt-multi-vantage",
                                   "probes": probes, "nearest": probes[0] if probes else None, "anycast_suspected": anycast,
                                   "relay_suspected": relay_suspect,
                                   "note": ("all vantage points see <25 ms: anycast/CDN in front, bounds are meaningless for the host" if anycast else
                                            (f"TLS handshake signed by the attestation-bound key: the tightest tls_ms bound locates the attested machine; {overhead_note}; "
                                             + ("inconsistent overhead ⇒ RELAY suspected" if relay_suspect else "constant overhead ⇒ no relay") if use_http else
                                             "each probe gives an upper bound on distance to the responding host; the tightest bound names the nearest city"))})
        except Exception as exc:
            out["signals"].append({"level": "error", "kind": "rtt-multi-vantage", "note": str(exc)})
    return out


# ---------------------------------------------------------------------------
# Governance checks and control mapping
# ---------------------------------------------------------------------------

CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
    "G01": {"EU AI Act": ["Art. 15(5) cybersecurity", "Annex IV §1(e) hardware description", "Annex IV §2(h) cybersecurity measures"],
            "SOC 2": ["CC6.1", "CC6.6"], "ISO/IEC 42001": ["A.4.5 system & computing resources"], "ISO/IEC 27001": ["A.8.9", "A.5.23"],
            "NIST AI RMF": ["MEASURE 2.7"]},
    "G02": {"EU AI Act": ["Art. 15(5) confidentiality attacks", "Art. 10(5) data protection", "Art. 55(1)(d) GPAI infra security"],
            "SOC 2": ["CC6.1", "CC6.7", "C1.1"], "ISO/IEC 42001": ["A.4.5"], "ISO/IEC 27001": ["A.8.24 cryptography"]},
    "G03": {"EU AI Act": ["Art. 15(5) confidentiality attacks", "Annex IV §2(h)"], "SOC 2": ["CC6.1", "CC6.8"],
            "ISO/IEC 27001": ["A.8.9 configuration management"]},
    "G04": {"EU AI Act": ["Annex IV §1(c) firmware versions", "Art. 15(4) resilience"], "SOC 2": ["CC6.8", "CC7.1"],
            "NIST": ["SP 800-193 firmware resiliency"]},
    "G05": {"EU AI Act": ["Annex IV §1(c)", "Annex IV §6 lifecycle changes", "Art. 15(5) model poisoning"], "SOC 2": ["CC6.8", "CC7.1", "CC8.1"],
            "ISO/IEC 27001": ["A.8.9", "A.8.19"]},
    "G06": {"EU AI Act": ["Art. 15(5) vulnerabilities", "Annex IV §6"], "SOC 2": ["CC7.1 vulnerability mgmt"], "ISO/IEC 27001": ["A.8.8"]},
    "G07": {"EU AI Act": ["Art. 15(5) confidentiality attacks"], "SOC 2": ["CC6.1", "CC6.7"]},
    "G08": {"EU AI Act": ["Annex IV §1(a) versions", "Annex IV §2(c) system architecture", "Art. 12 record-keeping"],
            "SOC 2": ["CC8.1 change management", "CC7.1"], "ISO/IEC 42001": ["A.6.2.4 verification & validation", "A.6.2.7 technical documentation"]},
    "G09": {"EU AI Act": ["Annex IV §1(a) model version", "Annex IV §6", "Art. 12 traceability"], "SOC 2": ["CC8.1", "CC6.8"],
            "ISO/IEC 42001": ["A.6.2.7", "A.8.4 communication of incidents"]},
    "G10": {"EU AI Act": ["Art. 12 & Art. 19 automatic logs (≥ 6 months)", "Art. 72 post-market monitoring"], "SOC 2": ["CC7.2 monitoring"],
            "ISO/IEC 42001": ["A.6.2.6 operation & monitoring"]},
    "G11": {"EU AI Act": ["Annex IV §1(e) deployment environment", "Art. 10(5)"], "SOC 2": ["CC6.6"],
            "Export controls": ["Chip Security Act (pending): location verification", "BIS licence conditions"], "GDPR": ["Ch. V transfers"]},
    "G12": {"EU AI Act": ["Art. 15(5)"], "SOC 2": ["CC6.7 data in motion"]},
}

CHECK_TITLES = {
    "G01": "Hardware identity chain: attestation signed by a key rooted in the silicon vendor",
    "G02": "Confidential-computing mode active on every attested device",
    "G03": "Debug / developer modes disabled on every attested device",
    "G04": "Secure or measured boot enforced (firmware measured into the TEE)",
    "G05": "Firmware & driver measurements match the vendor reference (RIM / golden values)",
    "G06": "Platform TCB up to date (no outstanding vendor security advisories)",
    "G07": "Isolation policy: live migration off, side-channel-relevant options recorded",
    "G08": "Attested workload measurement equals the documented reference (launch measurement / MRTD / image digest)",
    "G09": "Deployed model artefact cryptographically bound to the attestation (model digest in report data)",
    "G10": "Freshness: nonce matched and evidence within the retention / re-attestation window",
    "G11": "Deployment location: platform-asserted zone, or attestation-bound distance bound from multiple vantage points",
    "G12": "Multi-device protection: NVLink / NVSwitch attested or single-GPU passthrough confirmed",
}


@dataclass
class CheckResult:
    id: str
    title: str
    status: str                       # pass | fail | unknown | n/a
    evidence: List[str] = field(default_factory=list)
    controls: Dict[str, List[str]] = field(default_factory=dict)
    remediation: Optional[str] = None


def _known(oks: List[Optional[bool]]) -> Optional[bool]:
    """Evaluate over devices that report the property; unknown only if nobody reports it."""
    known = [o for o in oks if o is not None]
    if not known:
        return None
    return all(known)


def _status(ok: Optional[bool]) -> str:
    return "unknown" if ok is None else ("pass" if ok else "fail")


def run_checks(sources: List[EvidenceSource], expected_measurement: Optional[List[str]], model_digest: Optional[str],
               max_age_days: int, location: Optional[Dict[str, Any]] = None) -> List[CheckResult]:
    devices = [(s, d) for s in sources for d in s.devices]
    results: List[CheckResult] = []

    def add(cid: str, ok: Optional[bool], ev: List[str], remediation: Optional[str] = None, na: bool = False):
        results.append(CheckResult(cid, CHECK_TITLES[cid], "n/a" if na else _status(ok), ev, CONTROL_MAP[cid], remediation))

    # G01 identity chain
    ev, oks = [], []
    for s in sources:
        if s.format == "jwt":
            if s.signature_verified is True:
                oks.append(True); ev.append(f"{s.source}: {s.verify_note}")
            elif s.signature_verified is None:
                oks.append(None); ev.append(f"{s.source}: verifier-asserted token from {s.issuer} ({s.verify_note})")
            else:
                oks.append(False); ev.append(f"{s.source}: {s.verify_note}")
    for s, d in devices:
        if d.kind in ("gpu", "switch") and d.cert_chain_valid is not None:
            oks.append(d.cert_chain_valid); ev.append(f"{d.model or d.kind} {d.identity or ''}: device cert chain {'valid' if d.cert_chain_valid else 'INVALID'}")
        if s.format == "binary":
            if s.signature_verified is True:
                oks.append(True); ev.append(f"{s.source}: {s.verify_note}")
            elif s.signature_verified is False:
                oks.append(False); ev.append(f"{s.source}: {s.verify_note}")
            else:
                oks.append(None); ev.append(f"{s.source}: raw report, signature not verified (pass --verify-amd)")
    add("G01", (None if not oks else (False if False in oks else (None if None in oks else True))), ev,
        "Supply verifier JWKS (--jwks) so signatures are re-verified locally, or verify raw reports with vendor collateral.")

    # G02 CC mode
    ev, oks = [], []
    for s, d in devices:
        if d.kind in ("gpu", "switch"):
            oks.append(None if d.cc_mode is None else d.cc_mode.upper() == "ON")
            ev.append(f"{d.model or 'GPU'} {d.identity or ''}: cc_mode={d.cc_mode or 'not reported'}")
        else:
            oks.append(True); ev.append(f"{d.tee}: attestation implies TEE isolation active")
    add("G02", None if not oks else (False if False in oks else (None if None in oks else True)), ev,
        "Enable CC mode (nvidia-smi conf-compute -srs 1 / cloud CC-enabled SKU) and re-attest.")

    # G03 debug
    ev, oks = [], []
    for s, d in devices:
        oks.append(None if d.debug_enabled is None else not d.debug_enabled)
        ev.append(f"{d.tee} {d.identity or ''}: debug={'enabled' if d.debug_enabled else 'disabled' if d.debug_enabled is False else 'unknown'}")
    add("G03", None if not oks else (False if False in oks else (None if None in oks else True)), ev,
        "Re-launch with debug policy bits cleared (SNP policy bit 19, TDX TUD.DEBUG, GPU dbgstat).")

    # G04 secure boot
    ev, oks = [], []
    for s, d in devices:
        oks.append(d.secure_boot)
        ev.append(f"{d.tee} {d.identity or ''}: secure/measured boot=" + ("not reported" if d.secure_boot is None else str(d.secure_boot)))
    add("G04", _known(oks), ev, "Enable UEFI secure boot / measured boot in the CVM image; for raw SNP reports add the MAA or ITA token.")

    # G05 measurements match RIM
    ev, oks = [], []
    for s, d in devices:
        if d.kind in ("gpu", "switch") or d.measurements_match_reference is not None:
            oks.append(d.measurements_match_reference)
            state = ("platform-verified (no RIM detail in token)" if d.measurements_match_reference is None and d.extra.get("platform_verified")
                     else str(d.measurements_match_reference))
            ev.append(f"{d.model or d.tee} {d.identity or ''}: measurements match reference={state}; "
                      f"driver={d.firmware.get('driver')} vbios={d.firmware.get('vbios')}")
    add("G05", _known(oks), ev,
        "Update to a driver/vBIOS with a published RIM, or record the CSP compliance status claim.", na=not oks)

    # G06 TCB
    ev, oks = [], []
    for s, d in devices:
        if d.kind == "cpu-tee":
            oks.append(d.tcb_up_to_date)
            svns = {k: v for k, v in d.firmware.items() if k.endswith("_svn") and v is not None}
            ev.append(f"{d.tee} {d.identity or ''}: tcb_status={d.tcb_status or 'not reported'}"
                      + (f"; advisories={d.advisories}" if d.advisories else "") + (f"; svn={svns}" if svns else ""))
    add("G06", _known(oks), ev,
        "Apply platform firmware / microcode updates referenced by the advisories; re-attest.", na=not oks)

    # G07 isolation policy
    ev, oks = [], []
    for s, d in devices:
        if d.kind == "cpu-tee":
            oks.append(None if d.migratable is None else not d.migratable)
            ev.append(f"{d.tee} {d.identity or ''}: migratable={'not reported' if d.migratable is None else d.migratable}; smt={d.smt_enabled}")
    add("G07", _known(oks), ev,
        "Launch with migration disabled; document SMT decision in the Art. 15 risk assessment.", na=not oks)

    # G08 workload measurement vs expected
    ev, ok = [], None
    exp = {norm_hex(x) for x in (expected_measurement or [])}
    for s, d in devices:
        cands = {k: v for k, v in d.measurements.items() if v and k in ("launch_measurement", "mrtd", "container_image_digest")}
        for k, v in cands.items():
            if exp:
                hit = (v in exp)
                ok = hit if ok is None else (ok and hit)
                ev.append(f"{d.tee}: {k}={v[:16]}… {'in expected set' if hit else 'NOT in expected set'}")
            else:
                ev.append(f"{d.tee}: {k}={v[:16]}… (no --expected-measurement supplied)")
    add("G08", ok, ev, "Record the golden launch measurement / image digest in the model registry and pass it as --expected-measurement.",
        na=not ev)

    # G09 model digest binding
    ev, ok = [], None
    md = norm_hex(model_digest) if model_digest else None
    for s, d in devices:
        blobs = [x for x in (d.report_data, d.runtime_data, s.nonce) if x]
        if not blobs:
            continue
        if md:
            hit = any(md in norm_hex(b) or md in str(b).lower() for b in blobs)
            ok = hit if ok is None else (ok or hit)
            ev.append(f"{d.tee}: model digest {'FOUND' if hit else 'not found'} in report_data/runtime_data/nonce")
        else:
            ev.append(f"{d.tee}: report_data present ({(d.report_data or '')[:16]}…) — pass --model-digest to bind the model")
    add("G09", ok, ev, "Place SHA-256(model artefact) in REPORT_DATA / attester runtime data at launch so the running model is provable.",
        na=not ev)

    # G10 freshness
    ev, oks = [], []
    now = now_utc()
    for s in sources:
        if s.format == "jwt":
            if s.expires_at:
                exp_dt = _dt.datetime.fromisoformat(s.expires_at)
                oks.append(exp_dt > now); ev.append(f"{s.source}: token exp {s.expires_at} ({'valid' if exp_dt > now else 'EXPIRED'})")
            if s.issued_at:
                age = (now - _dt.datetime.fromisoformat(s.issued_at)).days
                oks.append(age <= max_age_days); ev.append(f"{s.source}: issued {s.issued_at}, age {age}d (window {max_age_days}d)")
            if s.nonce:
                ev.append(f"{s.source}: nonce present")
        for d in s.devices:
            if d.nonce_matched is not None:
                oks.append(d.nonce_matched); ev.append(f"{d.model or d.tee}: nonce match={d.nonce_matched}")
    add("G10", None if not oks else all(oks), ev, "Re-attest on a schedule (e.g. every deploy + daily) and retain tokens ≥ 6 months for Art. 19.")

    # G11 location
    ev, ok = [], None
    for s, d in devices:
        if d.location.get("attested"):
            ok = True
            ev.append(f"{d.tee}: zone={d.location.get('cloud_zone')} → {d.location.get('jurisdiction_hint')}")
    if location:
        for sg in location.get("signals", []):
            if sg.get("kind") == "registry":
                ev.append(f"network-inferred: prefix {sg.get('prefix')} announced by {sg.get('asns')}; RIR-registered country {sg.get('rir_registered_country')}")
            elif sg.get("kind") == "rtt-local":
                ev.append(f"network-inferred: min RTT {sg['min_rtt_ms']} ms from {sg['vantage']} → host within ~{sg['max_distance_km']} km")
            elif sg.get("kind") == "rtt-multi-vantage" and sg.get("nearest"):
                n = sg["nearest"]
                if n.get("tls_ms") is not None:
                    ev.append(f"attestation-bound: TLS key in chip report; nearest probe {n['city']}, {n['country']} completes the signed handshake in {n['tls_ms']} ms "
                              f"→ attested machine within ~{n['max_distance_km_attested']} km of it; handshake overhead {n['tls_ms']-n['tcp_ms']:.0f} ms"
                              + ("; RELAY suspected at some probe" if sg.get("relay_suspected") else "; consistent across probes, no relay"))
                    if not sg.get("relay_suspected") and not sg.get("anycast_suspected") and ok is None:
                        ok = True
                else:
                    ev.append(f"network-inferred: nearest probe {n['city']}, {n['country']} at {n['min_rtt_ms']} ms → host within ~{n['max_distance_km']} km of it"
                              + ("; ANYCAST suspected, bound not meaningful" if sg.get("anycast_suspected") else ""))
        b = location.get("tls_key_binding") or {}
        ev.append("TLS key bound in hardware report: " + (f"YES ({b.get('binding')}, {b.get('device')})" if b.get("bound") else "no"))
        ev.append("chip-signed location claim: not available from any token (Sep 2026); attestation-bound TLS timing is the strongest outside evidence")
    if ok is None:
        ev.append("No platform-attested location in evidence (NRAS/ITA/MAA tokens carry none today; Chip Security Act mechanisms not yet shipping)")
    add("G11", ok, ev, "Record deployment region from the CSP control plane as supporting evidence; network inference bounds the host, not the chip; track NVIDIA fleet-management / Chip Security Act location attestations.")

    # G12 multi-device
    ev, ok = [], None
    gpus = [d for _, d in devices if d.kind == "gpu"]
    switches = [d for _, d in devices if d.kind == "switch"]
    if gpus:
        spt = any(str(d.extra.get("cc_feature", "")).upper() == "SPT" for d in gpus)
        pdis = any(d.extra.get("switch_pdis") for d in gpus)
        ok = True if (len(gpus) == 1 or spt or switches or pdis) else None
        ev.append(f"{len(gpus)} GPU(s), {len(switches)} NVSwitch attestation(s); single-passthrough={spt}; switch PDIs={'yes' if pdis else 'no'}")
    add("G12", ok, ev, "For multi-GPU CC, include NVSwitch attestation (nvattest --switch) or PPCIE verifier output.", na=not gpus)
    return results


# ---------------------------------------------------------------------------
# Scoring, assurance level, report rendering
# ---------------------------------------------------------------------------

def assurance_level(sources: List[EvidenceSource]) -> Tuple[int, str]:
    if not sources:
        return 0, "L0 — no hardware evidence (self-declared)"
    if any(s.signature_verified for s in sources):
        return 3, "L3 — evidence independently re-verified against vendor / verifier keys"
    if any(s.format == "jwt" for s in sources):
        return 2, "L2 — verifier-attested (Intel Trust Authority / NRAS / Azure Attestation / Confidential Space token)"
    return 1, "L1 — raw device reports parsed, signatures not verified"


def coverage_score(results: List[CheckResult]) -> Tuple[int, int, int]:
    applicable = [r for r in results if r.status != "n/a"]
    passed = sum(1 for r in applicable if r.status == "pass")
    return (round(100 * passed / len(applicable)) if applicable else 0), passed, len(applicable)


def annex_iv_view(results: List[CheckResult], sources: List[EvidenceSource]) -> Dict[str, Any]:
    """What this evidence contributes to each Annex IV point, in the brief's §-numbering."""
    by = {r.id: r for r in results}
    fw = [dict(device=d.model or d.tee, **{k: v for k, v in d.firmware.items() if v is not None}) for s in sources for d in s.devices]
    return {
        "§1 General description": {"1(c) firmware/software versions": fw, "1(e) hardware the system runs on":
                                   sorted({(d.vendor, d.model or d.tee) for s in sources for d in s.devices}, key=str),
                                   "status": "auto" if fw else "gap"},
        "§2 Design & development": {"2(h) cybersecurity measures (hardware layer)": [by[i].status for i in ("G02", "G03", "G04", "G07")],
                                    "status": "auto-partial"},
        "§3 Monitoring, functioning & control": {"attested runtime state": [by[i].status for i in ("G05", "G06", "G10")], "status": "auto-partial"},
        "§4 Performance metrics": {"status": "n/a (see MLflow / W&B connectors)"},
        "§5 Risk management": {"inputs": "side-channel residual risk, vendor-root trust, TCB drift", "status": "manual"},
        "§6 Lifecycle changes": {"firmware/driver drift detection": by["G05"].status, "status": "auto-partial"},
        "§7 Standards applied": {"candidates": ["IETF RFC 9334 RATS", "IETF RFC 9711 EAT", "TCG DICE / SPDM", "NIST SP 800-193", "ISO/IEC 27001 A.8.24"],
                                 "status": "manual"},
        "§8 EU Declaration": {"status": "manual"},
        "§9 Post-market monitoring": {"re-attestation cadence evidence": by["G10"].status, "status": "auto-partial"},
    }


def render_markdown(meta: Dict[str, Any], sources: List[EvidenceSource], results: List[CheckResult], score: Tuple[int, int, int],
                    level: Tuple[int, str]) -> str:
    mark = {"pass": "✓", "fail": "✗", "unknown": "?", "n/a": "–"}
    lines = [
        f"# On-chip governance evidence — {meta.get('system_name') or 'AI system'}",
        "",
        f"Generated {meta['generated_at']} by tee_attestation_connector v{CONNECTOR_VERSION}. "
        f"Provider: {meta.get('provider') or '—'}. Environment: {meta.get('environment') or '—'}.",
        "",
        f"**Assurance level:** {level[1]}  ",
        f"**On-chip governance coverage:** {score[0]}/100 ({score[1]} of {score[2]} applicable checks pass)",
        "",
        "## 1. Evidence sources",
        "",
        "| Source | Issuer | Issued | Expires | Signature | Devices |",
        "|---|---|---|---|---|---|",
    ]
    for s in sources:
        sig = ("verified locally (vendor root)" if s.signature_verified and s.format == "binary" else "verified locally" if s.signature_verified
               else "FAILED" if s.signature_verified is False and "unsigned" not in s.verify_note
               else "verifier-asserted" if s.format == "jwt" else "not verified (raw)")
        lines.append(f"| {s.source} | {s.issuer or '—'} | {s.issued_at or '—'} | {s.expires_at or '—'} | {sig} | {len(s.devices)} |")
    lines += ["", "## 2. Attested devices", ""]
    for s in sources:
        for d in s.devices:
            lines.append(f"### {d.vendor} · {d.tee} · {d.model or d.kind}")
            lines.append(f"- Identity: `{d.identity or 'n/a'}`")
            lines.append(f"- Debug: {d.debug_enabled} · Secure/measured boot: {d.secure_boot} · CC mode: {d.cc_mode or 'n/a'} · Migratable: {d.migratable}")
            lines.append(f"- TCB: {d.tcb_status or 'n/a'} · Measurements match reference: {d.measurements_match_reference}")
            fw = {k: v for k, v in d.firmware.items() if v is not None and not isinstance(v, dict)}
            if fw:
                lines.append("- Firmware: " + ", ".join(f"{k}={v}" for k, v in fw.items()))
            for k, v in d.measurements.items():
                if v:
                    lines.append(f"- {k}: `{v}`")
            if d.location.get("attested"):
                lines.append(f"- Location (platform-attested): {d.location.get('cloud_zone')} ({d.location.get('jurisdiction_hint')})")
            lines.append("")
    lines += ["## 3. On-chip governance checks", "", "| # | Check | Result | Maps to |", "|---|---|---|---|"]
    for r in results:
        ctrl = "; ".join(f"{k}: {', '.join(v)}" for k, v in r.controls.items())
        lines.append(f"| {r.id} | {r.title} | {mark[r.status]} {r.status} | {ctrl} |")
    lines += ["", "### Evidence detail", ""]
    for r in results:
        lines.append(f"**{r.id} — {r.title}**")
        for e in r.evidence:
            lines.append(f"- {e}")
        if r.status in ("fail", "unknown") and r.remediation:
            lines.append(f"- ⚠ **Gap.** {r.remediation}")
        lines.append("")
    lines += ["## 4. Contribution to Annex IV", ""]
    for k, v in annex_iv_view(results, sources).items():
        lines.append(f"- **{k}** — {v.get('status')}")
    if meta.get("location_evidence"):
        loc = meta["location_evidence"]
        lines += ["", "## 4b. Location evidence (what an outside verifier can get today)", "",
                  f"Assurance: **{loc.get('assurance')}**. Hardware-attested location: **not available** — {loc['hardware_attested']['note']}", ""]
        for sg in loc.get("signals", []):
            if sg.get("kind") == "registry":
                lines.append(f"- Registry: prefix {sg.get('prefix')} announced by {sg.get('asns')}; RIR-registered country {sg.get('rir_registered_country')} — {sg.get('note')}")
            elif sg.get("kind") == "rtt-local":
                lines.append(f"- RTT from {sg['vantage']}: {sg['min_rtt_ms']} ms → within ~{sg['max_distance_km']} km — {sg['note']}")
            elif sg.get("kind") == "rtt-multi-vantage":
                if sg.get("probes") and sg["probes"][0].get("tls_ms") is not None:
                    lines.append(f"- Multi-vantage signed-handshake timing ({len(sg['probes'])} probes): " + "; ".join(
                        f"{p['city']} tcp {p['tcp_ms']} / tls {p['tls_ms']} ms (attested machine ≤{p['max_distance_km_attested']} km)" for p in sg["probes"][:8]) + f" — {sg['note']}")
                else:
                    lines.append(f"- Multi-vantage RTT ({len(sg.get('probes', []))} probes): " + "; ".join(f"{p['city']} {p['min_rtt_ms']} ms (≤{p['max_distance_km']} km)" for p in sg.get("probes", [])[:8]) + f" — {sg['note']}")
            elif sg.get("zone"):
                lines.append(f"- Platform-asserted zone: {sg['zone']} ({sg.get('jurisdiction_hint')}) — {sg['note']}")
        b = loc.get("tls_key_binding") or {}
        lines.append(f"- TLS key binding: {'YES — ' + str(b.get('binding')) + ' of the live certificate appears in the ' + str(b.get('device')) + ' report data' if b.get('bound') else 'not found'}")
    lines += ["", "## 5. Warnings", ""]
    warns = [f"- {s.source}: {w}" for s in sources for w in s.warnings]
    lines += warns or ["- none"]
    lines += ["", "## 6. What this evidence does not prove", "",
              "- Platform state ≠ model behaviour. Attestation proves *where and on what* the model ran, not *what it decided*. Pair with Art. 19 inference logs (Weave / inference SDK).",
              "- Trust roots are the silicon vendors (NVIDIA, Intel, AMD) and the verifier operator. Record this dependency in Annex IV §5 residual risks.",
              "- Side-channel and physical attacks remain out of scope of remote attestation; document compensating controls.",
              ""]
    return "\n".join(lines)


def print_console(results: List[CheckResult], score: Tuple[int, int, int], level: Tuple[int, str], out_json: str, out_md: str) -> None:
    mark = {"pass": "✓", "fail": "✗", "unknown": "?", "n/a": "–"}
    print("\n" + "=" * 78)
    print(" On-chip governance evidence · tee-attestation-connector")
    print("=" * 78)
    for r in results:
        print(f" {mark[r.status]}  {r.id}  {r.title}")
    print("-" * 78)
    print(f" Coverage: {score[0]}/100   ({score[1]}/{score[2]} applicable checks pass)")
    print(f" Assurance: {level[1]}")
    gaps = [r for r in results if r.status in ("fail", "unknown")]
    if gaps:
        print(f" ⚠ {len(gaps)} gap(s) flagged — see report section 3")
    print(f" Wrote {out_json}\n Wrote {out_md}")
    print("=" * 78 + "\n")


# ---------------------------------------------------------------------------
# Self-test: synthetic evidence, no hardware required
# ---------------------------------------------------------------------------

def _selftest_keypair() -> Tuple[int, Dict[str, Any]]:
    """Ephemeral P-256 key for the self-test only (never use for anything real)."""
    import secrets
    c = _CURVES["P-256"]
    d = secrets.randbelow(c["n"] - 1) + 1
    qx, qy = _ec_mul(d, (c["gx"], c["gy"]), c["p"])
    jwk = {"kty": "EC", "crv": "P-256", "kid": "selftest-key", "use": "sig",
           "x": b64url_encode(qx.to_bytes(32, "big")), "y": b64url_encode(qy.to_bytes(32, "big"))}
    return d, jwk


def _signed_jwt(payload: Dict[str, Any], d: int) -> str:
    import secrets
    c = _CURVES["P-256"]
    n, p = c["n"], c["p"]
    header = b64url_encode(json.dumps({"alg": "ES256", "typ": "JWT", "kid": "selftest-key"}).encode())
    body = b64url_encode(json.dumps(payload).encode())
    msg = f"{header}.{body}".encode("ascii")
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    while True:
        k = secrets.randbelow(n - 1) + 1
        x1, _ = _ec_mul(k, (c["gx"], c["gy"]), p)
        r = x1 % n
        if r == 0:
            continue
        s_ = pow(k, -1, n) * (e + r * d) % n
        if s_ != 0:
            break
    sig = r.to_bytes(32, "big") + s_.to_bytes(32, "big")
    return f"{header}.{body}.{b64url_encode(sig)}"


def _unsigned_jwt(payload: Dict[str, Any]) -> str:
    h = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    return f"{h}.{b64url_encode(json.dumps(payload).encode())}."


def write_selftest_fixtures(folder: str, model_digest: str) -> Dict[str, str]:
    os.makedirs(folder, exist_ok=True)
    now = int(now_utc().timestamp())
    priv, jwk = _selftest_keypair()

    def _unsigned_jwt(payload: Dict[str, Any]) -> str:  # shadow: self-test tokens are signed with the ephemeral key
        return _signed_jwt(payload, priv)

    gpu_claims = {
        "x-nvidia-ver": "2.0", "iss": "https://nras.attestation.nvidia.com", "eat_nonce": model_digest,
        "x-nvidia-attestation-type": "GPU", "hwmodel": "GH100 A01 GSP BROM", "ueid": "5340650110430080",
        "oemid": "5703", "secboot": True, "dbgstat": "disabled", "measres": "success",
        "x-nvidia-gpu-driver-version": "550.90.07", "x-nvidia-gpu-vbios-version": "96.00.9F.00.01",
        "x-nvidia-gpu-attestation-report-cert-chain-validated": True,
        "x-nvidia-gpu-attestation-report-signature-verified": True,
        "x-nvidia-gpu-attestation-report-nonce-match": True, "x-nvidia-gpu-arch-check": True,
        "x-nvidia-gpu-driver-rim-fetched": True, "x-nvidia-gpu-driver-rim-schema-validated": True,
        "x-nvidia-gpu-driver-rim-cert-validated": True, "x-nvidia-gpu-driver-rim-signature-verified": True,
        "x-nvidia-gpu-driver-rim-measurements-available": True, "x-nvidia-gpu-vbios-rim-fetched": True,
        "x-nvidia-gpu-vbios-rim-schema-validated": True, "x-nvidia-gpu-vbios-rim-cert-validated": True,
        "x-nvidia-gpu-vbios-rim-signature-verified": True, "x-nvidia-gpu-vbios-rim-measurements-available": True,
        "x-nvidia-gpu-vbios-index-no-conflict": True, "x-nvidia-gpu-measurements-match": True,
    }
    overall = {"x-nvidia-ver": "2.0", "iss": "https://nras.attestation.nvidia.com", "iat": now, "exp": now + 3600,
               "eat_nonce": model_digest, "x-nvidia-overall-att-result": True, "submods": {"GPU-0": ["DIGEST", ["SHA256", "…"]]}}
    nras = [["JWT", _unsigned_jwt(overall)], {"GPU-0": _unsigned_jwt(gpu_claims)}]
    ita = {"iss": "Intel Trust Authority", "iat": now, "exp": now + 300, "jti": "b1c1…", "ver": "1.0",
           "attester_type": "TDX", "attester_tcb_status": "UpToDate", "attester_tcb_date": "2026-05-15T00:00:00Z",
           "attester_advisory_ids": [], "tdx_mrtd": "a3" * 48, "tdx_rtmr0": "01" * 48, "tdx_rtmr1": "02" * 48,
           "tdx_rtmr2": "03" * 48, "tdx_rtmr3": "04" * 48, "tdx_mrseam": "cc" * 48, "tdx_seamsvn": 5,
           "tdx_td_attributes": "0000000010000000", "tdx_is_debuggable": False, "tdx_is_migratable": False,
           "tdx_report_data": model_digest + "00" * 32, "cvm_compliance_status": "compliant",
           "policy_ids_matched": [{"id": "9f2a…", "version": "v1"}], "policy_ids_unmatched": []}
    maa = {"iss": "https://sharedweu.weu.attest.azure.net", "iat": now, "exp": now + 28800, "nonce": "selftest-" + model_digest[:16],
           "x-ms-ver": "1.0", "x-ms-attestation-type": "sevsnpvm", "x-ms-compliance-status": "azure-compliant-cvm",
           "x-ms-policy-hash": "Ad…", "x-ms-sevsnpvm-launchmeasurement": "b7" * 48, "x-ms-sevsnpvm-hostdata": "00" * 32,
           "x-ms-sevsnpvm-idkeydigest": "1d" * 48, "x-ms-sevsnpvm-reportdata": model_digest + "00" * 32,
           "x-ms-sevsnpvm-is-debuggable": False, "x-ms-sevsnpvm-migration-allowed": False, "x-ms-sevsnpvm-smt-allowed": True,
           "x-ms-sevsnpvm-bootloader-svn": 4, "x-ms-sevsnpvm-tee-svn": 0, "x-ms-sevsnpvm-snpfw-svn": 22, "x-ms-sevsnpvm-microcode-svn": 213,
           "x-ms-sevsnpvm-guestsvn": 7, "x-ms-sevsnpvm-vmpl": 0, "x-ms-sevsnpvm-familyId": "01" * 16, "x-ms-sevsnpvm-imageId": "02" * 16,
           "x-ms-runtime": {"vm-configuration": {"secure-boot": True, "tpm-enabled": True, "vmUniqueId": "5E6B…"}}}
    gcs = {"iss": "https://confidentialcomputing.googleapis.com", "aud": "https://sts.googleapis.com", "iat": now, "exp": now + 3600,
           "hwmodel": "GCP_INTEL_TDX", "swname": "CONFIDENTIAL_SPACE", "swversion": ["260701"], "dbgstat": "disabled-since-boot",
           "secboot": True, "oemid": 11129, "eat_nonce": [model_digest], "google_service_accounts": ["credit-risk-inference@example.iam.gserviceaccount.com"],
           "submods": {"gce": {"project_id": "acme-lending-prod", "zone": "europe-west4-a", "instance_name": "credit-risk-inf-01", "instance_id": "8123…"},
                       "container": {"image_digest": "sha256:" + "e5" * 32, "image_reference": "europe-west4-docker.pkg.dev/acme/credit-risk@sha256:" + "e5" * 32,
                                     "restart_policy": "Never", "args": ["python", "serve.py"]},
                       "confidential_space": {"support_attributes": ["LATEST", "STABLE", "USABLE"]},
                       "nvidia_gpu": {"cc_mode": "ON", "cc_feature": "SPT",
                                      "gpus": [{"driver_version": "570.86.15", "hwmodel": "GCP_NVIDIA_H100", "ueid": "5340650110430081", "vbios_version": "96.00.A5.00.01"}]}}}
    # synthetic SEV-SNP report (1184 bytes): debug off, migrate off, TCBs equal
    r = bytearray(SNP_REPORT_LEN)
    policy = (1 << 17) | (1 << 16) | 0x00 | (0x00 << 8)  # reserved bit17=1, SMT allowed, abi 0.0
    struct.pack_into("<IIQ", r, 0x000, 3, 7, policy)
    r[0x010:0x020] = bytes.fromhex("01" * 16); r[0x020:0x030] = bytes.fromhex("02" * 16)
    tcb = (0x04) | (0x00 << 8) | (0x16 << 48) | (0xD5 << 56)
    struct.pack_into("<IIQQI", r, 0x030, 0, 1, tcb, 0x1, 0)
    r[0x050:0x090] = bytes.fromhex(model_digest) + b"\x00" * 32
    r[0x090:0x0C0] = bytes.fromhex("b7" * 48)
    struct.pack_into("<Q", r, 0x180, tcb); r[0x1A0:0x1E0] = hashlib.sha512(b"chip").digest()
    struct.pack_into("<Q", r, 0x1E0, tcb); r[0x1E8:0x1EB] = bytes([22, 1, 1]); r[0x1EC:0x1EF] = bytes([22, 1, 1])
    struct.pack_into("<Q", r, 0x1F0, tcb)
    paths = {}
    for name, obj in (("nras.json", nras), ("ita.jwt", _unsigned_jwt(ita)), ("maa.jwt", _unsigned_jwt(maa)), ("gcs.jwt", _unsigned_jwt(gcs))):
        p = os.path.join(folder, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(obj) if not isinstance(obj, str) else obj)
        paths[name.split(".")[0]] = p
    p = os.path.join(folder, "snp_report.bin")
    with open(p, "wb") as fh:
        fh.write(bytes(r))
    paths["snp"] = p
    p = os.path.join(folder, "jwks.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"keys": [jwk]}, fh)
    paths["jwks"] = p
    return paths


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="tee-attestation-connector — TEE attestation → EU AI Act / SOC 2 / ISO 42001 evidence")
    ap.add_argument("--nras", help="NVIDIA NRAS / nvattest output (JWT or JSON)")
    ap.add_argument("--ita", help="Intel Trust Authority token (JWT)")
    ap.add_argument("--maa", help="Azure Attestation token (JWT)")
    ap.add_argument("--gcs", help="Google Confidential Space token (JWT)")
    ap.add_argument("--snp-report", help="raw AMD SEV-SNP attestation report (binary)")
    ap.add_argument("--tdx-quote", help="raw Intel TDX quote (binary)")
    ap.add_argument("--jwks", action="append", default=[], help="verifier JWKS file or URL (repeatable)")
    ap.add_argument("--attestation-url", action="append", default=[],
                    help="fetch a published attestation document (Tinfoil-style {format, body}); host alone → /.well-known/tinfoil-attestation. Repeatable")
    ap.add_argument("--verify-amd", action="store_true", help="verify raw SEV-SNP reports against AMD KDS (VCEK → ASK → ARK); needs network")
    ap.add_argument("--kds-url", default=AMD_KDS_BASE, help="AMD KDS base URL or compatible proxy (default %(default)s)")
    ap.add_argument("--ark-sha256", default=None, help="pin the AMD root (ARK) certificate by SHA-256 of its DER")
    ap.add_argument("--cache-dir", default=None, help="folder to keep fetched documents, reports and certificates (the evidence corpus)")
    ap.add_argument("--locate", action="store_true", help="collect network-inferred location evidence for the attestation endpoint (registry + RTT bounds)")
    ap.add_argument("--globalping", action="store_true", help="with --locate: measure RTT from ~8 cities via the public Globalping probe network")
    ap.add_argument("--vantage", default=None, help="with --locate: where this machine is, e.g. 'Dublin, IE' (labels the local RTT bound)")
    ap.add_argument("--expected-measurement", action="append", default=None,
                    help="reference launch measurement / MRTD / image digest (hex); repeatable, one per attested platform")
    ap.add_argument("--model-digest", help="SHA-256 of the deployed model artefact (hex) to bind to report data")
    ap.add_argument("--max-age-days", type=int, default=1, help="freshness window for tokens (default 1 day)")
    ap.add_argument("--system-name", default=None)
    ap.add_argument("--provider", default=None)
    ap.add_argument("--environment", default=None, help="e.g. 'Azure NCC H100 v5, westeurope' or 'on-prem HGX B200'")
    ap.add_argument("--out-prefix", default="annex4_onchip")
    ap.add_argument("--selftest", action="store_true", help="run on synthetic evidence written to ./selftest_evidence/")
    args = ap.parse_args(argv)

    if args.selftest:
        digest = hashlib.sha256(b"credit-risk-classifier:v7").hexdigest()
        fx = write_selftest_fixtures("selftest_evidence", digest)
        args.nras, args.ita, args.maa, args.gcs, args.snp_report = fx["nras"], fx["ita"], fx["maa"], fx["gcs"], fx["snp"]
        args.jwks = list(args.jwks) + [fx["jwks"]]
        args.model_digest = args.model_digest or digest
        args.expected_measurement = args.expected_measurement or ["b7" * 48, "a3" * 48, "e5" * 32]
        args.system_name = args.system_name or "credit-risk-classifier v7 (selftest)"
        args.provider = args.provider or "Acme Lending BV"
        args.environment = args.environment or "synthetic: Azure SEV-SNP + GCP TDX/H100 + NRAS"
        args.out_prefix = args.out_prefix if args.out_prefix != "annex4_onchip" else "annex4_onchip_selftest"
        print("[selftest] synthetic evidence written to ./selftest_evidence/ (tokens signed with an ephemeral ES256 key; JWKS alongside)")

    keys: List[Dict[str, Any]] = []
    for src in args.jwks:
        keys.extend(load_jwks(src))

    sources: List[EvidenceSource] = []
    for flag, fn in (("nras", parse_nras), ("ita", parse_ita), ("maa", parse_maa), ("gcs", parse_gcs)):
        path = getattr(args, flag)
        if path:
            try:
                sources.append(fn(path, keys))
            except Exception as exc:
                print(f"[warn] could not parse {flag} evidence {path}: {exc}", file=sys.stderr)
    snp_paths = [args.snp_report] if args.snp_report else []
    tdx_paths = [args.tdx_quote] if args.tdx_quote else []
    for u in args.attestation_url:
        try:
            kind, path = fetch_wellknown_attestation(u, cache_dir=args.cache_dir)
            print(f"[fetch] {u} → {kind} saved to {path}")
            (snp_paths if kind == "snp-report" else tdx_paths).append(path)
        except Exception as exc:
            print(f"[warn] could not fetch attestation document from {u}: {exc}", file=sys.stderr)
    for pth in snp_paths:
        sources.append(parse_snp_report(pth, verify=args.verify_amd, kds_base=args.kds_url, cache_dir=args.cache_dir, ark_sha256=args.ark_sha256))
    for pth in tdx_paths:
        sources.append(parse_tdx_quote(pth))
    if not sources:
        ap.error("no evidence supplied (use --nras/--ita/--maa/--gcs/--snp-report/--tdx-quote/--attestation-url or --selftest)")

    location = None
    if args.locate:
        host = None
        for u in args.attestation_url:
            host = (u if u.startswith("http") else "https://" + u).split("/")[2]; break
        if host:
            print(f"[locate] collecting network-inferred location evidence for {host}")
            location = location_evidence(host, sources, vantage=args.vantage, globalping=args.globalping)
        else:
            print("[locate] --locate needs --attestation-url to know which endpoint served the evidence", file=sys.stderr)
    results = run_checks(sources, args.expected_measurement, args.model_digest, args.max_age_days, location)
    score = coverage_score(results)
    level = assurance_level(sources)
    meta = {"generated_at": now_utc().isoformat(), "connector_version": CONNECTOR_VERSION, "system_name": args.system_name, "location_evidence": location,
            "provider": args.provider, "environment": args.environment, "expected_measurement": args.expected_measurement,
            "model_digest": args.model_digest, "max_age_days": args.max_age_days}
    evidence = {"meta": meta, "assurance_level": {"level": level[0], "description": level[1]},
                "coverage": {"score": score[0], "passed": score[1], "applicable": score[2]},
                "sources": [asdict(s) for s in sources], "checks": [asdict(r) for r in results],
                "annex_iv": annex_iv_view(results, sources),
                "location_evidence": location,
                "standards_referenced": ["IETF RFC 9334 (RATS architecture)", "IETF RFC 9711 (EAT)", "draft-ietf-rats-corim",
                                         "AMD SEV-SNP ABI ATTESTATION_REPORT", "Intel TDX DCAP quote v4/v5", "NVIDIA Attestation claims v2/v3"]}
    out_json, out_md = args.out_prefix + ".json", args.out_prefix + ".md"
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, indent=2, default=str)
    with open(out_md, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(meta, sources, results, score, level))
    print_console(results, score, level, out_json, out_md)
    return 0 if not any(r.status == "fail" for r in results) else 2


if __name__ == "__main__":
    sys.exit(main())
