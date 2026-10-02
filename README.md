# On-chip governance: hardware attestation as AI compliance evidence

A research deep dive plus an open-source, standard-library-only Python connector that turns
confidential-computing attestation evidence into auditor-readable compliance evidence.

Inputs the connector understands: NVIDIA Remote Attestation Service (NRAS) tokens, Intel Trust
Authority tokens, Microsoft Azure Attestation tokens, Google Confidential Space tokens, raw AMD
SEV-SNP attestation reports, raw Intel TDX quotes, and published attestation documents of
confidential services (Tinfoil-style `/.well-known/tinfoil-attestation`).

Outputs: twelve on-chip governance checks (G01–G12), an assurance level (L0–L3), and a mapping of
each check to EU AI Act Annex IV / Art. 15, SOC 2, ISO/IEC 42001, ISO/IEC 27001 and NIST AI RMF.

Verification itself is prior art (Veraison, Keylime, go-sev-guest, snpguest, nvTrust, Intel Trust
Authority, Azure Attestation, Google Cloud Attestation). The contribution here is the step after
verification: normalising results across vendors and mapping them to controls an auditor can read.
The connector is meant to sit downstream of those verifiers, not replace them.

## Contents

| Path | What it is |
|---|---|
| `onchip_governance_deep_dive.md` / `OnChip_Governance_Deep_Dive.docx` | Deep dive, revision 2026-09-07: what on-chip governance is, the deployed / near-term / research layers, the RFC 9334 attestation model, regulatory timeline after the EU Digital Omnibus, and product implications. |
| `tee_attestation_connector.py` | Connector v0.6.0. Verifies RS/PS/ES JWT signatures, parses raw SEV-SNP and TDX evidence, verifies SEV-SNP reports against the AMD KDS (VCEK → ASK → ARK, root pinnable with `--ark-sha256`), fetches published attestation documents, and collects location evidence. No third-party dependencies. |
| `selftest_evidence/` | Synthetic tokens, JWKS and SEV-SNP report written by `--selftest`. Signed with throwaway keys; proves the pipeline, not any hardware. |
| `annex4_onchip_selftest.json` / `.md` | Output of the selftest run of 2026-09-09 (connector v0.4.0). |
| `evidence/tinfoil_2026-09-08/` | First live run against Tinfoil's public confidential inference endpoint (AMD SEV-SNP, EPYC Genoa): fetched attestation document, raw report, VCEK and Genoa chain, connector output with and without location evidence. |
| `evidence/tinfoil_2026-10-02/` | Re-run of the same endpoint, plus two reference-measurement runs: the launch measurement matched to Tinfoil's published GitHub release (pass) and a deliberately stale release (fail). Includes `tinfoilsh_published_measurements.json`, an index of SEV-SNP measurements published in tinfoilsh release notes. |
| `evidence/redpill_2026-10-02/` | First real Intel TDX quote processed by the connector: the attestation report published by the RedPill gateway (Phala dstack, Intel TDX), fetched with no account, once plain and once with a caller-supplied nonce; the raw quote; connector output; and Phala's own gateway attestation document. |

## Quick start

Requires Python 3.10 or newer. Nothing to install.

```bash
python3 tee_attestation_connector.py --selftest
```

Reproduce the live check against a third-party AMD SEV-SNP service, with the AMD root pinned to
the Genoa ARK fingerprint that Google's go-sev-guest also embeds (needs network):

```bash
python3 tee_attestation_connector.py --attestation-url https://inference.tinfoil.sh --verify-amd \
  --ark-sha256 4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1 \
  --cache-dir evidence/live --out-prefix evidence/live/onchip_tinfoil
```

Bind the attested workload to the operator's published release. Tinfoil prints the SEV-SNP launch
measurement in each GitHub release of `tinfoilsh/confidential-model-router`; copy the current
one and pass it as the reference (a stale release makes G08 fail):

```bash
python3 tee_attestation_connector.py --snp-report evidence/live/inference.tinfoil.sh.snp_report.bin --verify-amd \
  --cache-dir evidence/live --expected-measurement <measurement from the release notes> \
  --out-prefix evidence/live/onchip_tinfoil_measured
```

Fetch a real Intel TDX quote with a nonce of your choosing and grade it (the nonce comes back
inside the chip-signed REPORT_DATA; quote signature verification is not yet implemented, see below):

```bash
N=$(python3 -c "import secrets;print(secrets.token_hex(32))")
curl -s "https://api.redpill.ai/v1/attestation/report?nonce=$N" \
  | python3 -c "import json,sys;open('quote.bin','wb').write(bytes.fromhex(json.load(sys.stdin)['intel_quote']))"
python3 tee_attestation_connector.py --tdx-quote quote.bin --out-prefix onchip_redpill_tdx
```

Add `--locate --globalping` to collect location evidence (registry lookup plus TLS handshake timing
from several public vantage points). Run `python3 tee_attestation_connector.py --help` for the
remaining flags (`--model-digest`, `--jwks`, `--kds-url`; `--cache-dir` keeps fetched certificates so a
repeat run needs no network for the AMD chain).

## Results recorded in this repository

| Run | Evidence | Assurance | Checks |
|---|---|---|---|
| Selftest, 2026-09-09 | Synthetic Azure SEV-SNP + GCP TDX/H100 + NRAS | L3 | 11 of 12 applicable pass |
| Tinfoil live, 2026-09-08 | Real SEV-SNP report, VCEK chain verified to the AMD root | L3 | 5 of 10 applicable pass |
| Tinfoil live with location, 2026-09-09 | Same, plus registry and multi-vantage RTT evidence | L3 | 6 of 10 applicable pass |
| Tinfoil live, 2026-10-02 | Same chip and chain as September; AMD root pinned | L3 | 5 of 10 applicable pass |
| Tinfoil live + published release, 2026-10-02 | Launch measurement `b3be62c7…` equals the measurement in release v0.0.155 (2026-09-25) | L3 | 6 of 10 applicable pass (G08 pass) |
| Tinfoil live + stale release, 2026-10-02 | Reference set to release v0.0.145 (2026-09-08, measurement `2c01d86a…`) | L3 | 5 of 10; G08 fails as intended |
| RedPill / Phala live, 2026-10-02 | Real Intel TDX v4 quote (MRTD `f06dfda6…`); embedded PCK → Platform CA → Intel SGX Root CA chain, root fingerprint `44a0196b…74d3` equals Intel's published root; caller nonce present in REPORT_DATA | L1 | 3 of 10 applicable pass; signature not verified locally |

Two observations from the October runs. The launch measurement Tinfoil's service reports moved
between 8 and 25 September, and each value matches a dated release in their public repository,
so an outsider can tell which release is running without any vendor cooperation. And the RedPill
gateway accepts a caller-chosen nonce and returns it inside the hardware-signed quote, so freshness
can be demonstrated against a production Intel machine from any laptop.

The location check (G11) passes on the September run through an attestation-bound distance bound:
Tinfoil's SEV-SNP report carries the SHA-256 of the live TLS certificate's public key in
`REPORT_DATA`, so TLS handshake timing from multiple vantage points bounds the machine that holds
the attested key. This bounds the confidential VM's key holder under the confidential-computing
threat model, not the chip's fused key.

## Status and caveats

- The selftest evidence is synthetic. It exercises parsing, signature verification and mapping only.
- Real hardware evidence so far: AMD SEV-SNP (Tinfoil) and Intel TDX (RedPill / Phala), both published
  by production services for outside verification. No real NVIDIA, Intel Trust Authority, Azure
  Attestation or Google Confidential Space token has been processed yet; those parsers have only seen
  the synthetic selftest tokens.
- TDX quotes are parsed and their embedded certificate chain is checked, but the quote signature and
  TCB status are not verified locally yet. That is the next connector step, together with a one-flag
  `--reference-release` lookup that replaces the manual measurement copy above.
- No run has yet been made on a self-controlled confidential GPU VM. That is where the first real NVIDIA
  token will come from.
- No shipping hardware reports its own location. Location evidence here is network-inferred (labelled L0.5)
  or attestation-bound distance bounding (labelled L2).
- Regulatory dates in the deep dive reflect the EU Digital Omnibus (Regulation 2026/1744): Annex III
  high-risk obligations apply from 2 December 2027, Annex I from 2 August 2028. Verify before reuse.

## Licence

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
