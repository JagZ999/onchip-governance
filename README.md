# On-chip governance: hardware attestation as AI compliance evidence

A research deep dive plus an open-source, standard-library-only Python connector that turns
confidential-computing attestation evidence into auditor-readable compliance evidence.

Inputs the connector understands: NVIDIA Remote Attestation Service (NRAS) tokens, Intel Trust
Authority tokens, Microsoft Azure Attestation tokens, Google Confidential Space tokens, raw AMD
SEV-SNP attestation reports, raw Intel TDX quotes, and published attestation documents of
confidential services (Tinfoil-style `/.well-known/tinfoil-attestation`).

Outputs: twelve on-chip governance checks (G01–G12), an assurance level (L0–L3), and a mapping of
each check to EU AI Act Annex IV / Art. 15, SOC 2, ISO/IEC 42001, ISO/IEC 27001 and NIST AI RMF.

## Contents

| Path | What it is |
|---|---|
| `onchip_governance_deep_dive.md` / `OnChip_Governance_Deep_Dive.docx` | Deep dive, revision 2026-09-07: what on-chip governance is, the deployed / near-term / research layers, the RFC 9334 attestation model, regulatory timeline after the EU Digital Omnibus, and product implications. |
| `tee_attestation_connector.py` | Connector v0.6.0. Verifies RS/PS/ES JWT signatures, parses raw SEV-SNP and TDX evidence, verifies SEV-SNP reports against the AMD KDS (VCEK → ASK → ARK), fetches published attestation documents, and collects location evidence. No third-party dependencies. |
| `selftest_evidence/` | Synthetic tokens, JWKS and SEV-SNP report written by `--selftest`. Signed with throwaway keys; proves the pipeline, not any hardware. |
| `annex4_onchip_selftest.json` / `.md` | Output of the selftest run of 2026-09-09 (connector v0.4.0). |
| `evidence/tinfoil_2026-09-08/` | Live run against Tinfoil's public confidential inference endpoint: the fetched attestation document, the raw SEV-SNP report, the VCEK and Genoa certificate chain, and connector output with and without location evidence. |

## Quick start

Requires Python 3.10 or newer. Nothing to install.

```bash
python3 tee_attestation_connector.py --selftest
```

Reproduce the live check against a third-party confidential service (needs network; the
Globalping step measures TLS handshake timing from several public vantage points):

```bash
python3 tee_attestation_connector.py --attestation-url https://inference.tinfoil.sh --verify-amd --locate --globalping --out-prefix onchip_tinfoil_located
```

Run `python3 tee_attestation_connector.py --help` for the reference-value flags
(`--expected-measurement`, `--model-digest`, `--jwks`) that bind the attested machine to the
documented AI system.

## Results recorded in this repository

| Run | Evidence | Assurance | Checks |
|---|---|---|---|
| Selftest, 2026-09-09 | Synthetic Azure SEV-SNP + GCP TDX/H100 + NRAS | L3 | 11 of 12 applicable pass |
| Tinfoil live, 2026-09-08 | Real SEV-SNP report, VCEK chain verified to the AMD root | L3 | 5 of 10 applicable pass |
| Tinfoil live with location, 2026-09-09 | Same, plus registry and multi-vantage RTT evidence | L3 | 6 of 10 applicable pass |

The location check (G11) passes on the third run through an attestation-bound distance bound:
Tinfoil's SEV-SNP report carries the SHA-256 of the live TLS certificate's public key in
`REPORT_DATA`, so TLS handshake timing from multiple vantage points bounds the machine that holds
the attested key. This bounds the confidential VM's key holder under the confidential-computing
threat model, not the chip's fused key.

## Status and caveats

- The selftest evidence is synthetic. It exercises parsing, signature verification and mapping only.
- No run has yet been made on a self-controlled confidential GPU VM (Azure NCC H100 v5 or GCP A3). That is the next step.
- No shipping hardware reports its own location. Location evidence here is network-inferred (labelled L0.5) or attestation-bound distance bounding (labelled L2).
- Regulatory dates in the deep dive reflect the EU Digital Omnibus (Regulation 2026/1744): Annex III high-risk obligations apply from 2 December 2027, Annex I from 2 August 2028. Verify before reuse.

## Licence

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
