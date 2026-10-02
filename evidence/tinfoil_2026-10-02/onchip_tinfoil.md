# On-chip governance evidence — AI system

Generated 2026-10-02T15:10:28.423057+00:00 by tee_attestation_connector v0.6.0. Provider: —. Environment: —.

**Assurance level:** L3 — evidence independently re-verified against vendor / verifier keys  
**On-chip governance coverage:** 50/100 (5 of 10 applicable checks pass)

## 1. Evidence sources

| Source | Issuer | Issued | Expires | Signature | Devices |
|---|---|---|---|---|---|
| snp-report | AMD Secure Processor (Genoa) — VCEK chain verified to AMD root | — | — | verified locally (vendor root) | 1 |

## 2. Attested devices

### AMD · SEV-SNP · AMD EPYC Genoa (SEV-SNP guest)
- Identity: `1af1aa6c1f56037a05849a59b8815cf909583f9ba9ef2f053218c437f33ba183e4e415b039b37f8205250ad15f8b88a0a3add9f4c081c0779a48ed2214378e44`
- Debug: False · Secure/measured boot: None · CC mode: n/a · Migratable: False
- TCB: reported TCB ≥ committed TCB · Measurements match reference: None
- Firmware: report_version=3, guest_svn=0, fw_current=1.55.40, fw_committed=1.55.40, signing_key=VCEK, signature_algo=1
- launch_measurement: `b3be62c7199d8e4d24f130e5651bdc8a62a2532f72c7e87c986bec54bf5f90bab703ad4dbfc5e45bfd385f8972dfc66c`
- host_data: `0000000000000000000000000000000000000000000000000000000000000000`
- id_key_digest: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- author_key_digest: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- family_id: `00000000000000000000000000000000`
- image_id: `00000000000000000000000000000000`
- report_id: `ce55844c918899b761b425dcb3dcefb56a92b79998be9b29adfce27c30072b63`

## 3. On-chip governance checks

| # | Check | Result | Maps to |
|---|---|---|---|
| G01 | Hardware identity chain: attestation signed by a key rooted in the silicon vendor | ✓ pass | EU AI Act: Art. 15(5) cybersecurity, Annex IV §1(e) hardware description, Annex IV §2(h) cybersecurity measures; SOC 2: CC6.1, CC6.6; ISO/IEC 42001: A.4.5 system & computing resources; ISO/IEC 27001: A.8.9, A.5.23; NIST AI RMF: MEASURE 2.7 |
| G02 | Confidential-computing mode active on every attested device | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks, Art. 10(5) data protection, Art. 55(1)(d) GPAI infra security; SOC 2: CC6.1, CC6.7, C1.1; ISO/IEC 42001: A.4.5; ISO/IEC 27001: A.8.24 cryptography |
| G03 | Debug / developer modes disabled on every attested device | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks, Annex IV §2(h); SOC 2: CC6.1, CC6.8; ISO/IEC 27001: A.8.9 configuration management |
| G04 | Secure or measured boot enforced (firmware measured into the TEE) | ? unknown | EU AI Act: Annex IV §1(c) firmware versions, Art. 15(4) resilience; SOC 2: CC6.8, CC7.1; NIST: SP 800-193 firmware resiliency |
| G05 | Firmware & driver measurements match the vendor reference (RIM / golden values) | – n/a | EU AI Act: Annex IV §1(c), Annex IV §6 lifecycle changes, Art. 15(5) model poisoning; SOC 2: CC6.8, CC7.1, CC8.1; ISO/IEC 27001: A.8.9, A.8.19 |
| G06 | Platform TCB up to date (no outstanding vendor security advisories) | ✓ pass | EU AI Act: Art. 15(5) vulnerabilities, Annex IV §6; SOC 2: CC7.1 vulnerability mgmt; ISO/IEC 27001: A.8.8 |
| G07 | Isolation policy: live migration off, side-channel-relevant options recorded | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks; SOC 2: CC6.1, CC6.7 |
| G08 | Attested workload measurement equals the documented reference (launch measurement / MRTD / image digest) | ? unknown | EU AI Act: Annex IV §1(a) versions, Annex IV §2(c) system architecture, Art. 12 record-keeping; SOC 2: CC8.1 change management, CC7.1; ISO/IEC 42001: A.6.2.4 verification & validation, A.6.2.7 technical documentation |
| G09 | Deployed model artefact cryptographically bound to the attestation (model digest in report data) | ? unknown | EU AI Act: Annex IV §1(a) model version, Annex IV §6, Art. 12 traceability; SOC 2: CC8.1, CC6.8; ISO/IEC 42001: A.6.2.7, A.8.4 communication of incidents |
| G10 | Freshness: nonce matched and evidence within the retention / re-attestation window | ? unknown | EU AI Act: Art. 12 & Art. 19 automatic logs (≥ 6 months), Art. 72 post-market monitoring; SOC 2: CC7.2 monitoring; ISO/IEC 42001: A.6.2.6 operation & monitoring |
| G11 | Deployment location: platform-asserted zone, or attestation-bound distance bound from multiple vantage points | ? unknown | EU AI Act: Annex IV §1(e) deployment environment, Art. 10(5); SOC 2: CC6.6; Export controls: Chip Security Act (pending): location verification, BIS licence conditions; GDPR: Ch. V transfers |
| G12 | Multi-device protection: NVLink / NVSwitch attested or single-GPU passthrough confirmed | – n/a | EU AI Act: Art. 15(5); SOC 2: CC6.7 data in motion |

### Evidence detail

**G01 — Hardware identity chain: attestation signed by a key rooted in the silicon vendor**
- snp-report: report signature and VCEK→ASK→ARK chain verified locally (ARK not pinned; compare fingerprint with AMD's published root)

**G02 — Confidential-computing mode active on every attested device**
- SEV-SNP: attestation implies TEE isolation active

**G03 — Debug / developer modes disabled on every attested device**
- SEV-SNP 1af1aa6c1f56037a05849a59b8815cf909583f9ba9ef2f053218c437f33ba183e4e415b039b37f8205250ad15f8b88a0a3add9f4c081c0779a48ed2214378e44: debug=disabled

**G04 — Secure or measured boot enforced (firmware measured into the TEE)**
- SEV-SNP 1af1aa6c1f56037a05849a59b8815cf909583f9ba9ef2f053218c437f33ba183e4e415b039b37f8205250ad15f8b88a0a3add9f4c081c0779a48ed2214378e44: secure/measured boot=not reported
- ⚠ **Gap.** Enable UEFI secure boot / measured boot in the CVM image; for raw SNP reports add the MAA or ITA token.

**G05 — Firmware & driver measurements match the vendor reference (RIM / golden values)**

**G06 — Platform TCB up to date (no outstanding vendor security advisories)**
- SEV-SNP 1af1aa6c1f56037a05849a59b8815cf909583f9ba9ef2f053218c437f33ba183e4e415b039b37f8205250ad15f8b88a0a3add9f4c081c0779a48ed2214378e44: tcb_status=reported TCB ≥ committed TCB; svn={'guest_svn': 0}

**G07 — Isolation policy: live migration off, side-channel-relevant options recorded**
- SEV-SNP 1af1aa6c1f56037a05849a59b8815cf909583f9ba9ef2f053218c437f33ba183e4e415b039b37f8205250ad15f8b88a0a3add9f4c081c0779a48ed2214378e44: migratable=False; smt=True

**G08 — Attested workload measurement equals the documented reference (launch measurement / MRTD / image digest)**
- SEV-SNP: launch_measurement=b3be62c7199d8e4d… (no --expected-measurement supplied)
- ⚠ **Gap.** Record the golden launch measurement / image digest in the model registry and pass it as --expected-measurement.

**G09 — Deployed model artefact cryptographically bound to the attestation (model digest in report data)**
- SEV-SNP: report_data present (73a7d95ae502cced…) — pass --model-digest to bind the model
- ⚠ **Gap.** Place SHA-256(model artefact) in REPORT_DATA / attester runtime data at launch so the running model is provable.

**G10 — Freshness: nonce matched and evidence within the retention / re-attestation window**
- ⚠ **Gap.** Re-attest on a schedule (e.g. every deploy + daily) and retain tokens ≥ 6 months for Art. 19.

**G11 — Deployment location: platform-asserted zone, or attestation-bound distance bound from multiple vantage points**
- No platform-attested location in evidence (NRAS/ITA/MAA tokens carry none today; Chip Security Act mechanisms not yet shipping)
- ⚠ **Gap.** Record deployment region from the CSP control plane as supporting evidence; network inference bounds the host, not the chip; track NVIDIA fleet-management / Chip Security Act location attestations.

**G12 — Multi-device protection: NVLink / NVSwitch attested or single-GPU passthrough confirmed**

## 4. Contribution to Annex IV

- **§1 General description** — auto
- **§2 Design & development** — auto-partial
- **§3 Monitoring, functioning & control** — auto-partial
- **§4 Performance metrics** — n/a (see MLflow / W&B connectors)
- **§5 Risk management** — manual
- **§6 Lifecycle changes** — auto-partial
- **§7 Standards applied** — manual
- **§8 EU Declaration** — manual
- **§9 Post-market monitoring** — auto-partial

## 5. Warnings

- none

## 6. What this evidence does not prove

- Platform state ≠ model behaviour. Attestation proves *where and on what* the model ran, not *what it decided*. Pair with Art. 19 inference logs (Weave / inference SDK).
- Trust roots are the silicon vendors (NVIDIA, Intel, AMD) and the verifier operator. Record this dependency in Annex IV §5 residual risks.
- Side-channel and physical attacks remain out of scope of remote attestation; document compensating controls.
