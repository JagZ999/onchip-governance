# On-chip governance evidence — Tinfoil confidential inference (inference.tinfoil.sh)

Generated 2026-09-09T04:43:42.388653+00:00 by tee_attestation_connector v0.4.0. Provider: Tinfoil — third-party service, verified from outside. Environment: AMD SEV-SNP CVM (Genoa), production, fetched 2026-09-08.

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
- launch_measurement: `2c01d86a821fe34ac41832102fa8612179e9228ada5277f80c579592eb1c8c21c182df2bf5c275df82fc35962085ed2d`
- host_data: `0000000000000000000000000000000000000000000000000000000000000000`
- id_key_digest: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- author_key_digest: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- family_id: `00000000000000000000000000000000`
- image_id: `00000000000000000000000000000000`
- report_id: `a76db4a3d7e23ab182ce9b26c1073f891916a1e6b12b59bd14cb8ae93fe173a6`

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
| G11 | Deployment location / jurisdiction attested by the platform | ? unknown | EU AI Act: Annex IV §1(e) deployment environment, Art. 10(5); SOC 2: CC6.6; Export controls: Chip Security Act (pending): location verification, BIS licence conditions; GDPR: Ch. V transfers |
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
- SEV-SNP: launch_measurement=2c01d86a821fe34a… (no --expected-measurement supplied)
- ⚠ **Gap.** Record the golden launch measurement / image digest in the model registry and pass it as --expected-measurement.

**G09 — Deployed model artefact cryptographically bound to the attestation (model digest in report data)**
- SEV-SNP: report_data present (b560c56fe1e79fd9…) — pass --model-digest to bind the model
- ⚠ **Gap.** Place SHA-256(model artefact) in REPORT_DATA / attester runtime data at launch so the running model is provable.

**G10 — Freshness: nonce matched and evidence within the retention / re-attestation window**
- ⚠ **Gap.** Re-attest on a schedule (e.g. every deploy + daily) and retain tokens ≥ 6 months for Art. 19.

**G11 — Deployment location / jurisdiction attested by the platform**
- No platform-attested location in evidence (NRAS/ITA/MAA tokens carry none today; Chip Security Act mechanisms not yet shipping)
- ⚠ **Gap.** Record deployment region from the CSP control plane as supporting evidence; track NVIDIA fleet-management / Chip Security Act location attestations.

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
