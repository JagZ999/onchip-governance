# On-chip governance evidence — credit-risk-classifier v7 (selftest)

Generated 2026-09-09T04:43:56.278633+00:00 by tee_attestation_connector v0.4.0. Provider: Acme Lending BV. Environment: synthetic: Azure SEV-SNP + GCP TDX/H100 + NRAS.

**Assurance level:** L3 — evidence independently re-verified against vendor / verifier keys  
**On-chip governance coverage:** 92/100 (11 of 12 applicable checks pass)

## 1. Evidence sources

| Source | Issuer | Issued | Expires | Signature | Devices |
|---|---|---|---|---|---|
| nras | https://nras.attestation.nvidia.com | 2026-09-09T04:43:56+00:00 | 2026-09-09T05:43:56+00:00 | verified locally | 1 |
| ita | Intel Trust Authority | 2026-09-09T04:43:56+00:00 | 2026-09-09T04:48:56+00:00 | verified locally | 1 |
| maa | https://sharedweu.weu.attest.azure.net | 2026-09-09T04:43:56+00:00 | 2026-09-09T12:43:56+00:00 | verified locally | 1 |
| gcs | https://confidentialcomputing.googleapis.com | 2026-09-09T04:43:56+00:00 | 2026-09-09T05:43:56+00:00 | verified locally | 2 |
| snp-report | AMD Secure Processor (unverified) | — | — | not verified (raw) | 1 |

## 2. Attested devices

### NVIDIA · NVIDIA-CC · GH100 A01 GSP BROM
- Identity: `5340650110430080`
- Debug: False · Secure/measured boot: True · CC mode: ON · Migratable: None
- TCB: n/a · Measurements match reference: True
- Firmware: driver=550.90.07, vbios=96.00.9F.00.01, oemid=5703

### Intel · TDX · Intel TDX trust domain
- Identity: `n/a`
- Debug: False · Secure/measured boot: True · CC mode: n/a · Migratable: False
- TCB: UpToDate · Measurements match reference: None
- Firmware: tdx_module_svn=5, mrseam=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc, tcb_date=2026-05-15T00:00:00Z
- mrtd: `a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3`
- rtmr0: `010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101`
- rtmr1: `020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202`
- rtmr2: `030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303`
- rtmr3: `040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404`

### AMD · SEV-SNP · AMD SEV-SNP confidential VM
- Identity: `5E6B…`
- Debug: False · Secure/measured boot: True · CC mode: n/a · Migratable: False
- TCB: n/a · Measurements match reference: True
- Firmware: bootloader_svn=4, tee_svn=0, snpfw_svn=22, microcode_svn=213, guest_svn=7, hcl_family=01010101010101010101010101010101, hcl_image=02020202020202020202020202020202
- launch_measurement: `b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7`
- host_data: `0000000000000000000000000000000000000000000000000000000000000000`
- id_key_digest: `1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d`

### Google Cloud / Intel · Confidential Space · GCP_INTEL_TDX
- Identity: `8123…`
- Debug: False · Secure/measured boot: True · CC mode: n/a · Migratable: None
- TCB: LATEST,STABLE,USABLE · Measurements match reference: None
- Firmware: swname=CONFIDENTIAL_SPACE, swversion=['260701'], support_attributes=['LATEST', 'STABLE', 'USABLE']
- container_image_digest: `e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5`
- container_image_reference: `europe-west4-docker.pkg.dev/acme/credit-risk@sha256:e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5`
- Location (platform-attested): europe-west4-a (EU/EEA)

### NVIDIA · NVIDIA-CC · GCP_NVIDIA_H100
- Identity: `5340650110430081`
- Debug: False · Secure/measured boot: None · CC mode: ON · Migratable: None
- TCB: n/a · Measurements match reference: None
- Firmware: driver=570.86.15, vbios=96.00.A5.00.01

### AMD · SEV-SNP · AMD EPYC Genoa (SEV-SNP guest)
- Identity: `8f6b59b8c1b3454edd7054a93f44c75bb3af52848da4ff7a78c9fa5a1c28cdee221cd51585fa138960f0f7843adb4a29dcc0fd52a065dec25bbb8070ce99ddf6`
- Debug: False · Secure/measured boot: None · CC mode: n/a · Migratable: False
- TCB: reported TCB ≥ committed TCB · Measurements match reference: None
- Firmware: report_version=3, guest_svn=7, fw_current=1.1.22, fw_committed=1.1.22, signing_key=VCEK, signature_algo=1
- launch_measurement: `b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7`
- host_data: `0000000000000000000000000000000000000000000000000000000000000000`
- id_key_digest: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- author_key_digest: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- family_id: `01010101010101010101010101010101`
- image_id: `02020202020202020202020202020202`
- report_id: `0000000000000000000000000000000000000000000000000000000000000000`

## 3. On-chip governance checks

| # | Check | Result | Maps to |
|---|---|---|---|
| G01 | Hardware identity chain: attestation signed by a key rooted in the silicon vendor | ? unknown | EU AI Act: Art. 15(5) cybersecurity, Annex IV §1(e) hardware description, Annex IV §2(h) cybersecurity measures; SOC 2: CC6.1, CC6.6; ISO/IEC 42001: A.4.5 system & computing resources; ISO/IEC 27001: A.8.9, A.5.23; NIST AI RMF: MEASURE 2.7 |
| G02 | Confidential-computing mode active on every attested device | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks, Art. 10(5) data protection, Art. 55(1)(d) GPAI infra security; SOC 2: CC6.1, CC6.7, C1.1; ISO/IEC 42001: A.4.5; ISO/IEC 27001: A.8.24 cryptography |
| G03 | Debug / developer modes disabled on every attested device | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks, Annex IV §2(h); SOC 2: CC6.1, CC6.8; ISO/IEC 27001: A.8.9 configuration management |
| G04 | Secure or measured boot enforced (firmware measured into the TEE) | ✓ pass | EU AI Act: Annex IV §1(c) firmware versions, Art. 15(4) resilience; SOC 2: CC6.8, CC7.1; NIST: SP 800-193 firmware resiliency |
| G05 | Firmware & driver measurements match the vendor reference (RIM / golden values) | ✓ pass | EU AI Act: Annex IV §1(c), Annex IV §6 lifecycle changes, Art. 15(5) model poisoning; SOC 2: CC6.8, CC7.1, CC8.1; ISO/IEC 27001: A.8.9, A.8.19 |
| G06 | Platform TCB up to date (no outstanding vendor security advisories) | ✓ pass | EU AI Act: Art. 15(5) vulnerabilities, Annex IV §6; SOC 2: CC7.1 vulnerability mgmt; ISO/IEC 27001: A.8.8 |
| G07 | Isolation policy: live migration off, side-channel-relevant options recorded | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks; SOC 2: CC6.1, CC6.7 |
| G08 | Attested workload measurement equals the documented reference (launch measurement / MRTD / image digest) | ✓ pass | EU AI Act: Annex IV §1(a) versions, Annex IV §2(c) system architecture, Art. 12 record-keeping; SOC 2: CC8.1 change management, CC7.1; ISO/IEC 42001: A.6.2.4 verification & validation, A.6.2.7 technical documentation |
| G09 | Deployed model artefact cryptographically bound to the attestation (model digest in report data) | ✓ pass | EU AI Act: Annex IV §1(a) model version, Annex IV §6, Art. 12 traceability; SOC 2: CC8.1, CC6.8; ISO/IEC 42001: A.6.2.7, A.8.4 communication of incidents |
| G10 | Freshness: nonce matched and evidence within the retention / re-attestation window | ✓ pass | EU AI Act: Art. 12 & Art. 19 automatic logs (≥ 6 months), Art. 72 post-market monitoring; SOC 2: CC7.2 monitoring; ISO/IEC 42001: A.6.2.6 operation & monitoring |
| G11 | Deployment location / jurisdiction attested by the platform | ✓ pass | EU AI Act: Annex IV §1(e) deployment environment, Art. 10(5); SOC 2: CC6.6; Export controls: Chip Security Act (pending): location verification, BIS licence conditions; GDPR: Ch. V transfers |
| G12 | Multi-device protection: NVLink / NVSwitch attested or single-GPU passthrough confirmed | ✓ pass | EU AI Act: Art. 15(5); SOC 2: CC6.7 data in motion |

### Evidence detail

**G01 — Hardware identity chain: attestation signed by a key rooted in the silicon vendor**
- nras: signature verified locally (ES256, kid=selftest-key)
- ita: signature verified locally (ES256, kid=selftest-key)
- maa: signature verified locally (ES256, kid=selftest-key)
- gcs: signature verified locally (ES256, kid=selftest-key)
- GH100 A01 GSP BROM 5340650110430080: device cert chain valid
- snp-report: raw report, signature not verified (pass --verify-amd)
- ⚠ **Gap.** Supply verifier JWKS (--jwks) so signatures are re-verified locally, or verify raw reports with vendor collateral.

**G02 — Confidential-computing mode active on every attested device**
- GH100 A01 GSP BROM 5340650110430080: cc_mode=ON
- TDX: attestation implies TEE isolation active
- SEV-SNP: attestation implies TEE isolation active
- Confidential Space: attestation implies TEE isolation active
- GCP_NVIDIA_H100 5340650110430081: cc_mode=ON
- SEV-SNP: attestation implies TEE isolation active

**G03 — Debug / developer modes disabled on every attested device**
- NVIDIA-CC 5340650110430080: debug=disabled
- TDX : debug=disabled
- SEV-SNP 5E6B…: debug=disabled
- Confidential Space 8123…: debug=disabled
- NVIDIA-CC 5340650110430081: debug=disabled
- SEV-SNP 8f6b59b8c1b3454edd7054a93f44c75bb3af52848da4ff7a78c9fa5a1c28cdee221cd51585fa138960f0f7843adb4a29dcc0fd52a065dec25bbb8070ce99ddf6: debug=disabled

**G04 — Secure or measured boot enforced (firmware measured into the TEE)**
- NVIDIA-CC 5340650110430080: secure/measured boot=True
- TDX : secure/measured boot=True
- SEV-SNP 5E6B…: secure/measured boot=True
- Confidential Space 8123…: secure/measured boot=True
- NVIDIA-CC 5340650110430081: secure/measured boot=not reported
- SEV-SNP 8f6b59b8c1b3454edd7054a93f44c75bb3af52848da4ff7a78c9fa5a1c28cdee221cd51585fa138960f0f7843adb4a29dcc0fd52a065dec25bbb8070ce99ddf6: secure/measured boot=not reported

**G05 — Firmware & driver measurements match the vendor reference (RIM / golden values)**
- GH100 A01 GSP BROM 5340650110430080: measurements match reference=True; driver=550.90.07 vbios=96.00.9F.00.01
- AMD SEV-SNP confidential VM 5E6B…: measurements match reference=True; driver=None vbios=None
- GCP_NVIDIA_H100 5340650110430081: measurements match reference=platform-verified (no RIM detail in token); driver=570.86.15 vbios=96.00.A5.00.01

**G06 — Platform TCB up to date (no outstanding vendor security advisories)**
- TDX : tcb_status=UpToDate; svn={'tdx_module_svn': 5}
- SEV-SNP 5E6B…: tcb_status=not reported; svn={'bootloader_svn': 4, 'tee_svn': 0, 'snpfw_svn': 22, 'microcode_svn': 213, 'guest_svn': 7}
- Confidential Space 8123…: tcb_status=LATEST,STABLE,USABLE
- SEV-SNP 8f6b59b8c1b3454edd7054a93f44c75bb3af52848da4ff7a78c9fa5a1c28cdee221cd51585fa138960f0f7843adb4a29dcc0fd52a065dec25bbb8070ce99ddf6: tcb_status=reported TCB ≥ committed TCB; svn={'guest_svn': 7}

**G07 — Isolation policy: live migration off, side-channel-relevant options recorded**
- TDX : migratable=False; smt=None
- SEV-SNP 5E6B…: migratable=False; smt=True
- Confidential Space 8123…: migratable=not reported; smt=None
- SEV-SNP 8f6b59b8c1b3454edd7054a93f44c75bb3af52848da4ff7a78c9fa5a1c28cdee221cd51585fa138960f0f7843adb4a29dcc0fd52a065dec25bbb8070ce99ddf6: migratable=False; smt=True

**G08 — Attested workload measurement equals the documented reference (launch measurement / MRTD / image digest)**
- TDX: mrtd=a3a3a3a3a3a3a3a3… in expected set
- SEV-SNP: launch_measurement=b7b7b7b7b7b7b7b7… in expected set
- Confidential Space: container_image_digest=e5e5e5e5e5e5e5e5… in expected set
- SEV-SNP: launch_measurement=b7b7b7b7b7b7b7b7… in expected set

**G09 — Deployed model artefact cryptographically bound to the attestation (model digest in report data)**
- NVIDIA-CC: model digest FOUND in report_data/runtime_data/nonce
- TDX: model digest FOUND in report_data/runtime_data/nonce
- SEV-SNP: model digest FOUND in report_data/runtime_data/nonce
- Confidential Space: model digest FOUND in report_data/runtime_data/nonce
- NVIDIA-CC: model digest FOUND in report_data/runtime_data/nonce
- SEV-SNP: model digest FOUND in report_data/runtime_data/nonce

**G10 — Freshness: nonce matched and evidence within the retention / re-attestation window**
- nras: token exp 2026-09-09T05:43:56+00:00 (valid)
- nras: issued 2026-09-09T04:43:56+00:00, age 0d (window 1d)
- nras: nonce present
- GH100 A01 GSP BROM: nonce match=True
- ita: token exp 2026-09-09T04:48:56+00:00 (valid)
- ita: issued 2026-09-09T04:43:56+00:00, age 0d (window 1d)
- maa: token exp 2026-09-09T12:43:56+00:00 (valid)
- maa: issued 2026-09-09T04:43:56+00:00, age 0d (window 1d)
- maa: nonce present
- gcs: token exp 2026-09-09T05:43:56+00:00 (valid)
- gcs: issued 2026-09-09T04:43:56+00:00, age 0d (window 1d)
- gcs: nonce present

**G11 — Deployment location / jurisdiction attested by the platform**
- Confidential Space: zone=europe-west4-a → EU/EEA

**G12 — Multi-device protection: NVLink / NVSwitch attested or single-GPU passthrough confirmed**
- 2 GPU(s), 0 NVSwitch attestation(s); single-passthrough=True; switch PDIs=no

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

- snp-report: raw SEV-SNP report: signature not verified (pass --verify-amd to fetch the VCEK chain from AMD KDS)

## 6. What this evidence does not prove

- Platform state ≠ model behaviour. Attestation proves *where and on what* the model ran, not *what it decided*. Pair with Art. 19 inference logs (Weave / inference SDK).
- Trust roots are the silicon vendors (NVIDIA, Intel, AMD) and the verifier operator. Record this dependency in Annex IV §5 residual risks.
- Side-channel and physical attacks remain out of scope of remote attestation; document compensating controls.
