# On-chip governance evidence — AI system

Generated 2026-10-02T15:27:33.354925+00:00 by tee_attestation_connector v0.6.0. Provider: RedPill (Phala) — third-party service, verified from outside. Environment: Intel TDX CVM + NVIDIA GPU TEE, production, fetched 2026-10-02.

**Assurance level:** L1 — raw device reports parsed, signatures not verified  
**On-chip governance coverage:** 30/100 (3 of 10 applicable checks pass)

## 1. Evidence sources

| Source | Issuer | Issued | Expires | Signature | Devices |
|---|---|---|---|---|---|
| tdx-quote | Intel TDX module / Quoting Enclave (unverified) | — | — | not verified (raw) | 1 |

## 2. Attested devices

### Intel · TDX · Intel TDX trust domain (raw quote)
- Identity: `n/a`
- Debug: False · Secure/measured boot: True · CC mode: n/a · Migratable: None
- TCB: n/a · Measurements match reference: None
- Firmware: quote_version=4, attestation_key_type=2, tee_type=0x81, tee_tcb_svn=0b010500000000000000000000000000, mrseam=7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d, mrsignerseam=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, xfam=0702000000000000, qe_vendor_id=f79c4ca9940a0db3957f06074d796854
- mrtd: `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`
- mr_config_id: `010637b3d506c80c0328c84697c290f5fb7eef811c8d022124e04ee9b0f5f99567000000000000000000000000000000`
- mr_owner: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- mr_owner_config: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- rtmr0: `46a83f6bbbeaa274aaf04861ef47d7e8898d4e699126b642f72f582e8d7f5349cb266a188bbabf619940d4fece06594b`
- rtmr1: `07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c`
- rtmr2: `df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858`
- rtmr3: `ba906c142212988b80d87f5743d2f76da6774885f329102cc5b66341113e1b181905ac8dc66250368372ad30bc1c46c3`

## 3. On-chip governance checks

| # | Check | Result | Maps to |
|---|---|---|---|
| G01 | Hardware identity chain: attestation signed by a key rooted in the silicon vendor | ? unknown | EU AI Act: Art. 15(5) cybersecurity, Annex IV §1(e) hardware description, Annex IV §2(h) cybersecurity measures; SOC 2: CC6.1, CC6.6; ISO/IEC 42001: A.4.5 system & computing resources; ISO/IEC 27001: A.8.9, A.5.23; NIST AI RMF: MEASURE 2.7 |
| G02 | Confidential-computing mode active on every attested device | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks, Art. 10(5) data protection, Art. 55(1)(d) GPAI infra security; SOC 2: CC6.1, CC6.7, C1.1; ISO/IEC 42001: A.4.5; ISO/IEC 27001: A.8.24 cryptography |
| G03 | Debug / developer modes disabled on every attested device | ✓ pass | EU AI Act: Art. 15(5) confidentiality attacks, Annex IV §2(h); SOC 2: CC6.1, CC6.8; ISO/IEC 27001: A.8.9 configuration management |
| G04 | Secure or measured boot enforced (firmware measured into the TEE) | ✓ pass | EU AI Act: Annex IV §1(c) firmware versions, Art. 15(4) resilience; SOC 2: CC6.8, CC7.1; NIST: SP 800-193 firmware resiliency |
| G05 | Firmware & driver measurements match the vendor reference (RIM / golden values) | – n/a | EU AI Act: Annex IV §1(c), Annex IV §6 lifecycle changes, Art. 15(5) model poisoning; SOC 2: CC6.8, CC7.1, CC8.1; ISO/IEC 27001: A.8.9, A.8.19 |
| G06 | Platform TCB up to date (no outstanding vendor security advisories) | ? unknown | EU AI Act: Art. 15(5) vulnerabilities, Annex IV §6; SOC 2: CC7.1 vulnerability mgmt; ISO/IEC 27001: A.8.8 |
| G07 | Isolation policy: live migration off, side-channel-relevant options recorded | ? unknown | EU AI Act: Art. 15(5) confidentiality attacks; SOC 2: CC6.1, CC6.7 |
| G08 | Attested workload measurement equals the documented reference (launch measurement / MRTD / image digest) | ? unknown | EU AI Act: Annex IV §1(a) versions, Annex IV §2(c) system architecture, Art. 12 record-keeping; SOC 2: CC8.1 change management, CC7.1; ISO/IEC 42001: A.6.2.4 verification & validation, A.6.2.7 technical documentation |
| G09 | Deployed model artefact cryptographically bound to the attestation (model digest in report data) | ? unknown | EU AI Act: Annex IV §1(a) model version, Annex IV §6, Art. 12 traceability; SOC 2: CC8.1, CC6.8; ISO/IEC 42001: A.6.2.7, A.8.4 communication of incidents |
| G10 | Freshness: nonce matched and evidence within the retention / re-attestation window | ? unknown | EU AI Act: Art. 12 & Art. 19 automatic logs (≥ 6 months), Art. 72 post-market monitoring; SOC 2: CC7.2 monitoring; ISO/IEC 42001: A.6.2.6 operation & monitoring |
| G11 | Deployment location: platform-asserted zone, or attestation-bound distance bound from multiple vantage points | ? unknown | EU AI Act: Annex IV §1(e) deployment environment, Art. 10(5); SOC 2: CC6.6; Export controls: Chip Security Act (pending): location verification, BIS licence conditions; GDPR: Ch. V transfers |
| G12 | Multi-device protection: NVLink / NVSwitch attested or single-GPU passthrough confirmed | – n/a | EU AI Act: Art. 15(5); SOC 2: CC6.7 data in motion |

### Evidence detail

**G01 — Hardware identity chain: attestation signed by a key rooted in the silicon vendor**
- tdx-quote: raw report, signature not verified (pass --verify-amd)
- ⚠ **Gap.** Supply verifier JWKS (--jwks) so signatures are re-verified locally, or verify raw reports with vendor collateral.

**G02 — Confidential-computing mode active on every attested device**
- TDX: attestation implies TEE isolation active

**G03 — Debug / developer modes disabled on every attested device**
- TDX : debug=disabled

**G04 — Secure or measured boot enforced (firmware measured into the TEE)**
- TDX : secure/measured boot=True

**G05 — Firmware & driver measurements match the vendor reference (RIM / golden values)**

**G06 — Platform TCB up to date (no outstanding vendor security advisories)**
- TDX : tcb_status=not reported; svn={'tee_tcb_svn': '0b010500000000000000000000000000'}
- ⚠ **Gap.** Apply platform firmware / microcode updates referenced by the advisories; re-attest.

**G07 — Isolation policy: live migration off, side-channel-relevant options recorded**
- TDX : migratable=not reported; smt=None
- ⚠ **Gap.** Launch with migration disabled; document SMT decision in the Art. 15 risk assessment.

**G08 — Attested workload measurement equals the documented reference (launch measurement / MRTD / image digest)**
- TDX: mrtd=f06dfda6dce1cf90… (no --expected-measurement supplied)
- ⚠ **Gap.** Record the golden launch measurement / image digest in the model registry and pass it as --expected-measurement.

**G09 — Deployed model artefact cryptographically bound to the attestation (model digest in report data)**
- TDX: report_data present (79a5061efe5a46b0…) — pass --model-digest to bind the model
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

- tdx-quote: raw TDX quote: signature and TCB status not verified (needs Intel PCS collateral); pair with an Intel Trust Authority token

## 6. What this evidence does not prove

- Platform state ≠ model behaviour. Attestation proves *where and on what* the model ran, not *what it decided*. Pair with Art. 19 inference logs (Weave / inference SDK).
- Trust roots are the silicon vendors (NVIDIA, Intel, AMD) and the verifier operator. Record this dependency in Annex IV §5 residual risks.
- Side-channel and physical attacks remain out of scope of remote attestation; document compensating controls.
