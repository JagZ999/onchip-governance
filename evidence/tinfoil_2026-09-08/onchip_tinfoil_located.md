# On-chip governance evidence — Tinfoil confidential inference (inference.tinfoil.sh)

Generated 2026-09-09T05:23:01.146547+00:00 by tee_attestation_connector v0.6.0. Provider: Tinfoil — third-party service, verified from outside. Environment: AMD SEV-SNP CVM (Genoa), production, fetched 2026-09-09.

**Assurance level:** L3 — evidence independently re-verified against vendor / verifier keys  
**On-chip governance coverage:** 60/100 (6 of 10 applicable checks pass)

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
| G11 | Deployment location: platform-asserted zone, or attestation-bound distance bound from multiple vantage points | ✓ pass | EU AI Act: Annex IV §1(e) deployment environment, Art. 10(5); SOC 2: CC6.6; Export controls: Chip Security Act (pending): location verification, BIS licence conditions; GDPR: Ch. V transfers |
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

**G11 — Deployment location: platform-asserted zone, or attestation-bound distance bound from multiple vantage points**
- network-inferred: prefix 69.46.84.0/22 announced by [{'asn': 18779, 'holder': 'EGIHOSTING - EGIHosting'}]; RIR-registered country ['US']
- network-inferred: min RTT 82.1 ms from this machine (location not given) → host within ~8212 km
- attestation-bound: TLS key in chip report; nearest probe San Jose, US completes the signed handshake in 9 ms → attested machine within ~900 km of it; handshake overhead 7 ms; consistent across probes, no relay
- TLS key bound in hardware report: YES (sha256(spki), AMD SEV-SNP)
- chip-signed location claim: not available from any token (Sep 2026); attestation-bound TLS timing is the strongest outside evidence

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

## 4b. Location evidence (what an outside verifier can get today)

Assurance: **L2 attestation-bound distance bound**. Hardware-attested location: **not available** — No NVIDIA, Intel, AMD, Azure or Google attestation format carries a location claim (checked Sep 2026). A chip-signed, nonce-bound timed response (delay-based distance bounding rooted in the TEE) exists only as a design.

- Registry: prefix 69.46.84.0/22 announced by [{'asn': 18779, 'holder': 'EGIHOSTING - EGIHosting'}]; RIR-registered country ['US'] — who announces the address block and where the registry records it (public routing/RIR data); says who operates the network, not where the chip is
- RTT from this machine (location not given): 82.1 ms → within ~8212 km — TLS 1.3 handshake must be signed by the key bound in the hardware report; its time bounds the attested machine, not just the TCP responder. tls_over_tcp near 1 ⇒ no relay between network endpoint and key holder
- Multi-vantage signed-handshake timing (8 probes): San Jose tcp 2 / tls 9 ms (attested machine ≤900 km); Los Angeles tcp 13 / tls 22 ms (attested machine ≤2200 km); Seattle tcp 20 / tls 27 ms (attested machine ≤2700 km); Dallas tcp 39 / tls 46 ms (attested machine ≤4600 km); Ashburn tcp 60 / tls 67 ms (attested machine ≤6700 km); Tokyo tcp 107 / tls 118 ms (attested machine ≤11800 km); Frankfurt tcp 138 / tls 144 ms (attested machine ≤14400 km); Singapore tcp 180 / tls 187 ms (attested machine ≤18700 km) — TLS handshake signed by the attestation-bound key: the tightest tls_ms bound locates the attested machine; handshake overhead (tls-tcp) 6–11 ms across probes, median 7 ms; constant overhead ⇒ no relay
- TLS key binding: YES — sha256(spki) of the live certificate appears in the AMD SEV-SNP report data

## 5. Warnings

- none

## 6. What this evidence does not prove

- Platform state ≠ model behaviour. Attestation proves *where and on what* the model ran, not *what it decided*. Pair with Art. 19 inference logs (Weave / inference SDK).
- Trust roots are the silicon vendors (NVIDIA, Intel, AMD) and the verifier operator. Record this dependency in Annex IV §5 residual risks.
- Side-channel and physical attacks remain out of scope of remote attestation; document compensating controls.
