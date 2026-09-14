# On-Chip Governance Deep Dive

Revision 2026-09-07. Status: working draft for founder use. Scope: what "on-chip governance" is, how far it has actually shipped, why hardware attestation is compliance evidence, and what that changes in the product plan. Files delivered with this revision: `tee_attestation_connector.py` (Connector 3), this document, and the HTML deep dive.

## §1 What changed since the April brief (read this first)

The April brief was written 95 days before an EU deadline that has since moved. Six facts have changed and each one touches the plan.

| # | Topic | April brief assumed | Reality on 2026-09-07 | Effect on the plan |
|---|---|---|---|---|
| 1 | EU AI Act high-risk deadline | 2 Aug 2026 for Annex III systems | Regulation (EU) 2026/1744 ("Digital Omnibus on AI") published 24 Jul 2026, in force 27 Jul 2026. Annex III obligations now apply from 2 Dec 2027; Annex I (AI in regulated products) from 2 Aug 2028. | Bet 2's deadline urgency is gone. The upside: 15 months to build the connected product before enforcement, instead of selling a manual sprint into a panic. |
| 2 | Fine exposure | €30M / 6% | €35M or 7% for Article 5 prohibited practices; €15M or 3% for most high-risk and GPAI violations. | Update every deck and outreach template. |
| 3 | Harmonised standards | Available in time | As of June 2026 none of the CEN-CENELEC JTC 21 deliverables is cited in the Official Journal. EN 18286 (quality management, Art. 17) is at Formal Vote; standardisation request M/613 expires 28 Feb 2027. | Buyers cannot yet claim presumption of conformity. Evidence-based documentation (what this connector produces) is the fallback everyone will use. |
| 4 | Obligations that are live now | Everything starts Aug 2026 | Article 50 transparency duties applied on 2 Aug 2026 (watermarking grace for pre-existing systems to 2 Dec 2026). GPAI provider obligations (Arts. 51–56) have applied since 2 Aug 2025. New Art. 5 prohibitions (non-consensual intimate imagery, CSAM) need technical safeguards by 2 Dec 2026. | These are the only near-term EU deadlines left. Outreach hooks move from "Annex IV by August" to "Art. 50 and GPAI now, Annex IV by Dec 2027". |
| 5 | TEE attestation parser | Parking lot, "a 2027 conversation" | NVIDIA Confidential Computing is shipping on Hopper and Blackwell (HGX B200/B300, NVLink encryption across 8 GPUs, under 8% inference overhead in NVIDIA's own 2026 benchmark). Azure and Google Cloud sell confidential GPU VMs. Intel Trust Authority has a free tier. NVIDIA's attestation SDK moved to a C++ core and CLI; Google's Confidential Space token now carries a GPU sub-module. | Pull the attestation connector from the parking lot into Phase 2. It was built this session. |
| 6 | Chip export enforcement | Not in scope | The Chip Security Act (location verification on exported AI chips) passed the House Foreign Affairs Committee 42–0 on 26 Mar 2026 and was folded into the Senate FY2027 NDAA manager's amendment on 14 Jul 2026, alongside the AI OVERWATCH and MATCH Acts. The NDAA itself was stalled through August. NVIDIA has an opt-in fleet-management agent with latency-based location verification, Blackwell first. | A new evidence type ("attested location") and a new buyer (data-centre operators, neoclouds) are 12–24 months out. Watch, do not build yet. |

**What to do about Bet 2.** Keep the Annex IV sprint, but sell it as readiness for 2 Dec 2027, not as a rescue. The immediate hooks are Article 50 (live), GPAI obligations (live), and the fact that no harmonised standard yet gives presumption of conformity. The law-firm co-sell motion stays the same. Price does not need to change; the story does.

## §2 On-chip governance: three layers at three maturities

"On-chip governance" means using mechanisms built into the silicon (or into the firmware and security processors beside it) to make claims about AI compute that do not depend on the operator's word. In 2026 it is three different things at three different stages of maturity, and conflating them is the most common mistake in the field.

**Layer A — Confidential computing and remote attestation (deployed).** A trusted execution environment isolates a workload from the host, the hypervisor and the cloud operator, and a hardware-rooted key signs a report of what is running. Intel TDX, AMD SEV-SNP and Arm CCA do this for CPUs; NVIDIA Confidential Computing does it for H100, H200, B200 and B300 GPUs and for NVSwitch. Verifier services (Intel Trust Authority, NVIDIA Remote Attestation Service, Microsoft Azure Attestation, Google Confidential Space) check the report against vendor reference values and issue a signed token. The vocabulary is standardised: IETF RFC 9334 (RATS architecture, 2023) and RFC 9711 (Entity Attestation Token, April 2025), with CoRIM (reference values, draft-11, July 2026) and an EAT profile for composite CPU+GPU platforms (draft, September 2026) in progress. This layer is where this work sits now.

**Layer B — Hardware-enabled governance mechanisms (policy-driven, 2026–2028).** Mechanisms that reuse Layer A's keys and security processors to answer regulatory questions: where is this chip, how much has it computed, is its licence current, can it talk to 10,000 neighbours at full bandwidth. CNAS's "Secure, Governable Chips" (Jan 2024) and its December 2024 working paper set out the menu; delay-based location verification (a chip answers signed pings from landmark servers; round-trip time bounds distance) was costed at under $1M in firmware. The Chip Security Act would make a location mechanism mandatory within 180 days of enactment. NVIDIA's opt-in agent is the first commercial instance. These mechanisms will produce evidence that data-centre operators must retain and show. A compliance evidence layer should be ready to ingest it, not build it.

**Layer C — Flexible hardware-enabled guarantees, flexHEG (research, 2029+).** An auditable "guarantee processor" inside a tamper-responsive enclosure that meters FLOPs, records training data hashes, enforces rules updatable by an international authority, and wipes secrets on intrusion. Led by Yoshua Bengio's group with the flexHEG reports (mid-2025); the authors' own estimate for integrated hardware is 3.7–7.9 years. Interesting, not a product input.

### §2.1 The 20-mechanism taxonomy

Ansari's April 2026 taxonomy (arXiv 2604.04712) is the cleanest current map. Feasibility tiers follow TRL bands: deployable (TRL 7–9), near-term (TRL 4–6), requires R&D (TRL 2–3), speculative (TRL 1). The right-hand column is our view: which mechanisms produce evidence a compliance platform can already collect.

| ID | Mechanism | Feasibility | Evidence relevance |
|---|---|---|---|
| M1 | Cloud provider metadata & billing records | Deployable | Supporting evidence for §1(e) hardware description; already what Vanta collects |
| M2 | Workload classification from metadata | Deployable (cooperative) / near-term (adversarial) | Low |
| M3 | KYC for compute access | Near-term | Low; a data-centre operator obligation |
| M4 | Power consumption monitoring | Deployable (coarse) / near-term (AI-specific) | Low |
| M5 | On-chip FLOP metering | Requires R&D | None yet; GPAI systemic-risk threshold evidence later |
| M6 | Chip location tracking (delay-based) | Near-term (software) / R&D (hardware) | High from 2027 if the Chip Security Act passes; new buyer |
| M7 | Chip registry & supply-chain tracking | Near-term (registry) / deployable (trade data) | Medium; attestation tokens already carry chip identities (ueid, chip_id) |
| V1 | TEE workload attestation | Requires R&D for governance-grade accelerators | Core. Commercial-grade is enough for compliance evidence today |
| V2 | Cryptographic proof-of-training | Requires R&D | None |
| V3 | flexHEG verifiable claims | Requires R&D | None |
| V4 | Remote attestation via cryptographic licensing | Near-term on commercial TEE infrastructure / R&D adversarial | Core. This is what the verifier tokens are |
| V5 | Multiparty control of training runs | Speculative | None |
| V6 | Physical inspection & on-site auditing | Deployable | This connector produces the packet the inspector reads |
| E1 | Cloud provider access control | Deployable | Evidence for SOC 2 CC6 |
| E2 | Chip-to-chip networking restrictions | Speculative | None |
| E3 | Hardware-embedded off-switches | Requires R&D | Avoid entirely (see §6) |
| E4 | Remote performance degradation / disablement | R&D to speculative | Avoid entirely |
| E5 | Export controls on hardware | Deployable | Licence-condition reporting is a 2027 opportunity |
| E6 | Compute licensing & registration | Deployable (reporting) / R&D (hardware-enforced) | Reporting side only |
| E7 | Upstream supply-chain controls | Deployable | None |

The structural finding of the paper matters for positioning: the mechanisms most needed for treaty verification (M5, V2, E3) are the least mature, while the mechanisms that are deployable today (V1/V4 on commercial TEEs, M1, E1, V6) are exactly the ones a compliance product can turn into evidence.

## §3 How attestation works, in the terms an auditor needs

RFC 9334 gives five roles. The **Attester** is the device (CPU TEE, GPU) that produces signed evidence. The **Verifier** appraises that evidence against reference values and issues an **attestation result**. The **Relying Party** consumes the result and decides (release a key, admit a workload, accept as audit evidence). **Endorsers** vouch for the attester's identity (the silicon vendor's device certificate chain). **Reference Value Providers** publish what "good" looks like (NVIDIA's Reference Integrity Manifests for driver and vBIOS; Intel's TCB info; AMD's VCEK certificates). In a compliance engagement the customer's hardware is the attester, the vendor or cloud service is the verifier, and the auditor is the relying party. The connector is the relying party's reader.

### §3.1 The evidence chain for one confidential GPU VM

1. **CPU TEE launch.** The VM's initial memory is measured. AMD SEV-SNP produces a 1,184-byte ATTESTATION_REPORT signed by the chip's VCEK, containing the launch measurement, guest policy (debug and migration bits), platform TCB versions and 64 bytes of caller-supplied REPORT_DATA. Intel TDX produces a quote with MRTD (build-time measurement), four runtime measurement registers (RTMR0–3, extended by firmware, OS and application), TD attributes and 64 bytes of report data.
2. **GPU attestation.** The driver asks the GPU's security processor for a measurement report over SPDM. The report is signed by a key fused into the GPU at manufacture and chained to NVIDIA's device CA; it covers firmware measurements, CC-mode state, debug state and a caller nonce. Multi-GPU systems add NVSwitch attestation.
3. **Verification.** The verifier checks the certificate chains and revocation status, fetches the vendor's reference values (RIMs, TCB info), compares measurements, applies policy, and signs a JWT/EAT whose claims are the appraisal.
4. **Consumption.** The relying party verifies the token signature against the verifier's published keys, checks freshness (nonce, iat/exp), reads the claims, and either releases secrets to the workload or, in the compliance case, files the token as evidence and maps it to controls.

### §3.2 What a token actually says

The same properties appear under four different claim vocabularies. This table is the core of the connector's normalisation layer.

| Property | NVIDIA NRAS / nvattest | Intel Trust Authority | Azure Attestation (SEV-SNP CVM) | Google Confidential Space |
|---|---|---|---|---|
| Debug disabled | `dbgstat` = disabled | `tdx_is_debuggable` = false | `x-ms-sevsnpvm-is-debuggable` = false | `dbgstat` = disabled-since-boot |
| Secure / measured boot | `secboot` = true | RTMR0–3 present | `x-ms-runtime.vm-configuration.secure-boot` | `secboot` = true |
| Firmware matches vendor reference | `measres` = success; `x-nvidia-gpu-measurements-match` | `cvm_compliance_status` | `x-ms-compliance-status` = azure-compliant-cvm | `submods.confidential_space.support_attributes` |
| Platform TCB current | (RIM version-match claims) | `attester_tcb_status` = UpToDate; `attester_advisory_ids` | `*-svn` claims (bootloader, tee, snpfw, microcode) | `support_attributes` contains LATEST |
| Workload identity | driver / vBIOS versions | `tdx_mrtd`, `tdx_rtmr0..3` | `x-ms-sevsnpvm-launchmeasurement` | `submods.container.image_digest` |
| Model binding (caller data) | `eat_nonce` | `tdx_report_data`, `attester_runtime_data` | `x-ms-sevsnpvm-reportdata` | `eat_nonce` |
| Hardware identity | `ueid`, `hwmodel`, cert chain | (in quote) | `x-ms-runtime.vm-configuration.vmUniqueId` | `submods.gce.instance_id`; `submods.nvidia_gpu.gpus[].ueid` |
| CC mode | implied by a valid CC report | `nvgpu` composite section | — | `submods.nvidia_gpu.cc_mode` = ON |
| Location | — | — | — | `submods.gce.zone` |
| Token signature | JWT/EAT, NVIDIA-published JWKS | JWT, PS384 by default | JWT, RS256, tenant JWKS | OIDC JWT or PKI token with x5c |

Two observations. First, only Google's token attests location, and only as a cloud zone; nothing in today's tokens satisfies a Chip Security Act location mechanism. Second, "model binding" is a convention, not a claim: the customer must place SHA-256 of the deployed model artefact in the report data or nonce at launch. Without that one line, attestation proves the platform but not the model. This is the on-chip equivalent of the `mlflow.log_input()` line in the April brief.

## §4 Why this is compliance evidence

Regulators and auditors are moving from "show me the document" to "show me that the document describes what is running". Attestation is the first evidence type that answers the second question without a screenshot: the token is signed by a third party, bound to a nonce, and cheap to re-verify. The mapping below is what the connector emits for every check.

| On-chip fact (connector check) | EU AI Act | SOC 2 (TSC 2017) | ISO/IEC 42001 · 27001 | NIST AI RMF · other |
|---|---|---|---|---|
| G01 Hardware identity chain rooted in the silicon vendor | Art. 15(5); Annex IV §1(e), §2(h) | CC6.1, CC6.6 | 42001 A.4.5; 27001 A.8.9, A.5.23 | MEASURE 2.7 |
| G02 Confidential-computing mode active | Art. 15(5) confidentiality attacks; Art. 10(5); Art. 55(1)(d) for GPAI systemic risk | CC6.1, CC6.7, C1.1 | 42001 A.4.5; 27001 A.8.24 | RAND weight-security levels SL3–SL5 |
| G03 Debug / developer modes disabled | Art. 15(5); Annex IV §2(h) | CC6.1, CC6.8 | 27001 A.8.9 | — |
| G04 Secure or measured boot | Annex IV §1(c); Art. 15(4) | CC6.8, CC7.1 | — | NIST SP 800-193 |
| G05 Firmware & driver match vendor reference (RIM) | Annex IV §1(c), §6; Art. 15(5) model poisoning | CC6.8, CC7.1, CC8.1 | 27001 A.8.9, A.8.19 | — |
| G06 Platform TCB up to date, no open advisories | Art. 15(5); Annex IV §6 | CC7.1 | 27001 A.8.8 | — |
| G07 Isolation policy (migration off, SMT recorded) | Art. 15(5) | CC6.1, CC6.7 | — | — |
| G08 Workload measurement equals documented reference | Annex IV §1(a), §2(c); Art. 12 | CC8.1, CC7.1 | 42001 A.6.2.4, A.6.2.7 | — |
| G09 Model digest bound into the attestation | Annex IV §1(a), §6; Art. 12 traceability | CC8.1, CC6.8 | 42001 A.6.2.7 | — |
| G10 Freshness: nonce matched, within retention window | Art. 12, Art. 19 (logs kept ≥ 6 months); Art. 72 | CC7.2 | 42001 A.6.2.6 | — |
| G11 Deployment location attested | Annex IV §1(e); Art. 10(5) | CC6.6 | — | Chip Security Act (pending); GDPR Ch. V |
| G12 Multi-device (NVLink / NVSwitch) protection | Art. 15(5) | CC6.7 | — | — |

### §4.1 Where it lands in Annex IV

Adding a "TEE connector" column to the April coverage matrix: §1 General description gains firmware versions (1(c)) and the hardware the system runs on (1(e)) automatically. §2 gains 2(h), the cybersecurity measures, as attested state rather than prose. §3 gains proof that logging and isolation capabilities exist on the running platform. §6 gains firmware and driver drift detection between attestations. §9 gains a re-attestation cadence as post-market monitoring evidence. §5 and §7 remain manual but get better inputs: residual risks (side channels, vendor-root dependency, TCB drift) for §5, and RFC 9334, RFC 9711, SPDM/DICE and SP 800-193 for §7.

### §4.2 The GPAI angle

Providers of general-purpose models with systemic risk must ensure "an adequate level of cybersecurity protection" for the model and its physical infrastructure (Art. 55(1)(d)). The Code of Practice's Safety and Security chapter commits signatories to protecting unreleased weights, and the RAND security-level framework it leans on treats hardware isolation as a measure at the upper levels. An attestation token that says the weights only ever decrypt inside a TEE in CC mode with debug off is the most concrete piece of evidence that obligation has today. There are only 5–15 such providers, but they have budgets and the AI Office now has inspection powers.

### §4.3 What attestation does not prove

Platform state is not model behaviour: a token proves where and on what the model ran, not what it decided. Pair it with Article 19 inference logs (Weave, the inference SDK). The trust roots are NVIDIA, Intel and AMD plus the verifier operator; record that dependency as a residual risk. Side-channel and physical attacks are outside remote attestation's threat model. And a token is a snapshot; without re-attestation it decays into a screenshot with better cryptography.

## §5 The assurance ladder

The product needs one device that explains, in a sales call, why a token is worth more than a Vanta screenshot. This is it.

| Level | Evidence | Who produces it today |
|---|---|---|
| L0 | Self-declared: "we run in a secure environment" | Every questionnaire |
| L1 | Platform-reported: cloud console settings, config pulled by read-only API, screenshots | Vanta, Drata (this is where their ISO 42001 and EU AI Act modules stop) |
| L2 | Verifier-attested: a signed token from Intel Trust Authority, NRAS, Azure Attestation or Confidential Space, stored as evidence | Confidential-computing vendors, for their own key release; rarely filed for audit |
| L3 | Independently re-verified: the connector checks the token signature against the verifier's keys, compares measurements to the registry's reference values, and confirms the model digest is bound in | Connector 3 (this session), stdlib only |
| L4 | Continuous: re-attestation on every deploy and daily, drift alerts, tokens retained ≥ 6 months for Art. 19 | Phase 3 platform |
| L5 | Governance-mechanism claims: attested location, metering, licence state | Not shipping; 2027+ if the Chip Security Act and NVIDIA's agent land |

The commercial point: auditors accept L1 today because nothing better has been offered to them. L3 is the first evidence that survives "prove it is still true", and it is what a EU AI Office inspection under the expanded Omnibus powers will ask for.

## §6 Policy landscape on 2026-09-07

| Date | Event | Why it matters |
|---|---|---|
| Jan 2024 | CNAS, "Secure, Governable Chips" | Coins the on-chip governance agenda; notes most needed features already exist on NVIDIA, AMD, Intel, Apple silicon |
| Dec 11, 2024 | CNAS working paper on securing the chip supply chain | Location verification (<$1M in firmware), bandwidth limits, offline licensing, metering; recommends licence exemptions for chips with verified mechanisms |
| Apr 2025 | RAND-led HEM workshop paper (arXiv 2505.03742); RFC 9711 EAT published | Hardware mechanisms for verifying training claims; the token format the connector parses becomes an RFC |
| May 2025 | Chip Security Act introduced (H.R. 3447 / S. 1705) | Location verification mandate for exported AI chips |
| Jun 2025 | flexHEG reports (arXiv 2506.15093 and companions) | Layer C design; 3.7–7.9 years to integrated hardware |
| Jul 2025 | US AI Action Plan endorses exploring location verification | Executive branch alignment with the bill |
| Jul 31, 2025 | China's CAC summons NVIDIA over alleged H20 "backdoor" and tracking risks | On-chip mechanisms become a sovereignty issue; NVIDIA: "no backdoors, no kill switch" |
| Aug 2, 2025 | GPAI obligations apply; Code of Practice (incl. Safety & Security chapter) in place | First live EU obligations that hardware evidence can serve |
| Dec 2025 | Reuters: NVIDIA builds opt-in location-verification into fleet-management software, using CC capabilities, Blackwell first | First commercial Layer B mechanism |
| Jan 2026 | BIS codifies case-by-case licence review for advanced AI chips | Licence conditions are the likely home for attestation requirements |
| Mar 2026 | DOJ charges three over ~$2.5B of diverted AI servers; HFAC passes Chip Security Act 42–0 (Mar 26) | Political momentum |
| Apr 2026 | Ansari, 20-mechanism feasibility taxonomy (arXiv 2604.04712) | The map used in §2.1 |
| Jun 2026 | JTC 21 status: no AI Act standards cited in the OJ; EN 18286 at Formal Vote | Presumption of conformity unavailable; evidence carries the weight |
| Jul 14, 2026 | Senate NDAA manager's amendment includes Chip Security Act, AI OVERWATCH Act, MATCH Act; Senate cloture fails the same day | Enactment path exists but the vehicle is stalled |
| Jul 24 / 27, 2026 | Digital Omnibus on AI (Reg. 2026/1744) published / in force | Annex III to 2 Dec 2027; Annex I to 2 Aug 2028; AI Office gains inspection and fining powers |
| Aug 2, 2026 | Article 50 transparency obligations apply | Only high-visibility EU deadline that held |
| Aug 2026 | Canonical: Ubuntu confidential VMs on Google Cloud A3 with H100 | Confidential GPU supply broadens beyond Azure |
| Sep 2026 | IETF draft: EAT profile for composite platform attestation (CPU+GPU) | The token shape the connector should normalise to |
| Nov 10, 2026 | BIS affiliates-rule suspension ends | Watch for new licence conditions |
| Dec 2, 2026 | Art. 50(2) grace period ends; Art. 5 new-prohibition safeguards due | Near-term EU deadlines |
| Feb 28, 2027 | Standardisation request M/613 expires | Standards timeline pressure |
| Dec 2, 2027 | Annex III high-risk obligations apply | Bet 2's real date |
| Aug 2, 2028 | Annex I high-risk obligations apply | Medical devices, machinery |

Two currents converge on "attested hardware state": the EU wants evidence that high-risk and GPAI systems are secured as documented; the US wants evidence of where chips physically are. The contested middle is enforcement: China reads on-chip mechanisms as backdoors, NVIDIA insists there is no kill switch, and the delay-based design in the Chip Security Act debate is deliberately privacy-preserving and reuses existing CC keys. Our position should be the neutral evidence layer that reads what the hardware already says, never the mechanism that acts on it. Anything adjacent to E3/E4 (off-switches, remote disablement) is commercially radioactive in every target market.

## §7 Market reality check

| Platform | CPU TEE | GPU CC | Verifier / token | Status |
|---|---|---|---|---|
| Azure NCC H100 v5 | AMD SEV-SNP CVM | H100 CC | Azure Attestation + NRAS | GA; H200 CC series also listed |
| Google Cloud C3 / A3 | Intel TDX (C3); SEV-SNP or TDX (A3) | H100 CC on A3 | Confidential Space token with `nvidia_gpu` sub-module; Intel Trust Authority integration | C3 GA; A3 confidential VMs available with Ubuntu (Aug 2026) |
| AWS | Nitro Enclaves (no CPU TEE attestation of the SEV/TDX kind) | No documented GPU TEE attestation flow | Nitro attestation document | Gap; 1M+ NVIDIA GPUs planned but not confidential |
| On-prem HGX B200 / B300 | TDX or SEV-SNP host | Full CC across 8 GPUs, NVLink encryption, <8% overhead | NRAS or local verifier via nvattest | GA; neoclouds (e.g. Corvex) market it |
| Confidential-AI vendors | Managed | Managed | Anjuna, Fortanix, Edgeless Privatemode (EU-hosted), Tinfoil, Opaque | Partners, not competitors: they run the enclave, the connector files the evidence |

**Who buys on-chip evidence in the next 12 months.** (1) Regulated inference operators in health, finance and HR already on confidential GPUs, as an upsell to the Bet 1 SOC 2 package. (2) GPAI providers with systemic-risk obligations who need Art. 55(1)(d) evidence. (3) EU-hosted / sovereign AI services whose pitch is isolation and jurisdiction. (4) From 2027, data-centre operators and neoclouds facing licence conditions on chip location.

**Competitive picture.** Vanta shipped an ISO 42001 framework in March 2024 and has an EU AI Act framework; Drata is comparable. Both map policies and cloud configurations and reuse evidence across frameworks. Neither parses an attestation token, verifies a signature, or binds a model digest to a TEE report. The confidential-computing vendors produce tokens but stop at key release. The seam between them is the product.

## §8 Connector 3: what was built this session

File: `tee_attestation_connector.py` (~1,000 lines, Python 3.9+, standard library only). It follows the MLflow and W&B connectors: one file, JSON evidence plus a Markdown report, a console coverage summary with ✓/✗, and gap warnings for the questionnaire to fill.

**Inputs.** Any combination of: NVIDIA NRAS / nvattest output (`--nras`), Intel Trust Authority token (`--ita`), Azure Attestation token (`--maa`), Google Confidential Space token (`--gcs`), raw AMD SEV-SNP report (`--snp-report`), raw Intel TDX quote v4/v5 (`--tdx-quote`). Reference values: `--expected-measurement` (repeatable; launch measurement, MRTD or image digest from the model registry), `--model-digest` (SHA-256 of the deployed artefact), `--jwks` (verifier keys, file or URL, repeatable).

**Verification.** With verifier keys supplied, the connector re-verifies token signatures itself: RS256/384/512, PS256/384/512 and ES256/384, including keys embedded as x5c certificates. Every path was tested against the `cryptography` library, including tamper detection. This is what lifts evidence from L2 to L3 without adding a dependency.

**Checks.** Twelve on-chip governance checks G01–G12 (table in §4), each with evidence lines, a control mapping and a remediation note when it fails or is unknown.

**Outputs.** `annex4_onchip.json` (sources, normalised device facts, checks, Annex IV contribution, standards referenced) and `annex4_onchip.md` (auditor report with ⚠ gaps and a "what this evidence does not prove" section). Exit code 2 if any check fails.

**Self-test.** `python tee_attestation_connector.py --selftest` writes synthetic evidence for all five formats, signs the tokens with an ephemeral ES256 key, and runs the pipeline. Result on this machine: 11 of 12 checks pass, assurance L3, one gap (the raw AMD report cannot be verified without AMD's key service). That gap is correct behaviour.

**Limitations to fix on real hardware.** No AMD VCEK or Intel PCS collateral fetching, so raw reports stay "unverified" unless paired with a verifier token. No parsing of raw NVIDIA SPDM reports; the verifier's appraisal is trusted. Location comes only from Google's zone claim. Claim names follow vendor documentation as of September 2026 and will drift (NVIDIA's claims moved from v2 to v3 this year). The synthetic tokens have not been replaced by tokens from real hardware yet; that is next week's job.

**Integration with Connectors 1 and 2.** The MLflow connector already records the model version's artefact digest. Pass it as `--model-digest`, and store the golden launch measurement as a tag on the registered model version so `--expected-measurement` comes from the registry. The customer's one-line change: request attestation with a nonce, or fill report data, equal to SHA-256 of the model artefact at launch. Then Annex IV §1 (the model the auditor reads about) and the enclave (the model actually running) are the same object, cryptographically.

## §9 Revised bets and roadmap

**Bet 1 — SOC 2 AI evidence package.** Unchanged and still the cash bet. Add an "attested infrastructure" tier for customers already on confidential GPUs: the connector's report becomes CC6/CC7 evidence the auditor has never seen before, and it is the shortest path to a reference customer for on-chip governance.

**Bet 2 — EU AI Act conformity pack.** Reposition from deadline sprint to readiness, dated 2 Dec 2027. Lead with Article 50 and GPAI obligations, which are live, and with the absence of harmonised standards. Keep the price and the law-firm channel.

**Bet 3 (new, 2027) — Attested infrastructure and location reporting.** For data-centre operators and neoclouds if the Chip Security Act is enacted: ingest NVIDIA fleet-management attestations and produce the licence-condition report. Contingent; monitor, do not build before enactment.

**Phase 2 connector order, revised.** 1 MLflow (built). 2 W&B + Weave (built). 3 TEE attestation (built this session, moved from the 2027 parking lot). 4 Inference SDK. 5 SageMaker. 6 Vertex / Azure ML. The attestation connector moves up because supply (confidential GPUs GA on two clouds and on-prem Blackwell), demand (GPAI security obligations, regulated inference, sovereignty) and a policy tailwind (Chip Security Act) all arrived within the last nine months.

**Parking lot updates.** FHE-native compliance stays long-term, but note the complementarity: FHE protects the mathematics of the computation, TEEs attest the runtime, and both need the same evidence layer. flexHEG, metering and anything off-switch-adjacent stay out.

## §10 Risks and open questions

- Attestation proves platform, not behaviour; do not let sales collapse the distinction.
- Trust roots are three US vendors and their verifier services; EU buyers will ask, and the honest answer is that the alternative is self-declaration.
- Side channels and physical attacks are out of scope; document compensating controls.
- Crypto-agility: hardware primitives cannot be patched. Caliptra 2.1 (ML-DSA/ML-KEM) silicon is only now appearing in 2026 parts.
- Auditor literacy: most auditors have never seen an EAT. The two-page reading guide is a product, not a nicety.
- Schema churn: NVIDIA moved claims v2 to v3 and deprecated the Python SDK this year; budget for connector maintenance.
- Location claims are not standardised and the Chip Security Act may die with the NDAA.
- Confidential-GPU adoption is real but niche; the addressable set in 2026 is dozens of companies, not thousands.
- The Omnibus moved dates once; it could move them again.

## §11 Next 30 days on this thread

1. Stand up one confidential GPU VM (Azure NCC H100 v5 or a Google A3 confidential VM), run nvattest and the platform attestation, and feed real tokens to the connector. Fix schema drift the same day. Cost: a few dollars an hour.
2. Write the two-page "How to read an attestation token" guide for auditors. It is the wedge for the Bet 1 upsell and the first thing a GPAI security lead will forward internally.
3. Interview five teams already running confidential inference (customers of Privatemode, Tinfoil, Anjuna, Fortanix; health and fintech on Azure NCC). One question: "Has your auditor ever seen your attestation token?"
4. Add verifier JWKS auto-discovery for the four issuers and optional VCEK fetching behind an extra dependency.
5. Track four things: NDAA conference outcome, the JTC 21 cybersecurity standard, NVIDIA fleet-agent availability, and the IETF composite-platform EAT profile.
6. Do not build: flexHEG anything, metering, or any control that acts on a chip.

## §12 Sources

- Regulation (EU) 2026/1744 analyses: Cloud Security Alliance research note; Gibson Dunn; DLA Piper; Secure Privacy.
- CEN-CENELEC JTC 21 status: jtc21.eu; ai-act-standards.com; kla.digital tracker.
- Chip Security Act: House Foreign Affairs Committee / Select Committee on China releases; Americans for Responsible Innovation (Senate NDAA, 14 Jul 2026); NBC News; GeoComply whitepaper; CRS FY2027 NDAA status.
- NVIDIA location verification: Reuters via Tom's Hardware, TechPowerUp, PC Gamer (Dec 2025); NVIDIA statements on backdoors and kill switches.
- China CAC and NVIDIA H20: SCMP, CNBC (31 Jul 2025).
- Confidential computing: NVIDIA Technical Blog "Hardware-rooted AI security that won't slow you down" (2026); NVIDIA nvTrust repository and attestation claims guide; Intel Trust Authority documentation (attestation tokens, GPU attestation, policy v2); Microsoft Learn, Azure Attestation claim sets; Google Cloud, Confidential Space token claims; Canonical, Ubuntu confidential VMs on GCP A3 (Aug 2026); Azure blog on confidential GPUs.
- Standards: IETF RFC 9334, RFC 9711, draft-ietf-rats-corim-11, draft-sun-rats-composite-eat-00, draft-ietf-rats-ear; CHIPS Alliance / Microsoft on Caliptra 2.1 and OCP S.A.F.E.
- Research: CNAS "Secure, Governable Chips" (Jan 2024) and "Technology to Secure the AI Chip Supply Chain" (Dec 2024); O'Gara, Kulp et al., "Hardware-Enabled Mechanisms for Verifying Responsible AI Development" (arXiv 2505.03742); Petrie et al., flexHEG reports (arXiv 2506.15093, 2506.03409, 2506.15100); Ansari, "Hardware-Level Governance of AI Compute" (arXiv 2604.04712); Heim, "Considerations and Limitations for AI Hardware-Enabled Mechanisms".
- GPAI Code of Practice: European Commission; Freshfields; Latham & Watkins; The Future Society.
- Competitive: Vanta ISO 42001 and EU AI Act framework pages; Modulos vs Vanta; Fortanix at GTC 2026 (Business Wire); Anjuna EU AI Act guide.
