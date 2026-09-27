# Observable

Reference implementation of four Observable planes: **Agent Guard** (strong
identity and access control for AI agents, using tokens bound to
certificates issued by a pluggable qualified PKI), **Inventory &
Posture Management** (agentless SaaS/AI discovery, shadow-AI detection,
and posture findings, in the AppOmni tradition), **Detection**
(behavioral baselining that turns `risk_score` into a real, live signal
instead of a manually-set number), and **Compliance & SIEM/SOAR Export**
(a live control-by-control compliance report, plus CEF/JSON audit
export and SOAR-ready incident records). See `ARCHITECTURE.md` for the
design and its mapping to the Zero Trust for AI Agents guide's tiers.

## Install

```bash
pip install -r requirements.txt
```

## Run the tests

```bash
pytest -q
```

211 tests across all planes (PKI, identity, tokens, policy, audit +
gateway, Agent Guard HTTP API, SaaS connectors, inventory store,
shadow-AI detector, posture engine, Inventory HTTP API, behavior
baseline, anomaly scorer, detection engine + guard wiring, Detection
HTTP API, intent-conformance signal (§8.5), compliance framework +
report, compliance HTTP API, NIST AI RMF control set + Impact Register
(§9.5), CEF/JSON SIEM export, SOAR incident export, export HTTP API).

## Run the walkthroughs

```bash
python3 demo.py                      # Agent Guard: ARCHITECTURE.md §6
python3 inventory_demo.py            # Inventory & Posture: ARCHITECTURE.md §7
python3 detection_demo.py            # Detection plane: ARCHITECTURE.md §8
python3 intent_demo.py               # Intent-conformance signal: ARCHITECTURE.md §8.5
python3 compliance_export_demo.py    # Compliance & export: ARCHITECTURE.md §9
python3 nist_compliance_demo.py      # NIST AI RMF + Impact Register: ARCHITECTURE.md §9.5
```

`demo.py` runs the full Agent Guard flow against the real FastAPI app
in-process: enrollment, PoP-bound token issuance, an authorized call
with output redaction, two denials (missing scope, injection attempt), a
stolen-token replay rejected by proof-of-possession, automated
containment, and an audit-chain integrity check.

`inventory_demo.py` scans a mock SaaS tenant, shows two discovered AI
agents (one unenrolled = shadow AI), links one to an Observable identity to
clear its shadow flag, lists posture findings (stale admin account, no
MFA, an overly broad agent grant), then simulates the tenant granting a
new privileged permission and shows drift detection catching it.

`detection_demo.py` lets an agent's token run through a human-paced
string of normal lookups so the Detection Engine learns its baseline,
shows the learned baseline via `GET /detection/{agent_id}`, has the
operator set an automated-containment threshold via
`POST /admin/detection/threshold`, then simulates a stolen-token
replay — the same token rapid-fire scraping customer records it has
never touched before — and shows it getting caught and the agent
auto-contained mid-burst on behavior alone, with no rule anywhere
naming the specific resource IDs.

`intent_demo.py` arms the optional `intent_mismatch` signal
(`OBSERVABLE_INTENT_SCORER=mock`, no GPU needed) and declares a
reporting-analyst's purpose at token mint: reads that stay in scope for
that purpose sail through unaffected, while a call to a tool sharing no
vocabulary with the declared purpose gets flagged, pushing the combined
risk score over that tool's own policy ceiling — off by default in
every other walkthrough and deployment.

`compliance_export_demo.py` shows a fresh instance's compliance report
(some controls `partial` or `not_applicable` until an operator acts),
an inventory scan turning two controls red, the operator closing the
automated-containment gap, a live attack getting auto-contained, that
event exported as CEF for a SIEM, the same event as a SOAR-ready
incident with recommended next steps, and the incident closing itself
out once the operator reinstates the agent.

`nist_compliance_demo.py` shows the Impact Register (MAP 5) seeded
with Observable's own reflexive-governance entries, adds and resolves
one more entry, then runs `GET /compliance/report?framework=nist-ai-rmf`
— a second, independent lens over the same live instance, mapped to
NIST AI RMF 1.0's GOVERN/MAP/MEASURE/MANAGE subcategories instead of
the Zero Trust for AI Agents guide's rows — including one control
(MEASURE 3.3) that deliberately reports `fail`: no end-user/agent-
operator feedback or appeal channel exists yet, a real, named gap
rather than a hidden one. The original `?framework=zta` report keeps
working unchanged on the same endpoint.

## Serve it for real

```bash
uvicorn observable.api.app:app --reload
```

Note: this reference deployment terminates the "mTLS" proof-of-possession
at the application layer (signed requests — see `observable/api/pop.py`),
not via a TLS-terminating proxy. Point a real mTLS gateway at it and keep
the signature check as defense-in-depth, or extend `pop.py`'s
verification to read the certificate a proxy injects instead.

## Directory layout

```
observable/
  pki/            Block 1 — CertificateAuthority interface + ReferenceCA
  identity/       Block 2 — Identity Registry (enroll, lifecycle)
  tokens/         Block 3 — Token Service (PoP-bound JWT mint/verify)
  policy/         Block 4 — Policy Engine + tool registry
  guard/          Block 5 — Audit chain + Agent Guard gateway logic
  api/            Block 6 (+7-11) — FastAPI app wiring it together
  client/         Block 6 — Agent-side SDK
  inventory/      Blocks 7-10 — SaaS connectors, inventory store,
                  shadow-AI detector, posture findings engine
  detection/      §8 — behavior baseline, anomaly scorer, detection
                  engine; §8.5 — intent-conformance signal (intent.py)
  compliance/     §9.1 — control framework + report generation;
                  §9.5 — NIST AI RMF control set + Impact Register
  export/         §9.2-9.3 — CEF/JSON SIEM export, SOAR incident export
tests/                     pytest suite, one file per block
demo.py                    Agent Guard end-to-end walkthrough (§6)
inventory_demo.py          Inventory & Posture end-to-end walkthrough (§7)
detection_demo.py          Detection plane end-to-end walkthrough (§8)
intent_demo.py             Intent-conformance signal walkthrough (§8.5)
compliance_export_demo.py  Compliance & export end-to-end walkthrough (§9)
nist_compliance_demo.py    NIST AI RMF + Impact Register walkthrough (§9.5)
ARCHITECTURE.md            Full design document
```
