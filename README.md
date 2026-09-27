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

163 tests across all planes (PKI, identity, tokens, policy, audit +
gateway, Agent Guard HTTP API, SaaS connectors, inventory store,
shadow-AI detector, posture engine, Inventory HTTP API, behavior
baseline, anomaly scorer, detection engine + guard wiring, Detection
HTTP API, compliance framework + report, compliance HTTP API, CEF/JSON
SIEM export, SOAR incident export, export HTTP API).

## Run the walkthroughs

```bash
python3 demo.py                      # Agent Guard: ARCHITECTURE.md §6
python3 inventory_demo.py            # Inventory & Posture: ARCHITECTURE.md §7
python3 detection_demo.py            # Detection plane: ARCHITECTURE.md §8
python3 compliance_export_demo.py    # Compliance & export: ARCHITECTURE.md §9
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

`compliance_export_demo.py` shows a fresh instance's compliance report
(some controls `partial` or `not_applicable` until an operator acts),
an inventory scan turning two controls red, the operator closing the
automated-containment gap, a live attack getting auto-contained, that
event exported as CEF for a SIEM, the same event as a SOAR-ready
incident with recommended next steps, and the incident closing itself
out once the operator reinstates the agent.

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
                  engine
  compliance/     §9.1 — control framework + report generation
  export/         §9.2-9.3 — CEF/JSON SIEM export, SOAR incident export
tests/                     pytest suite, one file per block
demo.py                    Agent Guard end-to-end walkthrough (§6)
inventory_demo.py          Inventory & Posture end-to-end walkthrough (§7)
detection_demo.py          Detection plane end-to-end walkthrough (§8)
compliance_export_demo.py  Compliance & export end-to-end walkthrough (§9)
ARCHITECTURE.md            Full design document
```
