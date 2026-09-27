# Observable — Architecture

**Observable** is a SaaS-and-AI security platform (agentless posture management,
threat detection, compliance) with an integrated identity-and-access control
plane for AI agents: **Agent Guard**. This document specifies Agent Guard,
since that is the piece with novel architecture: strong cryptographic
identity and access tokens for agents, both issued from a qualified PKI.

It implements the Zero Trust for AI Agents guide's controls, mapped to the
guide's three tiers (Foundation / Enterprise / Advanced), and treats every
control against the guide's own test: **does this make the attack
impossible, or just tedious?**

---

## 1. Scope of this version

v1 builds the **Agent Guard core**:

1. **PKI plane** — pluggable Certificate Authority interface, so Observable can
   sit in front of a qualified Trust Service Provider (QTSP under eIDAS,
   e.g. a QTSP issuing qualified certificates) or a self-operated CA
   (EJBCA, step-ca, HashiCorp Vault PKI), without changing anything above
   the interface.
2. **Identity plane** — agent enrollment, unique cryptographic identity,
   lifecycle (issue / renew / suspend / revoke).
3. **Token plane** — short-lived, certificate-bound (proof-of-possession)
   access tokens, scoped per request, issued only to agents that prove
   possession of their private key.
4. **Policy plane** — deny-by-default RBAC + ABAC, a signed tool registry
   (least agency: which tool, which verbs, which resources, at what
   times), and policy evaluation at every request.
5. **Guard plane** — the enforcement gateway agents actually call through:
   policy decision + input sanitization + tamper-evident audit log +
   automated containment (suspend/quarantine/revoke).

Not in v1 (flagged for v2, see §7): behavioral baselining / anomaly
detection, SIEM streaming, sandboxed execution runtime, hardware attestation,
full multi-agent tracing, output semantic analysis.

---

## 2. Trust model

- **No implicit trust from network location.** Every call to a protected
  resource — including calls between Observable's own internal services — is
  authenticated with a certificate and authorized per request.
- **Assume breach.** Any single agent, any single service, or the CA
  intermediate can be compromised; the blast radius is bounded by short
  token lifetimes, narrow scopes, and hash-chained audit trail that makes
  tampering detectable even if an attacker gets write access to the log
  store.
- **Root of trust lives outside Observable.** The Root CA key is never held by
  the Observable process. Observable holds (or calls out to) an **Issuing CA**
  intermediate, which is what actually signs agent certificates. In
  production the Issuing CA's private key sits in an HSM or is operated by
  a QTSP; Observable's `CertificateAuthority` interface abstracts this so the
  reference implementation (software-only, for dev/test) and a
  production HSM/QTSP-backed implementation are interchangeable.
- **Two independent credential layers, deliberately redundant:**
  1. the agent's **X.509 certificate** (long-lived identity, minutes-to-
     months validity depending on tier),
  2. the agent's **access token** (short-lived, minutes, cryptographically
     bound to that certificate's public key — a stolen token is useless
     without the matching private key).
  This satisfies the guide's Foundation-tier token requirement *and*
  Enterprise-tier mTLS requirement simultaneously, and removes the classic
  weakness of bearer tokens (usable by whoever holds the string).

---

## 3. Component map

```
                                   ┌─────────────────────────┐
                                   │   Qualified PKI / QTSP   │
                                   │  (external, pluggable)   │
                                   └────────────┬─────────────┘
                                                │ CA interface
                                   ┌────────────▼─────────────┐
                                   │      CA Adapter          │
                                   │ (ReferenceCA in dev;      │
                                   │  EJBCA/step-ca/Vault/QTSP │
                                   │  adapter in prod)         │
                                   └────────────┬─────────────┘
                                                │
        ┌───────────────────────────────────────┼───────────────────────────────────────┐
        │                                       │                                       │
┌───────▼────────┐                   ┌──────────▼──────────┐                 ┌──────────▼──────────┐
│ Identity        │                   │  Token Service       │                 │  Policy Engine        │
│ Registry        │  issues CSR  ───▶ │  (PoP-bound, scoped, │                 │  (RBAC+ABAC, tool     │
│ (enroll, store,  │◀── cert ──────── │  short-lived JWTs)    │                 │  registry, least      │
│ lifecycle)       │                   └──────────┬──────────┘                 │  agency)               │
└───────┬─────────┘                              │                            └──────────┬──────────┘
        │                                        │                                       │
        └──────────────────┬─────────────────────┴───────────────────┬───────────────────┘
                            │                                         │
                     ┌──────▼─────────────────────────────────────────▼──────┐
                     │              Agent Guard Gateway                       │
                     │  mTLS termination → PoP check → policy decision →      │
                     │  input sanitization → forward to tool/SaaS API →       │
                     │  output check → hash-chained audit append              │
                     └──────┬───────────────────────┬───────────────────┬────┘
                            │                        │                   │
                    ┌───────▼──────┐        ┌────────▼───────┐   ┌──────▼──────┐
                    │ Protected     │        │ Audit Chain     │   │ Response /  │
                    │ tools / SaaS  │        │ (signed, hash-  │   │ Containment │
                    │ APIs          │        │ linked log)     │   │ (suspend,   │
                    └───────────────┘        └─────────────────┘   │ revoke,     │
                                                                     │ quarantine) │
                                                                     └─────────────┘
```

Everything above is exposed over one FastAPI service (`observable.api`) plus a
thin Python SDK (`observable.client`) that agents import to enroll, fetch tokens,
and call the gateway. All internal component-to-component calls go through
the same mTLS + PoP path as external agent calls — there is no "trusted
internal network" shortcut.

---

## 4. Certificate and token profiles

### 4.1 Agent certificate (X.509)

| Field | Value |
|---|---|
| Subject CN | `agent:<uuid>` (never a human-readable service name alone) |
| SAN | `URI:observable:agent:<uuid>`, plus organization-defined SANs |
| Key | EC P-256 (default) or RSA-3072 if the QTSP requires it |
| Extended Key Usage | `clientAuth` |
| Validity | Foundation: 90 days · Enterprise: 7 days · Advanced: 24h + hardware-bound key (TPM/HSM), attested at issuance |
| Extensions | Custom OID `1.3.6.1.4.1.55555.1.1` carries the agent's declared **role** and **tier**, checked against the Policy Engine's registry at every token issuance (belt-and-braces: even a validly-signed cert cannot claim a role it wasn't enrolled with) |
| Revocation | CRL + OCSP via the CA adapter; Guard checks revocation status on every PoP validation, not just at issuance |

### 4.2 Access token (PoP-bound JWT)

Modeled on RFC 7523 (JWT bearer) + RFC 7800/8705 (PoP / mTLS-bound tokens).

```json
{
  "iss": "observable-token-service",
  "sub": "agent:5b1e...c2",
  "cnf": { "x5t#S256": "<base64url SHA-256 of agent's leaf cert DER>" },
  "scope": "tool:crm.read tool:email.send:rate=10/min",
  "role": "sales-assistant",
  "tier": "enterprise",
  "aud": "observable-gateway",
  "iat": 1758359999,
  "exp": 1758360299,
  "jti": "a93f...",
  "req_ctx": { "risk_score": 0.1, "purpose": "ticket-triage" }
}
```

- **`exp - iat` = 300s by default** (Foundation: ≤15 min; Enterprise: ≤5 min;
  Advanced: ≤60s + continuous re-authorization per request instead of a
  session-length token — see §5.4).
- The Guard gateway will **reject any token whose `cnf` thumbprint does not
  match the TLS client certificate presented on the same connection.** A
  stolen token is inert without the private key; a stolen private key still
  only yields a 5-minute blast window per token, revocable at the CA layer
  immediately.
- `scope` is a space-delimited list of `tool:<name>[:constraint]` entries,
  never a broad "admin" scope — this is Least Agency, not just least
  privilege: it says which tool, and the constraint narrows verb/rate/
  resource.

---

## 5. Control-by-control mapping to the guide

| Guide capability | Tier targeted in v1 | Observable mechanism |
|---|---|---|
| Unique cryptographic identifiers | Foundation | Identity Registry issues one UUID + cert per agent instance, never reused |
| Certificate-based auth, full lifecycle | Enterprise | CA Adapter (issue/renew/revoke), CRL/OCSP |
| Hardware-bound identity, attested issuance | Advanced | `CertificateAuthority.issue()` accepts an optional `attestation` object (TPM/HSM quote); reference CA validates format, production adapter validates the quote against the platform's attestation service |
| Short-lived tokens from an identity provider | Foundation | Token Service, 5–15 min JWTs, PoP-bound |
| mTLS with certificate pinning | Enterprise | Gateway terminates mTLS, pins `cnf` to leaf cert per request |
| RBAC, deny-by-default | Foundation | Policy Engine: no match ⇒ deny; default policy set is empty |
| ABAC with context (time, risk score) | Enterprise | Policy Engine evaluates `req_ctx` (time window, risk score, resource sensitivity) alongside role |
| Continuous authorization, real-time revocation | Advanced | Every Guard request re-checks policy + revocation, not just at token mint; a policy or revocation change is live within one token TTL (≤5 min) |
| Identity-based isolation | Foundation | Every internal service call also goes through Guard/PoP; no service trusts a caller by network origin |
| Comprehensive action logs | Foundation | Guard logs every tool invocation, actor, decision, timestamp |
| Immutable audit trails, integrity verification | Enterprise | Hash-chained (`prev_hash`) + Ed25519-signed log entries; any edit breaks the chain, detectable by `verify_chain()` |
| Input sanitization | Foundation/Enterprise | Guard validates request shape/length before forwarding; pattern-based injection filtering at Enterprise |
| Output filtering | Foundation | Guard scans tool responses for credential/PII patterns before returning to the agent |
| Automated containment | Enterprise | Guard can auto-suspend an agent's certificate and revoke all outstanding tokens (`respond.contain_agent()`) on a policy-defined trigger; decision to escalate stays human, per the guide's "automate the bookkeeping, not the decisions" rule |
| Version-controlled / signed policy | Enterprise | Policy bundles are JSON, hash-referenced, and (optionally) signed by an authorized policy-admin cert before the engine will load them |

Rows intentionally left for v2 (not built here): sandboxed execution,
confidential computing, OpenTelemetry distributed tracing,
spotlighting/constitutional-classifier input validation. Statistical
anomaly detection is delivered in §8 (v1.2) and SIEM/SOAR export in §9
(v1.3); true ML behavioral models remain deferred (§8.4).

---

## 6. Request flow (worked example)

**Scenario:** a `sales-assistant` agent wants to call `tool:crm.read` for
account `A-102`.

1. Agent enrolled once (out of band, approved by an operator) → holds a
   private key + Identity Registry-issued certificate signed by the Issuing
   CA.
2. Agent calls `POST /token`, presenting its client certificate over mTLS
   and the scope it wants. Token Service:
   - verifies the cert chains to the trusted Issuing CA and is not revoked;
   - checks the Policy Engine: does this agent's enrolled role permit
     `tool:crm.read`? deny-by-default if no explicit grant;
   - mints a 5-minute JWT with `cnf` bound to the cert's SHA-256 thumbprint
     and `scope: tool:crm.read`.
3. Agent calls `POST /gateway/invoke` with the JWT (Authorization header)
   over the *same* mTLS connection. Agent Guard:
   - confirms `cnf` thumbprint == this connection's client cert thumbprint
     (PoP check — rejects token replay from a different key);
   - confirms token not expired, not for a revoked agent;
   - re-evaluates policy against current context (ABAC: is it inside
     business hours? has the agent's risk score changed since token mint?);
   - runs input sanitization on the request payload;
   - forwards to the CRM tool adapter, scoped strictly to `read`;
   - scans the tool's response for sensitive-pattern leakage;
   - appends a hash-chained, signed audit entry recording actor, decision,
     scope used, and outcome;
   - returns the (possibly redacted) result to the agent.
4. If the agent's certificate is later suspended (compromise detected),
   every outstanding token for that `cnf` is rejected at step 3 within one
   TTL window (≤5 minutes), and the Issuing CA marks the cert revoked so no
   new mTLS handshake succeeds at all.

---

## 7. Inventory & Posture Management plane (v1.1)

This is the AppOmni-style "Identify" layer the platform description
calls for: agentless, connector-based discovery of what SaaS apps and
AI agents actually exist in an organization's tenants, independent of
whether they were ever enrolled in Agent Guard. It is what makes Agent
Guard's identity plane trustworthy rather than aspirational — an
enrolled-agent list is only meaningful once you can also see what's
running *outside* it.

### 7.1 Why this comes before detection or compliance

Agent Guard (§1-§6) answers "is this specific, already-enrolled agent
allowed to do this action." It cannot answer "what agents exist in our
Salesforce/M365/ServiceNow tenants at all" — that requires reading the
SaaS platforms themselves, agentlessly, the way AppOmni does. Without
that, every downstream capability (posture findings, compliance
reports, anomaly baselines) is scoped only to agents Observable already
knows about, which is exactly the blind spot the guide calls Shadow AI.

### 7.2 Component map addition

```
        ┌─────────────────────────┐
        │   SaaS tenant (real     │
        │   or mock connector)    │
        └────────────┬─────────────┘
                     │ SaaSConnector interface
        ┌────────────▼─────────────┐
        │      Inventory Store      │◀── snapshot history, diffing
        └────────────┬─────────────┘
                     │
      ┌───────────────┼───────────────┐
      │                                │
┌─────▼──────┐                ┌────────▼────────┐
│ Shadow AI /  │                │ Posture Findings │
│ Shadow SaaS  │                │ Engine           │
│ Detector     │                │ (rule-based scan) │
└─────┬──────┘                └────────┬────────┘
      │ cross-references              │
┌─────▼──────────────┐                 │
│ Identity Registry    │◀───────────────┘ (findings can reference
│ (Block 2)            │                    an enrolled agent's
└──────────────────────┘                    identity_registry status)
```

### 7.3 Design principles

- **Pluggable connector interface**, same pattern as
  `CertificateAuthority`: nothing above `SaaSConnector` cares whether
  data comes from a `MockConnector` (dev/demo, deterministic sample
  tenant) or a real OAuth-based Salesforce/M365 Graph/ServiceNow
  adapter. v1.1 ships the interface plus the mock; real adapters are a
  contained addition later.
- **Read-only, agentless.** A connector only ever reads (apps, agents,
  users, permissions, config). It never has write/delete scope on the
  target SaaS tenant — matching the platform description's "agentless
  architecture."
- **Snapshots, not a live feed.** Each scan produces an immutable,
  timestamped `TenantSnapshot`. The store keeps snapshot history per
  app so posture findings can diff snapshot N against N-1 to detect
  configuration drift, not just point-in-time risk.
- **Shadow AI is a diff, not a guess.** A discovered SaaS-native agent
  (a Salesforce Agentforce bot, an M365 Copilot extension, a ServiceNow
  agent) is matched against the Identity Registry by its external
  reference. No match, or a match to a `revoked`/`suspended` Observable
  identity, means the agent is operating with zero Observable enrollment —
  exactly the gap the guide's "unscoped privilege inheritance" and
  "identity and privilege abuse" threats exploit.
- **Findings carry a severity and a reason, never just a count.** Every
  posture finding names the specific object (app, permission, account)
  and the rule that fired, so it can drive the same kind of
  step-by-step remediation guidance the guide's Enterprise-tier
  observability capability calls for.

### 7.4 What v1.1 does *not* do

One-click compliance report generation and real (non-mock) connectors
are deferred — the interface and store are built so those are additive,
not a rearchitecture. Statistical risk scoring was deferred in v1.1 and
is delivered next, in §8.

---

## 8. Detection plane (v1.2)

This is the piece that makes `risk_score` — used by ABAC (§5) and
available to automated containment — a real, live number instead of a
value a caller sets by hand. It closes the roadmap item from the
original v1 document: "baseline learning + statistical/ML anomaly
scoring feeding `req_ctx.risk_score`."

### 8.1 Design principles

- **Statistics, not ML.** Every signal is a plain online statistic or
  threshold check — an online mean/variance (Welford's algorithm) on
  call spacing, a bounded count of distinct never-seen resources in a
  rolling window, a deny-rate fraction, a first-time-tool check weighted
  by the tool's registered sensitivity. This is deliberately the guide's
  Foundation/Enterprise-tier capability ("threshold-based alerts",
  "statistical anomaly detection with tunable sensitivity"), not the
  Advanced-tier ML baseline — and it stays fully explainable: every
  `risk_score` this plane produces comes with the exact named signals
  that produced it, never an opaque number.
- **Scoring and learning are separate operations on the same state.**
  `DetectionEngine.pre_score()` is read-only: given an agent's current
  baseline, how anomalous would this next event be? `record_event()` is
  the only thing that mutates a baseline, and Agent Guard calls it only
  once an event's outcome (allow/deny/error) is actually known. This
  means scoring a request never depends on that same request's own
  outcome, and a denied attempt still teaches the baseline (a string of
  denials is itself a signal — see the deny-rate check).
- **One agent, one baseline, online.** There is no separate offline
  training step. A baseline starts empty and firms up with every real
  event, which is also how it naturally tolerates an agent's behavior
  legitimately drifting over time (the guide's Advanced-tier "continuous
  baseline refinement") without a retraining job.
- **The risk_score feeds two places, not one.** It flows into
  `ActionContext.risk_score` for the Policy Engine's existing ABAC
  `max_risk_score` check (§5) unconditionally — so even with no
  automated containment configured at all, a sufficiently risky first
  call on a sensitive, low-risk-ceiling tool is denied by policy that
  already existed. Automated containment (below) is a second, opt-in
  consumer of the same number.
- **Automated containment is a threshold an operator sets, not a
  judgment Agent Guard makes.** `AgentGuard(auto_contain_threshold=...)`
  (or `set_auto_contain_threshold()` at runtime) is `None` by default.
  Once set, crossing it suspends the agent and denies the triggering
  request in the same call — instant and total, per the containment
  design in §6 — but the *decision* that a given risk level is
  intolerable was made by a human when they set the number. This is the
  same "automate the bookkeeping around incidents, not the decisions"
  rule the guide states directly: the decision is made in advance and in
  the open (visible in `/admin/detection/threshold`); execution is
  mechanical.

### 8.2 The four signals

| Signal | What it measures | Fires when |
|---|---|---|
| `burst_rate` | Welford mean/std of inter-call spacing, z-scored against the candidate interval | z exceeds a threshold (call is much faster than this agent's own normal pace) and at least 5 intervals have been learned |
| `new_tool` | Whether this tool has ever been called by this agent before | first use, weighted by the tool's registered sensitivity (0.4 high / 0.25 medium / 0.1 low / 0.2 unknown) via `PolicyEngine.tool_sensitivity()` |
| `new_resource_burst` | Count of distinct never-before-seen resource IDs touched in a 60s rolling window | count reaches 5 |
| `deny_rate` | Fraction of the last 10 minutes' decisions that were deny/error | at least 4 recent attempts and the fraction exceeds 50% |

Individual signal scores combine via noisy-OR
(`combined = 1 - Π(1 - signal_i)`), so one strong signal dominates but
several weak ones still add up — never simple summation, which would
blow past 1.0 with only two or three signals firing.

### 8.3 Component map addition

```
                 ┌───────────────────────────┐
                 │      Agent Guard (§6)       │
                 │  ...verify token, then:     │
                 │  pre_score() ──────────────┼──▶ risk_score feeds
                 │  (before deciding anything) │    ActionContext (ABAC)
                 │  ...decide, act, log...     │
                 │  record_event() via _log()  │
                 └──────────────┬──────────────┘
                                │
                 ┌───────────────▼───────────────┐
                 │       Detection Engine          │
                 │  one AgentBehaviorBaseline       │
                 │  per agent_id                    │
                 └───────────────┬───────────────┘
                                │ optional backfill
                 ┌───────────────▼───────────────┐
                 │         Audit Chain (§6)         │
                 │  ingest_from_audit() replays      │
                 │  existing history into a fresh     │
                 │  baseline after a restart          │
                 └─────────────────────────────────┘
```

### 8.4 What v1.2 does *not* do

Cross-agent/cross-tenant anomaly correlation, geo/IP-based signals
("impossible travel" — no location data is available in this reference
deployment), and true ML behavioral models (the guide's Advanced tier)
are deferred. The four signals here are the cheap, explainable floor a
mature program should have before reaching for any of those.

---

## 9. Compliance & SIEM/SOAR export (v1.3)

Closes the two rows §5 explicitly deferred: the guide-to-mechanism
mapping is useful to a builder, but an operator eventually has to hand
something to an auditor, and a detected incident is only as good as
the case it turns into in whatever system the security team actually
works from. Both are read-only views over state the platform already
maintains (the registry, the policy bundle, the audit chain, the
Inventory Store, the Detection Engine) — nothing here is a new source
of truth.

### 9.1 Compliance framework

`observable/compliance/` turns the §5 table into a fixed list of ~11 named
controls, each backed by a small function that inspects the *running*
instance, not a questionnaire filled in once and left to rot:

* **Live/data-driven** checks read (never mutate) the registry, policy
  engine, audit chain, and inventory store, or run a genuinely
  side-effect-free probe against the policy engine (e.g. "does an
  unregistered tool ever get granted, at any tier?"). These can go from
  PASS to FAIL as the deployment's actual state changes — an unsigned
  policy bundle, a scan that turns up a stale admin account, an
  operator who hasn't yet configured an auto-containment threshold, a
  tampered audit entry.
* **Structural/by-design** checks report a property of the code path
  itself (e.g. "every token `verify()` re-checks the registry, not just
  at mint") — these can't be probed without faking a real request, so
  they PASS by construction, with evidence pointing at the exact
  module/function a reviewer should go read to confirm it themselves.

Every check returns a `ControlResult` (`pass` / `fail` / `partial` /
`not_applicable`, a plain-language summary, and an evidence list), and
`generate_report()` rolls all of them into one `ComplianceReport`. The
report's `overall_status` is `fail` if anything failed, else `partial`
if anything is partial (never silently rounds a partial control up to
green), else `pass`. `GET /compliance/report` exposes it over HTTP.

Generating a report is guaranteed side-effect-free — no check ever
suspends an agent, mutates the audit chain, or runs a scan on the
operator's behalf; it only reads what is already there. A control
whose live check would require a scan or a threshold that hasn't been
configured reports `not_applicable`, not a false pass.

### 9.2 SIEM export

`observable/export/cef.py` formats the audit chain two ways a SIEM already
knows how to ingest — pure functions of `AuditEntry`, no I/O:

* **CEF** (Common Event Format) — one line per entry, with severity
  escalating allow (1) < deny (6) < error (7) < containment action (8),
  so denials and containment events surface in a SIEM's default views
  without custom rules.
* **JSON Lines** (NDJSON) — one compact JSON object per entry, the
  shape Splunk HEC, Elastic Filebeat, and most log shippers ingest with
  zero parsing rules.

`GET /export/siem?format=cef|json` returns the formatted body as plain
text. Deliberately not a push integration: which collector a customer
points at (a syslog relay, Splunk's HEC endpoint, Sentinel's agent) is
a deployment decision, and this reference implementation's sandboxed
network has no live SIEM to push to regardless — the same reasoning
that kept a real Salesforce/M365 connector out of the Inventory plane
(§7).

### 9.3 SOAR incident export

`observable/export/soar.py` reads the audit chain's `containment:*` entries
(already logged by `contain_agent` / `revoke_agent` / `reinstate_agent`,
§6) and turns each one into a `SoarIncident`: a severity
(`suspend`→high, automated `suspend`→critical, any `revoke`→critical),
a plain-language trigger reason, and a short list of concrete
recommended next steps (check the agent's audit trail and learned
baseline, check its SaaS-side footprint via the Inventory plane's
shadow-AI findings, reinstate or escalate to revoke). A later
`containment:reinstate` for the same `agent_id` closes the matching
open incident, so a SOAR case tracker sees a full open→closed
lifecycle instead of an ever-growing pile of stale "open" cases.
`GET /export/soar/incidents` returns the current set as JSON, ready for
a SOAR platform's case-creation API (Splunk SOAR/Phantom, XSOAR, Tines,
or a plain ticketing webhook) — again, formatting only, no push.

### 9.4 What v1.3 does *not* do

No live SIEM/SOAR push (HEC token, webhook auth, retry/backoff) — the
sandbox this was built in has no such endpoint to push to, and which
one a customer uses is a deployment choice regardless. No OCSF/STIX
schema mapping (CEF and plain JSON cover the near-term ingestion path;
a customer standardized on OCSF would want a dedicated mapper). No
scheduled/automatic report generation or diffing between two
compliance reports over time — `GET /compliance/report` is generated
fresh on every call from live state.

---

## 10. Directory layout (code delivered with this document)

```
observable/
  pki/            Block 1 — CertificateAuthority interface + ReferenceCA
  identity/       Block 2 — Identity Registry (enroll, lifecycle)
  tokens/         Block 3 — Token Service (PoP-bound JWT mint/verify)
  policy/         Block 4 — Policy Engine + tool registry
  guard/          Block 5 (+detection wiring, §8) — Audit chain + Agent
                  Guard gateway logic
  api/            Block 6 (+7-11, +detection, +compliance/export) — FastAPI
                  app wiring it together
  client/         Block 6 — Agent-side SDK
  inventory/      Blocks 7-10 — SaaS connectors, inventory store,
                  shadow-AI detector, posture findings engine
  detection/      §8 — behavior baseline, anomaly scorer, detection engine
  compliance/     §9.1 — control framework + report generation
  export/         §9.2-9.3 — CEF/JSON SIEM export, SOAR incident export
  tests/          pytest suite, one file per block
  demo.py                    Scripted walkthrough of §6 (Agent Guard)
  inventory_demo.py          Scripted walkthrough of §7 (Inventory & Posture)
  detection_demo.py          Scripted walkthrough of §8 (Detection plane)
  compliance_export_demo.py  Scripted walkthrough of §9 (Compliance & export)
```
