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

Not in v1 (flagged for v2, see §7): SIEM streaming, hardware attestation,
full multi-agent tracing, output semantic analysis. (Behavioral
baselining / anomaly detection was flagged here in the original scope
note but was delivered in v1.2, §8; tool execution sandboxing was also
flagged here but a time/result-bounded — not OS-level — version was
delivered in v1.10, §9.10. Both lines are kept accurate rather than left
to imply they're still missing.)

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
  "scope": "tool:crm.read:resource=A-1,A-2 tool:email.send:rate=10/min",
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
- **The `resource=` constraint clause is enforced, not just carried.**
  `tool:crm.read:resource=A-1,A-2` authorizes `crm.read` only against
  those two resource_ids — a call for any other resource_id is denied by
  the Policy Engine (`observable/policy/engine.py`,
  `Scope.resource_allowlist()` in `observable/tokens/scope.py`), even
  though the token itself is validly signed and unexpired. A grant with
  no `resource=` clause at all keeps the original, unrestricted,
  tool-only granularity — resource scoping is opt-in per grant, not a
  new requirement on every scope. A token can carry more than one grant
  for the same tool (e.g. two separate resource-scoped approvals); Agent
  Guard tries every one of them against the live call and allows it if
  any matches (§6 step 5), rather than only ever checking the first.
  A malformed constraint (`resource=` with nothing after it, a duplicate
  clause) is rejected at grant time by `authorize_scopes` — it's never
  minted into a token — and, belt-and-braces, `authorize_action` fails
  closed on it too if a malformed `Scope` ever reaches it some other way.
  The `rate=` clause in the example above still only parses — nothing
  enforces a call-rate ceiling yet; that remains open (§5's "not built"
  list).

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
| Privilege scoping — resource-level granularity | Enterprise (v1.7) | A scope's `resource=` constraint is enforced, not just carried: `authorize_action` denies a call whose `resource_id` isn't in the grant's set (§4.2) |
| Privilege scoping — dynamic/JIT elevation | Enterprise/Advanced (v1.8) | `ElevationStore` (§9.8): time-boxed, per-agent grant of one tool a role doesn't statically carry; authorizes new mints and live calls immediately, automatically stops authorizing anything the instant it expires or is revoked — no separate cleanup step. Still missing: there is no automated "task completion" trigger — only a wall-clock TTL or an explicit early revoke |
| Privilege scoping — call-rate ceiling ("how often") | Enterprise (v1.9) | `RateLimiter` (§9.9): a scope's `rate=10/min`-style constraint is enforced, not just carried — `authorize_action` denies once an agent has made `limit` calls to that tool within the trailing window, checked last so a call denied for any other reason never consumes budget |
| Continuous authorization, real-time revocation | Advanced | Every Guard request re-checks policy + revocation, not just at token mint; a policy or revocation change is live within one token TTL (≤5 min) |
| Identity-based isolation | Foundation | Every internal service call also goes through Guard/PoP; no service trusts a caller by network origin |
| Comprehensive action logs | Foundation | Guard logs every tool invocation, actor, decision, timestamp |
| Immutable audit trails, integrity verification | Enterprise | Hash-chained (`prev_hash`) + Ed25519-signed log entries; any edit breaks the chain, detectable by `verify_chain()` |
| Input sanitization | Foundation/Enterprise | Guard validates request shape/length before forwarding; pattern-based injection filtering at Enterprise |
| Output filtering | Foundation | Guard scans tool responses for credential/PII patterns before returning to the agent |
| Automated containment | Enterprise | Guard can auto-suspend an agent's certificate and revoke all outstanding tokens (`respond.contain_agent()`) on a policy-defined trigger; decision to escalate stays human, per the guide's "automate the bookkeeping, not the decisions" rule |
| Behavioral analysis with contextual awareness | Advanced (partial, v1.4) | Optional `intent_mismatch` signal (§8.5): a self-hosted CLM model judges whether each tool call fits the agent's declared purpose; capped, fail-open, off by default |
| Version-controlled / signed policy | Enterprise | Policy bundles are JSON, hash-referenced, and (optionally) signed by an authorized policy-admin cert before the engine will load them |
| Sandboxed tool execution | Foundation (v1.10) | `observable.guard.sandbox` (§9.10): every tool invocation runs under a wall-clock deadline and a result-size cap, so a slow, hung, or runaway tool can't block Guard or exhaust the response path; per-tool overrides via `ToolDefinition`. Not OS-level process/container isolation — see §9.10's caveats |

Rows intentionally left for v2 (not built here): confidential computing,
OpenTelemetry distributed tracing, spotlighting/constitutional-classifier
input validation, and OS-level (process/container) isolation of tool
execution — v1.10 bounds a tool's *time and output*, not a full
untrusted-code sandbox (§9.10). Statistical anomaly detection is
delivered in §8 (v1.2) and SIEM/SOAR export in §9 (v1.3). One
model-derived signal, intent conformance, is delivered in §8.5 (v1.4);
full ML behavioral models remain deferred (§8.6).

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
mature program should have before reaching for any of those. v1.4 adds
one optional model-derived signal on top of that floor, not in place of
it (§8.5).

### 8.5 Intent-conformance signal (v1.4)

The four signals in §8.2 see *how* an agent behaves — its pace, what
is new to it, how often it is denied — but not *whether an action makes
sense for what the agent is supposed to be doing*. That blind spot is
where the guide's hardest threats live: tool chaining (a CRM read
followed by an external send), confused-deputy relays, indirect prompt
injection. In each of them every call is authorized and statistically
unremarkable; only its fit with the agent's purpose is wrong.

v1.4 adds one optional fifth signal, `intent_mismatch`
(`observable/detection/intent.py`). Before each decision, it asks one
question: *given this agent's role, its declared purpose
(`req_ctx.purpose`, signed into its token at mint, §4.2) and its recent
allowed tool calls, is calling this tool consistent with that purpose?*
The answer is a probability `p_consistent`.

**Scoring.** If `p_consistent` ≥ 0.5 the signal does not fire. Below
that, it contributes

`risk = 0.5 × (0.5 − p_consistent) / 0.5`

to the same noisy-OR as the statistical signals, so its contribution is
capped at 0.5. The label is readable in the audit trail like the others:
`intent_mismatch(tool='reporting.export', p_consistent=0.10,
purpose='weekly summary of booking activity', scorer=clm)`.

**Worked example (`intent_demo.py`).** A `reporting-analyst` token
declares the purpose "weekly summary of booking activity". Reading
bookings and generating the summary pass. A first call to
`reporting.export` scores `new_tool` = 0.25 statistically, under that
tool's ABAC ceiling (`max_risk_score` 0.5), so the statistical plane
alone would allow it. With `intent_mismatch` = 0.40 the combined score
is 0.55, and the existing ceiling denies it. No new policy was needed:
the signal only raised the live `risk_score` that ABAC already reads.

#### Design principles

- **Pluggable scorer**, same pattern as `CertificateAuthority` (§2) and
  `SaaSConnector` (§7.3). `IntentScorer` is the interface; nothing above
  it changes when an implementation is swapped.
  - `MockIntentScorer` — deterministic keyword overlap between the
    purpose and the tool's name/description. No semantic understanding;
    it exists so the full path runs in tests and demos without a GPU.
    Never for production.
  - `CLMIntentScorer` — adapter for a self-hosted Contrastive Language
    Model server (`clm-serve`, CLM-v0.1-8B on a frozen Qwen3-8B
    encoder, Apache 2.0). It calls `POST /v1/systemone` with one yes/no
    question and reads back the probability. It uses a yes/no question
    rather than CLM's ranking endpoint on purpose: ranking returns
    probabilities *relative to the candidate set*, which would penalise
    every legitimate step of a multi-tool workflow that isn't the single
    "best" next move. The adapter depends only on `httpx`; no torch or
    CLM package in the Observable process.
- **What the scorer sees is deliberately narrow:** role, declared
  purpose, the last 5 allowed tool calls, and the requested tool's name
  and registered description. Never the request payload. Payload-level
  judgments (injection, leakage) are separate concerns (§8.6).
- **A signal, never a control.** The 0.5 cap means this signal alone
  cannot deny a tool whose ceiling is above 0.5, nor trip an
  auto-containment threshold set above 0.5. It can only push an
  already-suspicious request over a line an operator drew. Deny-by-
  default policy, PoP tokens and scopes are untouched. Under the guide's
  "impossible vs tedious" test a probabilistic scorer is friction, so
  it is placed where friction is useful: adding evidence, not
  replacing barriers.
- **Fail-open, but loudly.** If the scorer times out or errors, the
  request is scored without this signal and the hard controls still
  apply. The outage is never silent: it appears as a `degraded` note on
  the assessment, in `GuardResult.detection_degraded` and the invoke
  response, in the audit entry's reason ("detection degraded: …"), and
  as failure counters in `GET /admin/detection/intent`.
- **Off the hot path where it doesn't matter.** A per-tool sensitivity
  floor (`OBSERVABLE_INTENT_MIN_SENSITIVITY`) limits model calls to
  tools at or above it. The `clm` default is `medium`, so low-risk
  reads never wait on a model. The scorer runs outside the Detection
  Engine lock, so a slow model never serializes other agents' scoring.
  CLM caches action-side embeddings server-side; the registered tool
  descriptions are a small fixed set, so they stay cached.
- **Off by default; turning it on is an operator decision**, like the
  auto-containment threshold (§8.1): `OBSERVABLE_INTENT_SCORER=off |
  mock | clm`. Adding an ML-derived input to authorization should never
  happen implicitly.
- **Explainability, stated honestly.** §8.1 promises every `risk_score`
  comes with the named signals that produced it. That holds here: the
  signal is named, its probability and the purpose it was judged
  against are logged. What is *not* explainable is why the model
  produced that probability. That is why the signal is capped, labelled
  with its scorer, and the only model-derived signal in the plane.

#### Component map addition

```
   Agent Guard ── pre_score(agent, tool, role, purpose) ──▶ Detection Engine
                                                               │
                         recent allowed tools (baseline) ──────┤
                                                               ▼
                                                        IntentChecker
                                          (skip rules, cap, degrade, stats)
                                                               │ IntentScorer
                                         ┌─────────────────────┴───────────────┐
                                         ▼                                     ▼
                                 MockIntentScorer                      CLMIntentScorer
                                 (dev / demo)                    HTTP ─▶ clm-serve :8700
                                                                        (self-hosted GPU,
                                                                         Qwen3-8B + CLM heads)
```

#### Deployment

The CLM server runs outside Observable, on a GPU host the customer
controls (Qwen3-8B needs roughly 24 GB of GPU memory). Following the
guide's supply-chain phase, it is self-hosted rather than called as a
third-party API, and its weights (the ~75 MB CLM heads and the Qwen3-8B
encoder) should be recorded in an AI-BOM and pinned by hash. Observable
reaches it with `OBSERVABLE_CLM_URL` and, if configured,
`OBSERVABLE_CLM_API_KEY`.

### 8.6 What v1.4 does *not* do

- **The declared purpose is chosen by the agent at token mint.** A
  compromised agent can declare a purpose that fits its malicious
  action. The signal still catches drift within a token's lifetime
  (a purpose fixed at mint, actions that stray from it), which is the
  prompt-injection case. Binding purposes per role or per enrollment,
  set by an operator rather than the agent, is the next step.
- **No payload analysis.** CLM could also serve as a second-layer input
  classifier ("does this tool response contain instructions addressed to
  an agent?") and as output semantic analysis. Both need CLM heads
  fine-tuned on labelled adversarial data before they can be trusted,
  and are deferred.
- **Zero-shot only.** The production adapter uses the base CLM-v0.1-8B
  checkpoint. Fine-tuning its heads on Observable's own labelled
  audit history (cheap: only the projection heads train) is expected to
  be needed before this signal is weighted more heavily.
- **Not validated against a live model in this repository.** The
  adapter's HTTP contract is tested against a mocked server; accuracy
  and latency must be measured on the customer's GPU host before
  enabling `clm` in production.

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

## 9.5 NIST AI RMF alignment: a second lens + Impact Register (v1.5)

§9.1's `DEFAULT_CONTROLS` map one-to-one to this document's own §5
table — a builder's view of the Zero Trust for AI Agents guide. NIST AI
RMF 1.0 asks a related but distinct question set (GOVERN/MAP/MEASURE/
MANAGE), and rather than force one control list to answer both, v1.5
adds a second, independent control set, `NIST_AI_RMF_CONTROLS`
(`observable/compliance/nist_ai_rmf.py`), over the *same* running
instance and the *same* `ComplianceContext` (§9.1) — plus one new piece
that MAP 5 specifically calls for and nothing before v1.5 provided: an
**Impact Register**.

### Impact Register (MAP 5)

`observable/compliance/impact_register.py` is a small, queryable store
of characterized impacts: a title, category (privacy / fairness /
security / safety / third-party / transparency), the affected parties,
a severity and likelihood, a status (`open` / `mitigated` / `accepted`),
and — when applicable — the mitigation actually in place. It is
in-memory, seeded at startup, same persistence posture as the
Inventory Store (§7) and the audit chain in this reference deployment.

It is seeded, not left empty, with impacts identified while doing this
alignment work — and deliberately including impacts of **Observable's
own** detection/intent-conformance components, not only the agents
Observable monitors. The Detection Engine (§8) and the intent-
conformance signal (§8.5) are themselves statistical/model-derived
components feeding an authorization boundary — "AI systems" under the
guide's own definition — and MAP 5 applies to them reflexively. The
seeded entries: a false positive from the Detection Engine blocking
legitimate agent work (mitigated: signals are capped and explainable,
every containment is a reviewable SOAR incident); possible bias or
blind spots in the intent-conformance CLM scorer (left **open** —
honestly, since §8.6 already documents it as zero-shot and unvalidated
against a live model); Observable's own detection plane being an AI
system under the guide's definition, stated explicitly rather than left
implicit (mitigated by this register and this compliance mode
existing); and a downstream SaaS tenant not being notified when one of
its connected agents is auto-contained (left **open** — a real gap).

`GET /compliance/impact-register` lists the register; `POST
/compliance/impact-register` adds an entry; `POST
/compliance/impact-register/{entry_id}/status` updates one's status
and mitigation. All three are plain CRUD over an in-memory store — no
new architecture, matching the "small, explicit, auditable" posture of
every other plane here.

### NIST AI RMF compliance-report mode

`GET /compliance/report?framework=nist-ai-rmf` runs the same live
checks NIST AI RMF actually asks for, reusing the exact registry,
policy engine, audit chain, inventory, and detection engine the
existing `?framework=zta` (default, unchanged) report reads — plus the
Impact Register. A representative slice, not full RMF coverage:

| Subcategory | What it checks |
|---|---|
| GOVERN 1.1 | Policy bundle is version-hash-referenced and signed |
| GOVERN 1.5 | Audit chain integrity holds; both report modes are regenerable live |
| MAP 1.1 | Registered tools carry a documented description (also what §8.5 judges intent against) |
| MAP 5.1 | Impact Register: any impact characterized; none left `open` and unmitigated at high/critical severity |
| MAP 5.2 | Third-party impacts: shadow-AI/posture findings (§7) plus Impact Register entries tagged `third_party` |
| MEASURE 2.1 | Structural: every plane ships tests plus a scripted demo walkthrough |
| MEASURE 2.6 | Honest partial whenever the intent-conformance signal is armed: capped and explainable, but explicitly zero-shot/unvalidated (§8.6) |
| MEASURE 3.3 | **Deliberate FAIL**: no end-user/agent-operator feedback or appeal channel exists yet in this reference deployment |
| MANAGE 1.3 | Whether an auto-containment threshold is actually configured, not just available |
| MANAGE 4.1 | Post-deployment monitoring: audit volume, live per-agent baselines, live reports |

MEASURE 3.3 is the control worth calling out by name: it always reports
`fail` in this reference deployment, on purpose. A compliance mode that
never shows red is not one an auditor should trust, and NIST AI RMF
frames risk management as continuous rather than a one-time
attestation — this mode is built to actually change as gaps like this
one get closed, not to attest that none exist.

`nist_compliance_demo.py` walks all of this end-to-end: the seeded
register, adding and resolving an entry, the NIST report showing a real
mix of pass/partial/fail, and the original `?framework=zta` report
still working unchanged over the same instance.

### NIST AI RMF cycle, on the Overview

The read-only `/console` dashboard's Overview page renders Observable's
four planes as the NIST AI RMF cycle itself, not just a control table:
a donut split into three clickable sectors for MAP (Inventory &
Posture, §7), MEASURE (Detection, §8), and MANAGE (Agent Guard, §1-6),
around a center hub for GOVERN (Compliance & Export, §9) — matching
the guide's own diagram, where GOVERN is cross-cutting rather than a
fourth equal slice, not a plain 4-way pie. Each block shows a live KPI
(open shadow-AI/posture findings, agents with an established baseline,
open containment incidents, overall compliance status) pulled from data
the console already loads, and is clickable straight through to that
plane's existing tab — a navigation aid over data already on the page,
not a new endpoint.

### Marketing landing page, at the root path

`GET /` serves `static/landing.html`, a standalone marketing page for
observable24.com — separate from, and unrelated to, the security
platform's own data model. Unlike `console.html`, it is a complete
document (own `<!doctype>`/`<head>`) with no live data and no JS: a
static page describing the four planes and their NIST AI RMF mapping in
prose, reusing the console's color tokens and IBM Plex type for visual
consistency. It intentionally lives in the same FastAPI app and Render
service as the rest of Observable so that one deployment, and one
domain once DNS is pointed at it, carries both the public-facing page
and the read-only console (still at `/console`, unchanged). `GET /`
previously redirected to `/console`; that redirect is gone now that
root has its own page.

### Brand identity: favicon and the red/grey palette

Both `/` and `/console` link a shared favicon (`static/icons/`:
`favicon.ico`, 16×16, 32×32, and a 180×180 Apple touch icon) built from
Observable's eye-mark logo, served via two dedicated routes
(`GET /favicon.ico` — the path browsers request by default regardless
of any `<link>` tag — and `GET /icons/{filename}`, allowlisted by exact
filename). The same logo (icon + "Observable" wordmark, plus the
tagline "Observe. Understand. Act." in the landing page's footer) also
replaces the console's previous shield glyph in the sidebar brand mark.

The UI's accent palette shifted from the original blue/teal/violet/amber
mix to a red/grey identity matching the logo: `--brand-red-1`/`-2` are
the logo's own fixed gradient stops (used only for the mark itself,
independent of theme); `--accent` (console) and `--accent`/`--accent-light`
(landing page) are the red functional accent (buttons, nav, the MAP
plane); `--accent-2`, `--plane-measure`, and the new `--plane-manage`
token are grey/charcoal shades covering the MEASURE and MANAGE planes
and the console's secondary UI. The semantic status colors
(`--ok`/`--warn`/`--critical`/`--na` — pass/partial/fail/not-applicable)
are deliberately untouched: they carry real compliance meaning and
`--warn`'s amber stayed reserved for "partial" status rather than being
repainted into the brand palette. One direct consequence: the console's
audit "agent activity map" previously colored *allowed* calls with the
same blue as everything else and *denied* calls with `--critical`
(red); now that the functional accent is also red, *allowed* calls were
switched to `--accent-2` (grey) so allowed-vs-denied stays visually
distinct instead of both reading as shades of red.

### What v1.5 does *not* do

No feedback/appeal channel itself (MEASURE 3.3 names the gap; closing
it is future work, not this change). No mapping to the full NIST AI RMF
subcategory list — the ten above are the ones this specific running
instance can meaningfully probe live, in the same spirit as §9.1's
"fixed, explicit list beats a configurable rules DSL" choice. No
durable persistence for the Impact Register (re-seeded on restart, like
every other in-memory store in this reference deployment).

## 9.6 Agents risk score over time (v1.6)

§8's Detection Engine always computed a live `risk_score` per call, but
nothing kept a *history* of it — the Detection tab (§8) only ever showed
the current baseline snapshot. This adds a per-agent time series of
every scored `risk_score`, purely on top of the existing statistical
engine (no CLM/model-derived signal, §8.5, is involved).

**Storage.** `AgentBehaviorBaseline` gets a new `risk_history: deque[(timestamp,
risk_score)]` field, bounded by count (`maxlen=500`) rather than the
1-hour wall-clock window `_prune()` uses for the other deques (§8.3) —
a chart of "how has this agent trended" should not silently lose its
oldest points just because they've aged past an hour. `DetectionEngine.record_risk_score()`
appends to it; `risk_history()`/`all_risk_histories()` read it back as
plain `{"t": iso8601, "risk_score": float}` dicts, per-agent or for
every agent that's been scored at least once.

**Wiring.** `AgentGuard.invoke()` calls `record_risk_score()` immediately
after step 2.5's `pre_score()` (§6's request-flow numbering) — the same
place §8 already computes the live score, so every scored call gets a
sample regardless of what happens next: allowed, denied for an
unrelated ABAC/policy reason, or auto-contained. The tamper-evident
Audit Chain (§3, §6) is deliberately untouched: this is a lightweight,
in-memory, best-effort series for a dashboard chart, not a security
record, so it doesn't belong in the hash-linked, signed chain.

**API.** `GET /detection/risk-history` returns every scored agent's
series in one response — `{"agents": [{agent_id, display_name, role,
status, points: [{t, risk_score}, ...]}, ...]}` — rather than one round
trip per agent. It's registered *above* the existing parameterized
`GET /detection/{agent_id}` route (§8), not below: FastAPI/Starlette
matches routes in registration order, and a literal `/detection/risk-history`
after a wildcard `/detection/{agent_id}` would be swallowed by it
(`agent_id="risk-history"`) and never reached.

**Console.** A new "Agents risk score" tab (`console.html`) — a left-nav
button alongside Detection and Incidents — renders every agent's series
as a hand-rolled SVG multi-line chart (same inline-SVG approach as the
NIST cycle ring and the activity map, §9.4/Overview): x is wall-clock
time, y is `risk_score` (0–1, gridlines at quarters), one polyline per
agent in a dedicated qualitative palette (`--chart-1`..`--chart-8`,
defined per theme) chosen specifically *not* to reuse the semantic
`--ok`/`--warn`/`--critical`/`--na` status colors, since a chart-line's
color here means "which agent," not "pass/fail." The legend below the
chart restates each agent's latest score, colored by that semantic
scale instead (≥0.6 critical, ≥0.3 warn, else ok) — so the same number
means agent-identity in the line and risk-level in the legend, without
conflating the two palettes.

### What v1.6 does *not* do

No way to zoom, pan, or filter to a time window — the chart always
plots everything currently retained (up to 500 points/agent). No
threshold/auto-contain reference line drawn on the chart itself (§8's
`/admin/detection/threshold` value isn't visualized here, only enforced
live). No historical backfill from the Audit Chain on restart — unlike
`ingest_from_audit()` for the baseline's other state (§8.3), a fresh
process starts every agent's risk history empty, since no `risk_score`
field exists on `AuditEntry` to replay from (and adding one was
deliberately ruled out above, to keep the audit schema unchanged).

## 9.7 Resource-scoped grants (v1.7)

§4.2 always *described* a `resource=` constraint clause on a scope
(`tool:crm.read:resource=A-1`) as part of what makes this Least Agency
rather than plain least privilege — but until now nothing actually read
it. A grant only ever narrowed *which tool*, never *which record*. This
closes that gap, purely within the existing scope/token/policy model —
no new token fields, no schema change.

**Grammar.** A scope's `constraint` string is `;`-separated `key=value`
clauses (`observable/tokens/scope.py`, `parse_constraint()`); a value
may itself be a comma-separated list. `Scope.resource_allowlist()`
reads the `resource` clause specifically and returns the set of allowed
`resource_id`s, or `None` if the scope carries no such clause at all
(the original, unrestricted, tool-only grant — resource scoping is
opt-in per grant, existing scopes and tests are unaffected). A
malformed clause (`resource=` with nothing after it, a duplicate key)
raises rather than being silently read as "unrestricted."

**Enforcement, fail-closed at two points:**
- `PolicyEngine.authorize_scopes()` (mint time) drops a requested scope
  whose constraint doesn't parse — the same way it already drops a
  scope for an unregistered tool. A malformed grant is never minted
  into a token in the first place.
- `PolicyEngine.authorize_action()` (every request, §6 step 5) denies
  the call if the scope carries a `resource=` allowlist and either no
  `resource_id` was given (can't confirm it's in-bounds) or the given
  `resource_id` isn't in that set. A scope that somehow reaches this
  check still malformed (not possible via `authorize_scopes`, but
  defense in depth for a directly-constructed `Scope`) denies too,
  rather than being treated as unrestricted.

**Multiple grants per tool.** A token can carry more than one scope
entry for the same tool — e.g. two separate resource-scoped approvals
made at different times (`tool:crm.read:resource=A-1` and
`tool:crm.read:resource=B-1`). `AgentGuard.invoke()` (§6 step 5) tries
every scope matching the requested tool name and allows the call if
*any* of them authorizes it against the live context, rather than only
ever evaluating the first match — a change from before this feature,
when only one scope per tool was ever meaningfully possible.

### What v1.7 does *not* do

No dynamic/JIT privilege elevation — a resource-scoped grant is exactly
as static as an unrestricted one; it's requested once at mint time and
lasts the token's TTL, not "elevated for this one task, then reverted."
No enforcement of the `rate=` clause at the time this section was
written — since closed in §9.9. No resource *hierarchies* or
wildcards (`resource=account/*`) — the allowlist is an exact-match set
of literal IDs. No UI surface for granting or reviewing resource-scoped
grants — they're requested the same way any scope is, via
`requested_scopes` on `POST /token`.

## 9.8 Just-in-time privilege elevation (v1.8)

§9.7 closed "which resource"; this closes the other half of Privilege
Scoping the guide calls out: "when" and "for how long." Before this, a
role's grants were exactly as static as the bundle that defined them —
the only way to give an agent a capability its role lacks was to change
the bundle itself (affecting every agent with that role, forever, until
someone remembers to change it back). `ElevationStore`
(`observable/policy/elevation.py`) grants one specific agent one
specific tool — optionally narrowed to specific `resource_id`s, exactly
like §9.7's constraint — for a bounded time, and it stops authorizing
anything the instant that time elapses or an operator revokes it early.
No background job, timer, or cleanup step exists or is needed: every
check (`ElevationGrant.is_active(now)`) is evaluated fresh against
whatever `now` the caller passes, the same way token TTL and CRL expiry
already work in this codebase — "automatic expiration" means the check
that used to say yes simply starts saying no.

**Two integration points, matching the guide's own RBAC/ABAC split
(§4.2, §6):**
- **At mint** (`PolicyEngine.authorize_scopes`, now also taking
  `agent_id`): if the static bundle doesn't grant a requested tool to
  this role, an active elevation grant for this specific agent+tool is
  checked as a fallback. If one exists, the *grant's own* scope is
  minted — never the raw request — so an elevation can only ever narrow
  what ends up in the token, never be used to ask for more than what
  was actually approved (a request for unrestricted `crm.delete` when
  the only active grant is `resource=A-1` mints `resource=A-1`, not
  unrestricted access).
- **At every action** (`PolicyEngine.authorize_action`, `ActionContext`
  now also carrying `agent_id`): the same static-grant-missing branch
  re-checks for a still-active elevation, every single call — not just
  at mint. This is what makes expiry and early revocation take effect
  immediately, mid-token-life, without needing to separately invalidate
  the JWT: the token still parses and still hasn't hit its own TTL, but
  the very next `invoke()` is denied the moment the elevation itself
  is gone. The per-call resource check that follows is the same one
  §9.7 already added — it re-validates against whatever the *scope*
  carries (which, for an elevated grant, is exactly what was minted
  above), not against the elevation store a second time.
- **Tier is not elevatable.** A tool's `min_tier` requirement (§4.2) is
  checked identically regardless of whether access comes from a static
  role grant or an elevation — elevation raises "what a role can reach,"
  it does not lower the identity-assurance bar a tier represents.

**Multiple grants, and which one wins.** An agent can hold more than one
active elevation for the same tool (e.g. two separate, narrower
approvals granted at different times); `ElevationStore.active_grant_for`
breaks ties by most-recently-granted, so a newer correction takes
precedence without the older grant needing to be explicitly revoked
first. Separately, `AgentGuard.invoke()` (§6 step 5) already tries every
scope a token carries for the requested tool name (added in §9.7 for
multiple resource-scoped RBAC grants) — the same loop covers a token
that carries more than one elevation-derived scope, with no extra code.

**Auditability.** `AgentGuard.grant_elevation()`/`revoke_elevation()`
are the only way to create or end a grant, and both write a hash-chained
audit entry (`elevation:grant` / `elevation:revoke`, alongside the
existing `containment:*` actions) — "log all privilege changes" from
the guide's Enterprise row, satisfied the same way containment already
satisfies "automate the bookkeeping, not the decisions": the decision to
elevate is the caller's (an operator, or an upstream approval workflow),
Guard only enforces and records it.

**API.** `POST /admin/elevation/grant`, `POST /admin/elevation/{id}/revoke`,
`GET /admin/elevation` (optionally filtered by `agent_id`) — mirroring
the existing `/admin/contain`/`/admin/reinstate` pair.

### What v1.8 does *not* do

No automated "task completion" trigger — a grant ends on its wall-clock
TTL or an explicit early revoke, never on Observable inferring that the
task it was granted for is actually done. No approval workflow of its
own (who may call `grant_elevation`, or a request/approve handshake) —
this module enforces and audits whatever a caller decides; deciding
who's allowed to decide is deployment-specific, out of scope here, same
caveat as automated containment's "the decision stays human." No
enforcement of the `rate=` constraint clause at the time this section
was written — since closed in §9.9. No console UI for granting,
reviewing, or revoking elevations — API-only for now, same as §9.7's
resource scoping.

## 9.9 Call-rate enforcement (v1.9)

§9.7 closed "which resource," §9.8 closed "when/for how long." This
closes the last piece of the scope grammar that §4.2's example JWT
always showed but nothing ever read: `tool:email.send:rate=10/min` —
Least Agency's "how often," not just "which tool." Before this, a
`rate=` clause parsed cleanly and then did nothing; any grant, static or
elevated, resource-scoped or not, authorized unlimited calls for its
entire lifetime.

**A sliding-window counter, per `(agent_id, tool)`.** `RateLimiter`
(`observable/policy/ratelimit.py`) keys its counters by agent and tool —
deliberately *not* by scope string or by grant — because what a rate
clause actually limits is "how many times has this agent invoked this
tool recently," regardless of which grant (a static role, a
resource-scoped one, or a JIT elevation) happened to authorize any
individual call. Two different grants for the same tool share one
ceiling rather than each getting its own budget. `check_and_record()` is
an atomic check-and-increment: a denied attempt records nothing, so
retrying right after a legitimate denial isn't doubly penalized and an
agent can't be locked out indefinitely by its own denied attempts.
`count_in_window()` is a separate, read-only introspection method that
never mutates state.

**Grammar.** `Scope.rate_limit()` (`observable/tokens/scope.py`) reads
the constraint's `rate` clause (`<count>/<unit>`, unit one of
`s`/`sec`/`second(s)`, `m`/`min`/`minute(s)`, `h`/`hr`/`hour(s)`,
`d`/`day(s)`) and returns `(max_calls, window)`, or `None` if the scope
carries no `rate=` clause at all — the original, unlimited grant,
unaffected, exactly as `resource_allowlist()` already does for the
`resource` clause. A zero/negative count or unrecognized unit raises,
the same fail-closed behavior as every other malformed constraint in
this grammar.

**Enforcement, the same two-point pattern as §9.7 and §9.8:**
- `PolicyEngine.authorize_scopes()` (mint time) also validates
  `scope.rate_limit()` parses, alongside the existing
  `resource_allowlist()` check, dropping the scope if not — a malformed
  rate clause is never minted into a token.
- `PolicyEngine.authorize_action()` (every request) checks the rate
  limit *last*, after tier, business-hours, risk-score, and resource
  checks have all already passed — so a call that would be denied
  anyway for an unrelated reason never consumes rate budget. If the
  agent is at or over `limit` calls to that tool within the trailing
  `window`, the call is denied with a reason naming the current count,
  the limit, and `retry_after`; otherwise the call is recorded and
  allowed. This is also the one check in `authorize_action` that
  mutates state — deliberately the last thing evaluated, so only calls
  that are actually going to be admitted are ever counted.
- Needs `context.agent_id` (added in §9.8) to key the counter; a
  rate-limited scope presented with no `agent_id` is denied rather than
  silently treated as unlimited.

**Automatic reset, same idiom as everything else in this codebase.**
Nothing expires or gets cleaned up on a timer — the sliding window is
just "calls within `window` of `now`," re-evaluated fresh on every
check, so a ceiling that was hit simply starts admitting calls again
the instant the oldest call ages out, with no separate reset step, the
same way token TTL, CRL revocation, and elevation expiry already work.

**API.** No dedicated admin endpoint — like §9.7's resource scoping,
rate limiting is purely a property of whatever scope was requested at
`POST /token` (`tool:email.send:rate=10/min`), enforced transparently
wherever that clause appears, not a separately granted or revoked
capability.

### What v1.9 does *not* do

No distributed rate limiting — `RateLimiter` is in-memory and
per-process, same durability model (and the same "resets to empty on
restart is the safe failure direction") as the Identity Registry, Audit
Chain, Detection Engine baselines, and Elevation Store; a multi-process
or multi-region deployment would need a shared store (Redis, etc.) for
one ceiling to hold across all of them. No token-bucket/burst
allowance — a plain sliding window, so a ceiling of `10/min` is exactly
"no more than 10 calls in any trailing 60 seconds," never a burst
credit that can spike briefly. No per-resource rate ceilings (`rate=`
combined with `resource=` limits the *tool* overall, not each resource
separately) and no admin API for granting, adjusting, or inspecting
limits — same gap as §9.7's resource scoping, requested the same way
any other scope constraint is.

## 9.10 Tool execution sandboxing (v1.10)

The last row §5 carried as "intentionally left for v2": sandboxed
execution. §9.7–§9.9 each bound *whether* a call is authorized
(which resource, for how long a grant lasts, how often). This bounds
something different — once a call *is* authorized, what the tool
invoker itself is allowed to do to the Gateway process while it runs,
independent of authorization entirely. Before this, step 6 of
`AgentGuard.invoke()` called a registered tool invoker directly and
simply waited for it to return (or raise); a tool that hung forever
blocked that call forever, and a tool returning an arbitrarily large
result had nothing stopping it from doing so.

**Scoped honestly to what this codebase's tools actually are.**
Observable's tools are first-party Python callables a deployer
registers in-process (`AgentGuard.register_tool`) — often closures over
shared in-memory demo state, as `observable/api/state.py`'s own
`crm_read`/`email_send`/etc. are — not arbitrary untrusted code a tenant
uploads. So the threat this closes is "a slow, buggy, or hung tool
degrades the service for other agents," not "a malicious tool escapes
to the host." That second, harder threat model — a real untrusted-code
sandbox — needs OS-level isolation (a separate process or container, a
seccomp/gVisor boundary, a network-egress policy) and tools invoked
across a process boundary rather than as in-process closures; both are
a rearchitecture out of scope here (see "What v1.10 does *not* do").

**Two bounds, enforced by `observable/guard/sandbox.py`'s
`run_sandboxed()`, wrapped around step 6 of `invoke()`:**
- **A wall-clock execution deadline.** The invoker runs on its own
  `threading.Thread(daemon=True)`; `run_sandboxed()` waits up to
  `timeout_seconds` for it to finish. If it doesn't, a `ToolTimeoutError`
  is raised and `invoke()` returns control to its caller immediately —
  what the deadline actually buys is bounding how long *the request*
  (and whatever's waiting on it — an HTTP worker) stays blocked on one
  tool, not reclaiming the CPU time already spent. Python has no safe,
  portable way to forcibly kill a running thread, so the invoker's own
  thread is abandoned, not terminated; it keeps running in the
  background until it finishes on its own or the process exits. The
  thread is daemonized specifically so a tool that never returns can't
  also wedge a graceful shutdown.
- **A result-size cap.** Once the invoker returns, its result is
  JSON-encoded and measured; a result over `max_result_bytes` raises a
  `ResultTooLargeError` instead of being handed to output filtering and
  the response path. A result that isn't JSON-serializable at all is
  deliberately let through unchanged — diagnosing *that* failure belongs
  to Gateway's existing output-encoding path, in its own terms, not to
  this boundary.

**Fail path, same shape as the existing `ToolExecutionError`.** Both
violations are raised as `SandboxViolation` (a `ToolTimeoutError` or
`ResultTooLargeError`), which `invoke()` catches and re-raises as a
`ToolExecutionError` — the same exception type, and the same `502`
mapping at the API layer (§6 `app.py`), a tool invoker's own exception
already produced. The audit entry's reason is prefixed
`"sandbox violation: ..."` so it reads distinctly from
`"tool invocation raised: ..."` in the audit trail, even though both
share the `error` decision and the same exception class at the Python
level.

**Defaults, with a per-tool override.** `AgentGuard` takes
`sandbox_timeout_seconds` (default 10s) and `sandbox_max_result_bytes`
(default 1 MB) at construction, applied to every tool. `ToolDefinition`
gained two matching optional fields,
`max_execution_seconds`/`max_result_bytes` (`None` means "use the
Guard's default," the same convention `min_tier=None` already uses) —
so one unusually slow or chatty tool (a `reporting.export` that
legitimately takes longer, say) can be given its own bound via the
policy bundle without loosening the default for every other tool.
`PolicyEngine.tool_sandbox_limits(tool_name)` is the read accessor
Guard calls before each invocation, alongside the existing
`tool_sensitivity`/`tool_description` accessors.

### What v1.10 does *not* do

No OS-level isolation — no separate process, container, or
seccomp/gVisor boundary; a tool still runs with the same memory space,
filesystem access, and network reachability as the rest of the
Gateway process. No hard CPU or memory ceiling — `RLIMIT_CPU`/`RLIMIT_AS`
are process-wide on POSIX, not something a single thread inside a
shared interpreter can be bound by individually, so a CPU-bound runaway
tool is time-boxed (the *caller* is released) but is not prevented from
continuing to spend CPU in the background until it finishes. No network
egress control for what a tool calls out to. No forced termination of a
timed-out invoker — Python provides no safe way to kill a running
thread, so a timed-out tool's thread is abandoned, not stopped; under
sustained, repeated timeouts this means unboundedly many abandoned
threads can accumulate for the life of the process. No distributed or
shared sandbox state — bounds are purely per-process, same durability
model as every other piece of live state in this reference deployment
(Identity Registry, Audit Chain, Elevation Store, Rate Limiter). No
admin API for inspecting or adjusting sandbox limits at runtime — they
are set at `AgentGuard` construction and per-tool in the policy bundle,
not changeable through `POST`/`GET` endpoints the way containment and
elevation are.

## 9.11 Operator console authentication (v1.11)

Not a guide control — §5 maps Zero Trust capabilities for *AI agents*,
and this is a human-facing gap in the platform itself: `/console` was a
read-only dashboard served with no authentication at all. Anyone who
found the URL could view agent inventory, compliance status, and audit
history. v1.11 closes that with a small, deliberately separate identity
system for the humans operating Observable, under `observable/accounts/`
— distinct from, and never cross-checked against, the PKI/PoP identity
system the rest of this document specifies for AI agents. An operator
account proves a human may view the console; an agent certificate proves
an AI agent may call the Gateway. They answer different questions and
are not meant to be unified.

**Two factors, both required, reusing primitives already built for the
agent side where the shape matched exactly:**
- **Password** — PBKDF2-HMAC-SHA256 (`observable/accounts/passwords.py`),
  390,000 iterations (OWASP's 2023 minimum), random 16-byte salt per
  password, constant-time comparison. Stdlib-only, like the rest of this
  reference's cryptographic primitives — no new dependency for a
  well-specified, NIST-recommended KDF.
- **TOTP (RFC 6238)** — `observable/accounts/totp.py`, also stdlib-only
  (HMAC-SHA1 over a 30-second time counter, same reasoning as the
  password hashing: a small, standard primitive doesn't need a new
  third-party dependency). Interoperable with any standard authenticator
  app via the `otpauth://` provisioning URI returned once at setup.

**Login is two HTTP round-trips, matching how authenticator apps are
actually used:**
1. `POST /login/password` — checked against a sliding-window
   `RateLimiter` *before* the password itself is checked, keyed by
   username rather than `(agent_id, tool)` — the exact same class
   §9.9 built for per-agent tool-call throttling, reused here to
   throttle brute-force login guessing instead of a runaway agent. On
   success, issues a short-lived (5 min) "pending MFA" token as an
   `HttpOnly` cookie — proof the password step passed, nothing more.
2. `POST /login/verify` — the pending-MFA cookie plus a TOTP code;
   on success, issues a 12-hour session token as a second `HttpOnly`
   cookie and revokes the pending one. `GET /console` now requires a
   live, unexpired session cookie (`observable.accounts.session.TokenStore`)
   or redirects to `/login` — the dashboard is simply unreachable
   without having passed both factors.

**Bootstrap, single-operator reference scope.** There is no open
registration endpoint. `POST /accounts/setup` creates the one operator
account this deployment will ever have, returns the TOTP secret and
provisioning URI *once*, and then permanently refuses (`409`) — "first
operator becomes the operator," the same bootstrap pattern many
single-tenant admin tools use, rather than a multi-account system this
reference scope doesn't need yet.

**Fail-closed details worth naming explicitly:** a nonexistent username
still runs a password-hash comparison against a throwaway value (so a
missing account isn't measurably faster to reject than a wrong password
for a real one); a wrong TOTP code doesn't burn or reissue the pending
login, so a mistyped code can simply be retried within the same 5-minute
window; every store here (`AccountStore`, the pending-MFA and session
`TokenStore`s, the login `RateLimiter`) is in-memory and process-local,
the same durability tradeoff — and the same "resets to empty is the safe
failure direction" — already made for the Elevation Store and the
per-agent Rate Limiter.

### What v1.11 does *not* do

Single operator only — no multi-account roles, no invitation flow, no
per-operator audit attribution (console views aren't logged the way
agent tool calls are). No password reset or account-recovery flow — a
lost password or a lost authenticator app has no self-service path in
this reference scope; the only way back in is restarting the process
(which clears the in-memory `AccountStore` and allows `/accounts/setup`
to run again). No backup/recovery codes for 2FA. No account lockout
beyond the sliding-window login throttle (an attacker who waits out the
window can keep guessing indefinitely, just slowly). No CSRF protection
on the login endpoints — acceptable for a JSON API called by same-origin
`fetch()` with `SameSite=Lax` cookies, but a production deployment
embedding this in a larger application should review that assumption.
No hardware-key (WebAuthn/FIDO2) second-factor option — TOTP only.

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
  detection/      §8 — behavior baseline, anomaly scorer, detection engine;
                  §8.5 — intent-conformance signal + scorers (intent.py)
  compliance/     §9.1 — control framework + report generation;
                  §9.5 — NIST AI RMF control set + Impact Register
                  (nist_ai_rmf.py, impact_register.py)
  export/         §9.2-9.3 — CEF/JSON SIEM export, SOAR incident export
  accounts/       §9.11 — human-operator accounts, password hashing (RFC-free,
                  stdlib PBKDF2), TOTP 2FA (RFC 6238), session/pending-MFA
                  token stores — separate from the AI-agent identity system
  tests/          pytest suite, one file per block
  demo.py                    Scripted walkthrough of §6 (Agent Guard)
  inventory_demo.py          Scripted walkthrough of §7 (Inventory & Posture)
  detection_demo.py          Scripted walkthrough of §8 (Detection plane)
  intent_demo.py             Scripted walkthrough of §8.5 (Intent signal)
  compliance_export_demo.py  Scripted walkthrough of §9 (Compliance & export)
  nist_compliance_demo.py    Scripted walkthrough of §9.5 (NIST AI RMF + Impact Register)
```
