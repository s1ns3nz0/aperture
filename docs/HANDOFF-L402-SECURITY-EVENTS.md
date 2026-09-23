# Handoff: L402 Security Events for SIEM Collection

Date: 2026-09-23. Status: design agreed; implementation not started.

## Objective and ownership

Add opt-in, structured security events to seller-side Aperture so an operator's collector can forward them to a SIEM. This is a separate issue and change set from the L402 Prometheus metrics work (#286).

This handoff records the decisions reached with the user through `grill-me`. It is not permission to publish an issue or PR, push, deploy, change existing secrets, or contact third parties. The present task created documentation only. Obtain an implementation request before modifying production code.

## Repository and baseline

- Actual repository: `lightning-labs/aperture/aperture` (nested inside the project directory).
- Upstream remote `origin`: `lightninglabs/aperture`.
- Fork remote `fork`: `s1ns3nz0/aperture`.
- Observed branch: `chore/install-codex-harness`.
- Observed HEAD: `78cacdd05c673312bfb80d4efcd96e015a9a12c7`.
- This HEAD already includes the two metrics commits, `cb7d889` and `3e864d4`.
- The local K8s deployment was independently identified as release v0.5.0, commit `311220b15b04c06ecabd52c78fde8f5d6ea73c82`, with no source modifications reported by the binary. Do not confuse this with the fork HEAD or upstream master.
- Existing untracked work at inspection: `.threatmodel/` and `mpp/jcs_fuzz_test.go`. Preserve it.

Read `AGENTS.md` before starting. Refresh Git state and confirm the implementation base; do not silently carry the metrics commits into an unrelated security-logging PR. Keep the parent directory's existing `HANDOFF.md` unchanged: it is older context, not the decision record for this work.

## Agreed decisions

| Area | Decision |
|---|---|
| Mechanism | Structured JSON security events, not a new severity level |
| Enablement | Separate opt-in setting, default OFF; `securitylog.enabled` is the proposed name |
| Log-level independence | When enabled, security events are emitted regardless of the ordinary application log threshold |
| Coverage | Authentication success and failure, payment challenge issuance, and settlement-check outcomes |
| Authentication cardinality | Exactly one final L402 authentication outcome per request reaching the L402 authentication path; no success sampling |
| Severity | INFO for normal payment flow and authentication acceptance/denial; ERROR for internal storage, invoice-lookup, or other processing failures |
| Output | Existing container stdout; an external collector filters security events and forwards them to the SIEM |
| Network coupling | No direct Aperture-to-SIEM client or delivery dependency |
| Identifiers | Dedicated-key HMAC references for credentials and payment correlation; never credential or payment-hash originals |
| Source information | Source IP, configured service name, and HTTP method |
| Excluded request data | Raw URL/path, query string, and Referer; use a configured fixed endpoint identifier if needed |
| Excluded secrets | Authorization header, serialized macaroon, preimage, signing secret, and HMAC key |
| Missing/invalid HMAC key | If security events are enabled, fail startup with a safe configuration error; never fall back to raw identifiers |
| Runtime output failure | Continue authentication; bound buffering and output waiting; expose delay, errors, and dropped-event counts |
| Retention and access | Owned by the organization and SIEM/collector, not Aperture |

INFO denial events are not attack verdicts. Initial unauthenticated requests normally obtain a payment challenge. Valid credential reuse is allowed by L402 policy and must not automatically be labeled a replay attack. SIEM correlation decides whether a pattern is suspicious.

Settlement-check time is when Aperture checked or observed a result, not necessarily when the payment occurred. Authentication acceptance is not proof that the backend request succeeded.

## Explicitly out of scope

- Changing, removing, or sanitizing existing DEBUG log statements. The user explicitly deferred this work.
- Claiming that all Aperture logs are safe: existing DEBUG paths can still expose credential material. The new events' exclusion guarantees apply only to the new event stream.
- Metrics #286 changes, dashboards, SIEM-specific integrations or detection rules.
- Retention, archival, deletion, and SIEM access-control policy.
- New authentication rules, replay prevention, pricing, payment behavior, or MPP/session redesign.

Collectors must distinguish the new security events from ordinary logs. Filtering the new events does not sanitize other log streams or prevent those streams from being collected elsewhere.

## Implementation starting points

| Source | What to inspect |
|---|---|
| `config.go`, `sample-conf.yaml`, `aperture.go`, `log.go` | Configuration validation, logger wiring, lifecycle and shutdown |
| `proxy/proxy.go` | Request boundary, source IP, configured service, method, challenge response, authentication dispatch |
| `auth/authenticator.go` | Final L402 decision, challenge creation, invoice-check result |
| `mint/mint.go` | Typed failure causes, token verification, minting failures |
| `l402/header.go` | Header parsing and token extraction; existing DEBUG output remains out of scope |
| `challenger/lnd.go` | Actual invoice-check semantics, including strict-verification bypass |

Observed constraints to preserve:

- `L402Authenticator.Accept` currently receives a header and service name and returns a boolean. It does not carry request metadata or a structured outcome. Design propagation deliberately instead of correlating independent messages by time.
- `VerifyL402` owns detailed token failures; `Accept` owns final acceptance and invoice checks. Do not emit duplicate final authentication events from both layers.
- Proxy authentication dispatch may try multiple schemes. Internal attempts must not become duplicate request-level L402 decisions or misleading failures for a request accepted through another scheme. Define and test mixed-scheme handling before extending beyond the L402 path.
- `LndChallenger.VerifyInvoiceStatus` returns without checking when strict verification is disabled. Record `skipped`/`not_checked` rather than claiming settlement was verified.
- Existing metric label `invoice_unsettled` groups invoice-check errors. Do not copy that coarse classification into logs as proof that an invoice was unpaid; distinguish an observed state mismatch from inability to check.
- The proxy derives its current remote IP from `RemoteAddr`. Do not start trusting arbitrary `X-Forwarded-For` values. If trusted-proxy support is needed, define the trust boundary explicitly.
- Request-derived resource names can contain path data. Log the configured service name, not an unreviewed resource string that reintroduces the excluded URL path.

## Proposed event contract — finalize during implementation

The following names are a draft, not an existing API. Keep the schema versioned and events independently parseable as single-line JSON, without a text logger prefix.

```json
{
  "schema_version": 1,
  "timestamp": "2026-09-23T12:00:00Z",
  "level": "INFO",
  "category": "security",
  "event": "l402.authorization",
  "request_id": "server-generated-id",
  "service": "indicator-api",
  "method": "GET",
  "source_ip": "192.0.2.10",
  "outcome": "denied",
  "reason": "invalid_signature",
  "credential_ref": "hmac:...",
  "credential_verified": false,
  "key_id": "operator-key-version"
}
```

Use separate event kinds for challenge issuance, final authentication, and settlement checking. They can share a request ID; issuance and later requests can share a payment reference. One final authentication event does not mean one total lifecycle event per request.

Payment references must use the payment hash bound to the issued token where available, not the hash of an arbitrary submitted preimage. Before token validation, mark claimed references as unverified. Omit unavailable references for malformed input; do not hash or log the entire raw header as a fallback.

Do not attach raw error strings to JSON events: they can contain preimages or headers. Use stable, allowlisted reason codes and bounded fields. Preserve detailed internal errors only through existing behavior; do not expand their exposure into the new stream.

### Engineering choices still to resolve

These are not user-approved details; inspect existing conventions and propose the smallest implementation:

Before implementation, explicitly resolve three design gates: event semantics when another authentication scheme succeeds, permanent stdout blockage and bounded shutdown, and credential identity/key-rotation behavior. Do not silently choose these policies or describe the handoff as a finalized event schema.

- Exact schema, typed outcome propagation, and request-ID ownership. Do not trust arbitrary client-supplied IDs as authoritative correlation keys.
- Credential HMAC input: a validated stable token identifier versus a serialized-token fingerprint affects correlation across attenuated tokens. Document the choice and distinguish unverified claims from validated identity.
- Key delivery, accepted key format/length, rotation, and optional `key_id`. Prefer an operator-provided mounted secret; do not create or alter deployed secrets. Use domain separation for credential and payment references. Correlation across replicas requires consistent keys; rotation changes references.
- Bounded queue size, maximum event size, writer isolation, flush deadline, and loss accounting. A goroutine that blocks forever or grows without bound does not satisfy the agreed availability requirement.
- For permanent stdout blockage, specify how the writer is interrupted or isolated at shutdown and where loss signals can still be observed. Queue bounds alone are insufficient.
- Health reporting for dropped events and output failures must not rely only on the failing output. Any small exporter-health metrics belong to this feature, not changes to #286's L402 counters.

## MVP and completion criteria

When implementation is authorized, build a small opt-in emitter and one end-to-end L402 authentication path first, then add challenge and settlement correlation. Keep default-OFF behavior and existing authorization results unchanged.

Required scenarios:

| Scenario | Required observation |
|---|---|
| Normal issuance, payment, and authentication | Issuance and subsequent requests correlate; checked settlement is distinguished from skipped checks; authentication is accepted |
| Tampered signature | One final denial event with a signature-failure reason; no secret material |
| Wrong preimage | One final denial event with a payment-proof mismatch reason; submitted preimage absent |
| Expired token | One final denial event identifying a restriction failure; no change to rejection behavior |
| Secret-store failure | Internal error classified separately from invalid credentials; rejection behavior preserved |

Also verify:

- Valid credential reuse remains accepted and produces one final event per request.
- Missing headers and malformed input are handled without leaking input or treating normal challenge acquisition as a confirmed attack.
- Enabled events appear even when the ordinary logger would suppress INFO; disabled mode adds no security events and requires no HMAC key.
- Enabled mode rejects missing/invalid keys at startup without printing the key.
- HMAC references are deterministic for the chosen input and key; credential/payment domains are distinct. Test rotation semantics and unverified references.
- Inject token, preimage, key, URL, and Referer canaries; assert they never appear in the new event output. Existing DEBUG logs are outside this assertion, not silently fixed or declared safe.
- Parse emitted lines as JSON under concurrency; assert no interleaving, duplicate final decisions, or uncontrolled input growth.
- Under blocked/failed output, authentication results remain unchanged, request latency and buffering remain bounded, and dropped-event health signals are observable. Document any loss; this is not a lossless audit guarantee.
- Use maintained Linux Docker tooling, pinned by digest where available. Run targeted tests, race/concurrency tests, and short repository-required sip/shower reviews. Report actual results rather than marking the design as implemented.

## Prior evidence: do not overstate

A synthetic isolated test on fork commit `78cacdd` reproduced full credential output at DEBUG and successful authentication using the header recovered from that log. It used real parsing/verification with mock storage and a settled-invoice stub, not real payments or a full production proxy.

For deployed v0.5.0, source inspection found the header DEBUG statement, but exact-version dynamic reproduction was blocked by missing offline dependencies. The available live log sample had 22 lines and no DEBUG/credential-output lines. This does not prove historical absence or a production compromise.

No security-event implementation or deployment was performed during this discussion. The earlier metrics test counts are not validation evidence for this new feature.
