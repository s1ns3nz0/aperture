# L402 security events

Aperture can emit versioned, single-line JSON security and operational events for an external stdout collector. The feature is off by default and has no SIEM client or network delivery dependency. Authentication rules, pricing and credential reuse are unchanged.

## Enablement

Use Linux with stdout connected to a pipe, as in a container without a TTY. Regular-file redirection, TTYs, sockets and other operating systems are rejected when the feature is enabled. `/proc/self/fd` must be accessible. The daemon opens an independent nonblocking file description; it does not change stdout's existing file flags.

Mount an operator-provided secret file containing exactly 64 hex characters (32 random bytes), optionally followed by a newline. Use a dedicated key, never an L402 signing secret or an MPP HMAC key. Aperture does not generate, deploy or rotate secrets.

```yaml
securitylog:
  enabled: true
  keyfile: /run/secrets/aperture-security-hmac
  keyid: security-2026-09
```

Equivalent flags are `--securitylog.enabled`, `--securitylog.keyfile` and `--securitylog.keyid`. `keyid` is optional, non-secret and limited to 64 ASCII letters, digits, dots, underscores or hyphens. Missing/unreadable/invalid keys fail startup with a fixed error that does not include key contents. Disabled mode does not read a key file or create an event writer. Keys are loaded at startup; restart after rotation. Replicas need the same key to correlate references. Key rotation changes both reference domains; changing only `keyid` does not.

Enable the existing `prometheus.enabled` exporter and configure its existing `listenaddr` to expose output-health metrics independently of stdout. Apply the normal network access controls to that endpoint. No additional listener is created by security logging.

Share the dedicated logging key among instances in the same authentication environment; use different keys for development and production. Although optional in configuration, always set a non-secret `keyid` for SIEM use and change it when rotating the key. If omitted, `key_id` is absent from events and cannot distinguish key generations. Correlation is supported within a key generation, not across rotations; no old/new reference bridge is maintained. During a rolling restart, old and new instances can emit different references for the same token. Scope SIEM correlation by environment, `key_id`, and either `credential_ref` for tokens or `payment_ref` for payments; rotation changes both references. Analysts and collectors do not need the key or token originals. Previously collected `sha256:` references cannot be joined directly to `hmac:` references.

## Event contract (schema_version 1)

Every event contains `schema_version`, a UTC `timestamp`, `category`, `event`, `level`, a server-generated random `request_id`, configured `service`, `method`, `outcome`, `reason`, and `credential_verified`. A valid source IP is derived only from `RemoteAddr`, never forwarding headers. `key_id`, `source_ip`, `credential_ref`, `payment_ref`, and `l402_reason` are omitted when unavailable.

`schema_version` is the integer `1`; `credential_verified` is a JSON boolean and is false when credentials are absent. All other fields are strings. `timestamp` uses RFC 3339 with a UTC `Z` suffix and optional fractional seconds. Security records have `category=security`, `level=INFO`; operational failures have `category=operational`, `level=ERROR`. INFO is a record classification, not a claim that an action is safe. Treat `request_id` as an opaque server-generated string, not a client header or a value with embedded timing semantics. Security authorization outcomes are `accepted`, `denied`, `indeterminate`, or `not_applicable`; settlement outcomes are `settled`, `skipped`, `mismatch`, `error`, or `unknown`; challenge outcomes are `issued` or `error`.

| Event | Meaning |
|---|---|
| `l402.authorization` | One final L402 decision for each request that actually reaches L402 authentication. `accepted`, `denied`, or `indeterminate` describes authentication only, not the backend response or freebie/rate-limit decisions. `indeterminate` means an internal failure prevented a decision; the existing refusal to authenticate remains unchanged. |
| `l402.settlement` | An invoice check was attempted after token validation. `settled` means the checker observed the desired state; `skipped` means strict verification was disabled. `mismatch` is an observed state mismatch; `error` is inability to check/find an invoice. A checker without observation support reports `unknown`. |
| `l402.challenge` | `issued` means a minted L402 challenge was selected for the HTTP/gRPC payment-required response. It is not a client-delivery acknowledgement. Mint failure or failure before issuing the response produces `error`. |

All security records, including denials and unsuccessful payment/challenge operations, use INFO. Internal processing/storage/invoice lookup/challenge failures additionally produce an operational ERROR record. An observed invoice mismatch is INFO; an unknown/missing invoice is not evidence of nonpayment. Settlement timestamps describe the check, not the original payment time. There is no success sampling.

Stable reasons include `missing_credentials`, `malformed_credentials`, `malformed_identifier`, `payment_proof_mismatch`, `unknown_credential`, `secret_store_error`, `invalid_signature`, `restriction_failure`, `processing_error`, `accepted`, `accepted_other_scheme`, `settled`, `verification_disabled`, `invoice_state_mismatch`, `invoice_not_found`, `invoice_check_error`, `checker_stopped`, `check_status_unknown`, `challenge_issued`, `challenge_creation_failed`, and `challenge_delivery_failed`. Raw error strings are never attached to events.

### Operational failures and collection

For each internally failed L402 phase, an additional record uses the same `event` name (`l402.authorization`, `l402.settlement`, or `l402.challenge`), `request_id`, and timestamp, with `category=operational`, `level=ERROR`, `outcome=error`, and an allowlisted failure `reason`. Operational records carry service/method/source context but omit credential/payment references, `key_id`, and `l402_reason`; `credential_verified` is false because this record does not attest credentials.

A failed invoice lookup can affect both settlement and authorization and therefore produce two operational records with the same request ID and reason, one per phase. Group those by environment, `request_id`, and `reason` rather than treating them as independent outages. Timestamp equality applies only to each security/operational pair, not across phases. The security authorization result is `indeterminate`; security settlement/challenge failures retain `outcome=error`, which is an operation result, not an ERROR log level. Invalid signatures, unknown/revoked credentials, restrictions, and observed invoice-state mismatches remain known denials and do not generate operational records.

Internal failure codes are `secret_store_error`, `processing_error`, `invoice_check_error`, `invoice_not_found`, `checker_stopped`, `challenge_creation_failed`, and `challenge_delivery_failed`. An unavailable invoice is not treated as proof of an invalid token. In mixed-scheme authentication, the operational record uses the original failure code retained in the security record's `l402_reason`.

Category separation is logical routing, not separate transport: both categories share the bounded queue, and each record can be dropped independently. A security record does not guarantee delivery of its operational counterpart. Existing `aperture_securitylog_*` transport metrics count both structured categories; console drops remain separate. Output failures are monitored through those metrics, never by recursively logging another operational event to failed stdout. No new liveness/readiness checks or application-wide structured logging are introduced.

The schema remains version 1 with an additional category and authorization outcome. Update collectors that assume every structured record is a security event or that all failures are `denied`. Security `reason` fields retain diagnostic codes but must not be interpreted as attack verdicts.

### Mixed schemes

Authentication dispatch order and short-circuiting are unchanged. If L402 is attempted and denied but another scheme succeeds, the single L402 final event has `outcome=not_applicable`, `reason=accepted_other_scheme`, with the original allowlisted reason in `l402_reason`. An internal L402 error additionally produces an operational ERROR record with the original failure reason. The security record remains INFO and `not_applicable`, not `indeterminate`, when the alternate scheme succeeds. If another scheme succeeds before L402 is attempted, or the service selects MPP only, there is no L402 final decision. Challenge events follow actual L402 minting, including challenges in a mixed response.

### Correlation and exclusions

The credential reference is HMAC-SHA256 of the 32-byte token ID; attenuated versions of the same token share it. The payment reference is HMAC-SHA256 of the payment hash embedded in the token identifier, never a hash derived from an arbitrary submitted preimage. Inputs use separate `aperture/security/v1/credential\0` and `aperture/security/v1/payment\0` domains. References are lowercase hex prefixed with `hmac:`. Only exact version-0, 66-byte identifiers are correlated; malformed or unavailable identifiers produce no references.

`credential_verified=false` marks all references as unverified claims until signature validation succeeds. A correctly signed but expired/restricted token can have `credential_verified=true` while authentication is denied. Issued tokens are server-generated and marked verified. Reuse remains allowed and creates a new server request ID each time; it is not labeled a replay attack. Initial missing credentials are normal challenge acquisition, not an attack verdict.

Events exclude Authorization headers, macaroons, invoices, preimages, payment-hash originals, signing keys, HMAC keys, raw URL/path, query strings and Referer. Service names come from configuration, not request-derived resource names, and are capped at 128 bytes. Standard HTTP methods are retained; other methods become `OTHER`. The fixed schema has no arbitrary user fields or client-controlled correlation IDs.

## Output bounds and health

The event writer has one queue of 256 records and one worker. Each serialized record is at most 4096 bytes, including its newline. On Linux, [nonblocking pipe writes up to PIPE_BUF](https://man7.org/linux/man-pages/man7/pipe.7.html) either write the whole record or report that the pipe is full. The worker retries for at most 100 ms per record and has a total shutdown flush budget of 250 ms. Requests never wait for queue space or stdout. Queue overflow, write failure and flush expiry lose records; this is not a lossless audit log. Scheduling can add normal OS scheduling latency to these budgets.

When enabled, ordinary console logs use the same bounded stdout queue so their synchronous writes cannot stall request completion behind a blocked collector. Their contents and severity filtering remain unchanged. Console records over 4096 bytes are dropped, not truncated or split. Console loss is counted separately. File logging keeps its existing behavior; disk or backend I/O is outside this stdout bound. The daemon's event writer closes its own descriptor after flushing and leaves the original stdout open.

| Metric | Meaning |
|---|---|
| `aperture_securitylog_emitted_total` | Structured security and operational records written to stdout, not acknowledged by a collector |
| `aperture_securitylog_dropped_total` | Lost/rejected structured security and operational records |
| `aperture_securitylog_console_dropped_total` | Lost ordinary console records |
| `aperture_securitylog_output_errors_total` | Failed/timed-out writes, including console writes |
| `aperture_securitylog_queue_depth` | Pending records in the shared bounded queue |
| `aperture_securitylog_delay_seconds` | Histogram of queue and write delay through delivery or loss |

Scrape these metrics from the existing exporter while stdout is blocked. Process termination can lose queue contents and in-memory counters before a final scrape. Configure alerting and retention in the collector/SIEM; Aperture does not manage them.

Stdout can also contain ordinary, non-JSON console lines. Collectors must tolerate and discard those lines, then route JSON records by the supported schema version and `category`: `security` to SIEM and `operational` to operational monitoring. Collect all security records regardless of INFO level; SIEM correlation rules assign alert severity. Existing DEBUG statements are unchanged and can still disclose credentials in ordinary logs. This feature neither sanitizes nor authenticates those other streams; a stdout filter is not a guarantee about other collected logs. Do not present all Aperture logs as safe.

## Verification

The feature tests use real macaroon minting/parsing/signature and caveat checks with synthetic secrets, invoice states and backend HTTP responses. They do not demonstrate real Lightning payment settlement or production deployment.

Run the affected packages on Linux, including the actual full/closed-pipe tests and race checks:

```sh
go test -p 1 ./securitylog ./auth ./mint ./challenger ./proxy .
go test -p 1 -race ./securitylog ./auth ./mint ./challenger ./proxy .
npm run harness:verify
```

Use `-p 1` because the existing root hashmail tests and proxy backend tests both bind `localhost:8082`. Parallel package execution can produce unrelated 404/gRPC failures. Race instrumentation and concurrency inside each package remain enabled.

Validated on 2026-09-24 in Linux/arm64 using `golang@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c` (Go 1.26.0, Bookworm): all six affected packages passed, including `go test -mod=readonly -tags=dev -p 1 -race -count=1 -timeout=5m ./securitylog ./auth ./mint ./challenger ./proxy .`. A production build of `./cmd/aperture` also passed in that container. `go vet` for the same packages and the two harness tests passed locally. Category-separation tests cover known denials, indeterminate authorization, alternate-scheme success, operational correlation, challenge failures, and bounded output under failure. Independent `shower` review clarified incident grouping and per-pair timestamps; the `sip` consistency audit matched the category and outcome contract to the implementation.

The implementation branch is based on `8ffa560`, with the repository-local harness carried separately; it does not include the #286 metrics commits. The original design record is [HANDOFF-L402-SECURITY-EVENTS.md](HANDOFF-L402-SECURITY-EVENTS.md); its internal-error severity classification is superseded by the category separation described here.
