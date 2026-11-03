# ListGuard remediation plan

All steps below are **planned, not executed**. Preserve content-only moderation, closed-set actions and append-only human decisions. The linked [review](REVIEW.md) identifies confirmed findings and unverified deployment risks. Proposed files below do not already exist unless identified as observed.

## Phase map and gates

| Phase | Entry | Required exit |
|---|---|---|
| 0: reproducible baseline | Pinned source available | LG-T1 installs, packages and runs real checks in isolation |
| 1: correctness and trust | Baseline recorded | LG-T2–T4 preserve policy invariants, trusted identity and key separation |
| 2: operations and review desk | Trust decisions settled | LG-T5–T6 demonstrate recovery and usable review flows |
| 3: release acceptance | Earlier evidence complete | LG-T7 independently reproduces checks and owner accepts residual risks |

### LG-T1 — Recover installation, real CI and distributable resources

**Links:** LG-01, LG-05; packaging risk. **Prerequisites:** approved Python baseline and disposable checkout. **Observed paths:** `requirements.txt`, `pyproject.toml`, `listguard/main.py`; **proposed:** `.github/workflows/ci.yml` and installed-artifact tests.

1. Separate the pasted workflow from requirements; validate both formats and reconcile dependency pins without opportunistic upgrades or weakening strict pytest settings.
2. Install via the documented requirements path and editable path in independent clean environments. Build a wheel and install it outside the checkout; verify dashboard template, taxonomy and demo-resource availability rather than importing resources from the source tree accidentally.
3. Establish active CI for installation, dependency consistency and tests. Add a canonical demo smoke check requiring all four fixtures and expected bucket/actions; test missing and malformed fixtures as negative cases.

**Deliverable:** reproducible install/build log and real workflow. **Verification:** planned `python -m pip check` and `python -m pytest`, with tool versions recorded; independently verify a broken requirement, missing fixture and wrong policy result fail the appropriate gate.

- [ ] Requirements contains dependencies only; workflow exists at its real path.
- [ ] A clean wheel installation can locate every required runtime asset.
- [ ] CI fails on a deliberately broken test, not merely on setup errors.
- [ ] Canonical demo cannot silently omit fixtures or incorrect outcomes.

### LG-T2 — Preserve strongest-policy precedence

**Links:** LG-04, LG-07. **Prerequisite:** T1 baseline; owner-approved precedence table. **Paths:** `listguard/policy.py`, `tests/test_policy.py`, `tests/test_phase2_deterministic.py`.

1. Write a table of combined signals covering weapon plus counterfeit, injection plus counterfeit, verifier exception and clean content. Include default and custom verifiers.
2. Add failing regression cases where a custom verifier labels a weapon listing counterfeit and where `rifle` is the sole weapon cue in a title or independent metadata field. Correct the singular regex alternative; cover word position, case, punctuation and plural forms without matching unrelated substrings. Combine independently detected reasons before resolving priority; keep weapon/block and the prohibition on injection/allow invariant.
3. Test valid and malformed dependency output, then exercise the actual moderation API and persisted receipt so the fix is not isolated to a helper.

**Deliverable:** precedence implementation and adversarial regression matrix. **Verification:** remove the new precedence protection temporarily in the test workspace and observe the regression test fail; retain original receipt reason codes for inspection.

- [ ] Custom verifier output cannot downgrade a detected weapon.
- [ ] Combined reasons are retained and no seller sanction is introduced.
- [ ] Persisted API results satisfy the same matrix as direct evaluation.
- [ ] Standalone singular weapon terms are blocked in every supported text field.

### LG-T3 — Establish authenticated, authorized review identity

**Link:** LG-02. **Prerequisites:** identity provider, roles and any tenant model selected. **Paths:** `listguard/api.py`, `web/templates/index.html`; **proposed:** gateway configuration and API authorization tests.

1. Map moderation, receipt reads and override operations to authorized principals. Decide whether enforcement resides in the application or a mandatory gateway; prevent bypass by direct backend access.
2. Derive `operator_id` from trusted authentication claims. Reject mismatches, enforce object/tenant permissions, and address CSRF if browser sessions use cookies; remove editable identity as a source of authority.
3. Test anonymous, expired, insufficient-role, wrong-tenant and forged-operator requests through the intended deployed boundary. Confirm rejected requests append no human receipt.

**Deliverable:** deployable identity boundary and negative API tests. **Verification:** compare stored attribution with the authenticated test principal; prove removing the authorization control makes a negative test fail.

- [ ] Direct and gateway paths cannot bypass authorization.
- [ ] Caller-supplied identity cannot impersonate another reviewer.
- [ ] Receipt reads and modifications enforce resource-level access.
- [ ] Local unauthenticated demo mode cannot be mistaken for production configuration.

### LG-T4 — Separate signing keys and prove receipt integrity

**Links:** LG-03, LG-06. **Prerequisites:** T1; signing owner and recovery objectives. **Paths:** `listguard/storage.py`, `listguard/api.py`; **proposed:** key-provider adapter and integrity tests.

1. Define local/demo and production signing semantics. Require production configuration explicitly; external mode must fail without its managed key and must not persist key bytes in SQLite.
2. Implement versioned key identifiers, controlled rotation and signature verification before returning a production receipt or accepting it as the basis of an override. Apply this to the concrete store and API retrieval path; verification-mode parameters must affect enforcement, not merely be passed through compatibility helpers. Plan migration of existing metadata carefully; do not delete old verification material before retained receipts are accounted for.
3. Test copied-database inspection using a canary key, schema-valid payload tampering, a modified single-receipt chain, chain truncation, wrong/missing key, rotation and a restore with external checkpoints. Assert altered receipts cannot be read as trusted or used for an override. Distinguish HMAC possession from independent proof of historical authenticity.

**Deliverable:** separated key lifecycle and documented integrity limits. **Verification:** a database-only copy contains no production signing secret and cannot forge a newly accepted receipt; restored history verifies against a separately retained checkpoint.

- [ ] Production key bytes are absent from database, logs and exported artifacts.
- [ ] Missing/wrong managed key fails closed.
- [ ] A schema-valid but signature-invalid single receipt is rejected on read and override, even if its chain links appear valid.
- [ ] Rotation preserves verification of authorized historical receipts.
- [ ] Recovery of both receipts and signing access is independently demonstrated.

### LG-T5 — Make SQLite operations recoverable and bounded

**Links:** operational risks and constant health response. **Prerequisites:** T3/T4 trust boundaries; approved retention, RPO and RTO. **Paths:** `listguard/storage.py`, `listguard/api.py`, `listguard/main.py`; **proposed:** operations runbook and load/recovery tests.

1. Separate liveness from readiness and define readiness for unavailable storage and required signing dependencies. Set request-body and rate limits appropriate to listing size and reviewer traffic.
2. Exercise concurrent writes, repeated submissions, disk-full conditions, interrupted transactions and process restarts. Define retry/idempotency semantics so uncertain responses do not create misleading duplicate human decisions.
3. Back up SQLite consistently, including WAL considerations, then restore to a separate instance. Measure data loss and recovery time and verify key/checkpoint dependencies before promotion.

**Deliverable:** bounded service configuration, failure evidence and executable recovery procedure. **Verification:** fail storage or signing deliberately; readiness must not report a healthy usable service, while existing audit data remains consistent.

- [ ] Concurrent and retried requests have documented durable outcomes.
- [ ] Restore meets owner-approved recovery objectives.
- [ ] Alerts distinguish storage, signing and policy-evaluation failures without logging sensitive listing bodies.

### LG-T6 — Verify safe reviewer interaction and accessibility

**Link:** UI risks; T3 trusted attribution. **Paths:** `web/templates/index.html`; **proposed:** browser flow and accessibility tests.

1. Review keyboard-only and screen-reader operation, including field errors, busy states, shortcuts and focus after failed submissions. Do not claim compliance based on static markup.
2. Make the target receipt and consequence clear before an override; prevent stale-card and duplicate-submit errors and show trusted reviewer identity. Permit shortcut opt-out where needed.
3. Assert the server actually persisted the expected human receipt and preserved the original. Test expired authorization and network failure without displaying false success.

**Deliverable:** tested review flows and accessibility evidence. **Verification:** browser tests follow visible controls and independently fetch the recorded decision; introduce a persistence failure to prove the UI does not falsely succeed.

- [ ] Keyboard and assistive-technology users can complete and recover a review.
- [ ] Shortcuts cannot silently target the wrong receipt.
- [ ] Success reflects server-confirmed persistence and trusted attribution.

### LG-T7 — Independent release and rollback acceptance

**Prerequisites:** T1–T6 complete, or individual residual risks explicitly accepted. **Proposed output:** release evidence bundle and operational sign-off.

1. Have an operator other than the implementer deploy the exact packaged artifact into isolated staging using the production-shaped identity and signing boundaries.
2. Repeat adversarial policy cases, unauthorized operations, failed persistence and backup restoration. Record actual measurements and unavailable checks rather than copying earlier successful output.
3. Approve promotion only after documenting supported classification limits and a rollback plan. Assess receipt schema/key compatibility before rollback; restore backups only under an approved data-loss decision.

- [ ] Artifact, revision, environment and evidence are traceable.
- [ ] No production-readiness claim exceeds demonstrated behavior.
- [ ] Owner approves residual risk, recovery tradeoffs and human-review policy.

No production credentials, migrations, external model integration, deployment or deletion is authorized by this plan itself.
