# Action binding

| | |
|---|---|
| Extension | Action binding |
| Version | 0.2.0 |
| Status | Proposal. Not part of the Standard. |
| Written against | Core v1.3, reading edition rev. 11 (tag `v1.3-rev11`), with reference files 5.2.0 (tag `ref-5.2.0`) |
| Licences | This text: CC BY 4.0 ([LICENSE](../../LICENSE)). The schemas (`schemas/`) and the tests (`tests/`): Apache-2.0 ([LICENSES/Apache-2.0.txt](../../LICENSES/Apache-2.0.txt)) |

This extension is for a decision that authorises an external action, such as a payment or a message to a third party. It says how to keep evidence that the action carried out is the action that was approved, and how a check of that evidence reports what it found. It adds two objects beside the decision record: an execution-evidence attachment and a verification report. It does not add a field to a decision record, and it does not change one.

Version 0.2.0 changes 0.1.0 after review, and some 0.1.0 documents are no longer valid: a change must say how it was given (`method`), a report must give each attachment's digest, its reviews and its executed specifications, and the check now stops one approval from paying for more requests than it states.

## Scope, and what this extension does not claim

- The extension is optional. Its MUST, SHALL and SHOULD sentences bind only an implementation that says it uses action binding 0.2.0.
- It does not change what a core field means or when it is required. Where this text and the Standard's text disagree, the Standard's text governs.
- It says nothing about what any law requires. It sets no rule on how many people review an action, and no expected rate of rejections.
- The records and the attachment remain input, not evidence. A matching digest shows that two stages name the same bytes. It does not show that the reviewer read them, that the action was right, or that the named person acted.
- Using this extension makes no one certified or compliant. The outcome value `approved` records only the reviewer's own act, not approval by any regulator or other authority.

## Core fields it reads

| Core field | In the Standard | What the extension reads it for |
|---|---|---|
| `decision_id` | §6.2.1 | The record the attachment sits beside |
| `drafting_authority` | §6.2 | Who proposed the action, when an AI worker drafted it |
| `review_log` | §5.1(2), §6.2 | The reviewer, the time and the outcome the record states |
| `affirmation_record` | §5.1(3), §5.2, §6.2 | The actor, time and method of an approval given by affirmation. They are the issuer's statements |

The attachment refers to the record by `decision_id`. It is never inserted into the record. An action is usually carried out after the record is sealed, so the record's seal does not cover the attachment. There is one attachment per decision record. It is not sealed or chained: the digest that a verification report gives for it fixes which bytes were checked.

## The attachment

An attachment made under this extension:

1. MUST identify the profile and its version (`dps-action-binding`, `0.2.0`) and the record it sits beside.
2. MUST carry each action specification that is proposed, shown, approved, requested or attempted, with the SHA-256 digest of its exact bytes. The specification holds what is material: the operation, the target, the parameters, the input-version references and the applicable policy version. The deployer decides what else is material. Anything left out of the specification is not bound by the approval.
3. MUST record these as separate stages, each with its own id and the issuer's time: the proposal (by an AI worker or a person), the review (with the digest of the specification shown), the outcome (`approved`, `rejected` or `escalated`), the authorised request, each recheck of the authorisation, each execution attempt, and each observed result. A review MAY name the proposal it answers (`proposal_ref`). A review shown something other than its proposal names who edited it (`edited_by`): that person is the author of the change, and the report shows them.
4. MUST bind an approval to the digest shown in the review it answers. A review has one outcome, given by the person who was shown the specification. An outcome MAY name the core field that records the same act (`core_ref`): the `affirmation_record` or a `review_log` entry. A core field backs at most one outcome. A rejection or an escalation carries no approved digest, and MUST NOT be represented as an approval.
5. MUST record the authority that an approval asserts. An approval covers one request unless it states a `request_limit`, and a change of it counts as one of those requests. However many approvals and changes bind one specification, the requests for it number at most the largest `request_limit` any of them states.
6. MUST NOT let an approval carry over to a changed specification. Any change gives a new digest. The new digest needs a renewed review and approval, or a separately authorised change that names the earlier approval and a different specification. A change is authorised by a named person, who states their own authority and how they gave it: never by the proposer, by a service named in the attachment, or by default. A change cannot reach a specification that a reviewer in the attachment rejected or escalated: overriding that needs a new review. No reviewer is shown a specification reached only through a change, and the report says so. Where a change alters what the affirmed record decided, the Standard's rule applies: a correction is a new record that supersedes it (§5.1(3)).

## The executor

An executor that uses this extension:

- MUST execute only a specification whose digest an approval or an authorised change binds, through a request that names that approval or change.
- MUST recheck the authorisation before each attempt, and record the recheck. If the latest recheck does not authorise the action, for example because a permission was revoked after the approval, it MUST NOT attempt it. A retry is a new attempt, with its own recheck.
- MUST give each request a `request_id` that is unique within the attachment, and MUST NOT run a second request with the same `request_id` as a new action. Where the target accepts an idempotency key, the executor sends the `request_id` as that key.
- MUST record an observed result for each attempt: `succeeded`, `failed` or `indeterminate`, with the basis of the observation. An attempt is not a completed action, and a result is never inferred from the attempt. When the outcome cannot be established, as after a timeout, the result is `indeterminate`.

## The verifier and its report

A verifier that uses this extension:

- MUST check each specification's bytes against its digest, and report unavailable bytes as unavailable. It MUST check the statements the attachment makes outside the digest against those bytes where it can read them: the operation, the target, the policy version and the input-version references in the `summary`. Where it cannot read them, it reports them as not checked. A matching digest alone does not show that a specification is the action its summary names.
- MUST check the stages' statements about core fields against the decision record, where it holds the record: the `decision_id`, an AI proposer against `drafting_authority`, and an outcome against the `affirmation_record` or the `review_log` entry it names. It reports them as verified only when every approval names a core field and every statement matches. An approval that names no core field is reported as not checked, because the record does not show it. So is a `review_log` outcome word the check does not know, a core time with no offset, and a `review_log` index not written as an integer. A matching `decision_id` shows consistency only, since a verifier usually finds the record by that same id. Without the record, it reports these statements as not checked.
- MUST check that the shown, approved, requested and attempted digests agree, or are joined by an authorised change; that each review has one outcome, and each core field backs at most one; that a change names a different specification, uses up one request of what it changes, is not authorised by the proposer or by a service named in the attachment, and does not reach a specification a reviewer rejected or escalated; that a review shown something other than its proposal names who edited it; that each stage comes after the stages it names; that no request rests on a rejection or an escalation; that no `request_id` is used twice, no approval or change covers more requests than it states, and no specification is requested more often than the largest `request_limit` of the approvals and changes that bind it; that each attempt follows an authorising recheck; and that each attempt has exactly one result. Times are the issuer's, and the report says so. They are compared as instants: `09:12:00Z` and `09:12:00+00:00` are the same time.
- MUST give exactly one result for each attachment, with its index, its `decision_id` and its `attachment_digest` (the SHA-256 of the attachment's bytes as received), and state the attachment count. No two results name the same `decision_id`; this can be checked only among the attachments one report covers. The `attachment_digest` fixes the bytes for a reader who holds the report as the verifier issued it. Within each result it gives one result for each specification. It says, for each review, whether the reviewer was shown what was proposed and, if not, who edited it; and, for each executed specification, whether a reviewer was shown it or it was reached only through a change. It carries through the observed result of each attempt and its basis, and reports a missing result as missing. JSON Schema cannot compare two documents, so a reader holding both checks this; the test runner does.
- MUST report each check as a separate dimension, and MUST NOT merge them into one pass, fail or compliance result. It keeps `not_checked`, `unavailable` and `not_supported` explicit, and states the scope of its conclusion. That scope never includes what the reviewer actually saw: the report shows only which digest the attachment says was shown.

## Separate assertions

Four statements are reported separately. None stands for another.

- **Human identity.** A stage's `actor_ref` is the issuer's statement of who acted. The report records identity as verified only against an independent source it names.
- **Organisational authority.** The authority an approval asserts. The report records it as verified only against an independent source, such as the permission system the executor rechecked. The recheck stage is itself the issuer's record, so the verifier asks the permission system itself.
- **Issuer signature.** A signature over the attachment attests that the issuer recorded these claims. It does not show that the named person reviewed anything, or that the claims are true. The signed bytes SHOULD include the profile, its version and the key reference. When a later version chooses a signature suite, this SHOULD becomes a MUST, as for portable verification. In 0.2.0, the fixed point is the `attachment_digest` in the report.
- **Legal signature.** An outcome may reference one (`legal_signature_ref`). Whether a signature has legal effect is outside this extension.

## Rationale provenance

Each outcome states when its rationale was recorded: `contemporaneous` (with the outcome, no later than its time), `later_supplemented`, or `not_recorded`. A recorded rationale also states whether it was drafted with AI assistance (`ai_assisted`). A later explanation MUST NOT be presented as contemporaneous. A verifier MUST compare the stated timing with the issuer's times. It cannot tell who wrote the text.

## Decisions and telemetry

The Core is not a real-time telemetry format, and it lets records reference traces kept elsewhere (§5.3). This extension keeps that line. The attachment records the stages of one reviewed action. Detailed machine traces MAY stay in another system, referenced by `trace_refs`. They MUST NOT be copied into the attachment, which is not a stream of machine events.

## Relation to portable verification

This extension reuses two definitions from [portable verification 0.1.0](../portable-verification/), by reference, and applies them to action specifications instead of records: exact bytes (item 3 of its export rules: the bytes that were hashed, unchanged) and the representation rule (item 5: the original bytes, or a canonical form named with a specification that fixes every byte). Both use SHA-256 in lowercase hex. Nothing else is reused. Using action binding does not require using portable verification. A record exported under portable verification and its attachment are checked side by side, each under its own extension.

## Files and tests

| Path | What it is |
|---|---|
| `schemas/execution-evidence.schema.json` | The attachment (JSON Schema Draft 2020-12) |
| `schemas/verification-report.schema.json` | The verification report |
| `tests/cases.json` | The test cases, with their expected outcomes |
| `tests/run_checks.py` | Runs the cases, with the standard library and `jsonschema` only |

To run them from the repository root: `python extensions/action-binding/tests/run_checks.py`. The exit code is 0 when every case behaves as expected and 1 otherwise.

- **Schema cases** change one thing in a valid attachment or report. Among the negative ones: an approval with no asserted authority, a rejection carrying an approved digest, an outcome given by default, an attempt with no recheck or reported as completed, a result inferred from the attempt, a rationale that does not state its timing, machine traces copied in, a key carried in the attachment, a change that does not say how it was given, a result with no attachment digest, an earlier profile version, a merged verdict, and identity reported as verified on the issuer's word or because the attachment is signed. Five cases check that the fixture records are valid core records.
- **Digest cases** use SHA-256 over exact bytes: a changed amount or destination is detected, and JSON that is equal but re-serialised does not match. The affirmed fixture records are sealed as the repository's governance records are: the SHA-256 of the record with the `seal_hash` value replaced by 64 zeros.
- **Binding cases** run the reference check. They detect a shown, approved, requested or executed specification that differs from the one before it; a changed parameter, target or destination with no renewed approval; execution before approval, or after a rejection or an escalation; a rejection the record states, presented as an approval; a missing or refusing recheck; a permission revoked before the attempt; a missing result; a duplicate request; a rationale written later but presented as contemporaneous; relabelled specifications; two outcomes on one review; two approvals backed by one core field; a change authorised by the AI worker's own role or by a service; a change reaching a specification a reviewer rejected; an edited proposal with no editor named; a review naming a proposal dated after it; and one approval paying twice in each shape found in review: a change that does not use up the approval it changes, a change naming the specification it changes, and two core fields or two reviewers of one record each backing an approval of the same specification. They report as not checked, never as verified, an approval that no core field backs, a `review_log` word the check does not know, a core time with no offset and a `review_log` index written `0.0`. They accept a rejection without execution, an indeterminate result reported as such, a renewed approval, an authorised change (reported as reached only through a change), a review by two people with one request, and the same instant written with different offsets. Two cases pass by design and the runner states their limits: a signed attachment naming an unverified person, and a change authorised by a service the attachment does not name.
- **Pairing cases** read the report with its attachments. They detect a missing, duplicated or relabelled result, a wrong count, two attachments for the same decision record, an attachment changed after the report was made, a specification without a result, an observed result, its basis or the execution state not carried through as recorded, a specification reached only through a change reported as shown to a reviewer, the editor of a proposal not carried through, and a dimension reported as verified that the reference check does not verify.

The cases include no signature. A signature suite and signature vectors across languages are future work.

## Credit

Author: Laurent Lemonnier, iSoluce (CR-004). Prepared with AI assistance and reviewed by Laurent. The shape of this extension was agreed in issue #21.
