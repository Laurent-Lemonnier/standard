# Portable verification

| | |
|---|---|
| Extension | Portable verification |
| Version | 0.1.0 |
| Status | Proposal. Not part of the Standard. |
| Written against | Core v1.2, reading edition rev. 10 (tag `v1.2-rev10`), with reference files 5.1.2 (tag `ref-5.1.2`) |
| Licences | This text: CC BY 4.0 ([LICENSE](../../LICENSE)). The schemas (`schemas/`) and the tests (`tests/`): Apache-2.0 ([LICENSES/Apache-2.0.txt](../../LICENSES/Apache-2.0.txt)) |

This extension says how to export sealed decision records so that someone else can check them, and how that check reports what it found. It adds two objects beside the records: an export and a verification report. It does not add a field to a decision record, and it does not change one.

## Scope, and what this extension does not claim

- The extension is optional. Its MUST, SHALL and SHOULD sentences bind only an implementation that says it uses portable verification 0.1.0.
- It does not change what a core field means or when it is required. Where this text and the Standard's text disagree, the Standard's text governs.
- It says nothing about what any law requires. A verification report is not a legal conclusion, and it does not grade a Conformance Level.
- The records remain input, not evidence. A seal that matches shows that the bytes have not changed since they were sealed. It does not show that the record is true, complete or lawful.
- Using this extension makes no one "certified", "compliant" or "approved".

## Core fields it reads

| Core field | In the Standard | What the extension reads it for |
|---|---|---|
| `seal_hash`, `seal_algorithm` | §5.1(3), §6.2 | The value the covered bytes are compared with |
| `affirmation_record` | §5.1(3), §6.2 | Whether the sealed bytes include it. Its timestamp and actor are the issuer's statements |
| `supersedes` | §5.1(3), §6.2 | The link to the record a correction replaces |
| `revision_history` | §6.2, §6.2.3.2 | The original seal, kept after a migration re-seals a record |
| `target_record_hash`, `target_decision_id` | §5.5, §6.2 | The seal and identifier of the record a redaction event names |
| `decision_id`, `record_type` | §6.2.1, §6.2 | Which record an export entry is |

The export and the report refer to records. They are never inserted into one.

## The export

An export made under this extension:

1. MUST identify the profile and its version (`dps-portable-verification`, `0.1.0`).
2. MUST identify, for each entry, the record (`decision_id`, `record_type`), the seal algorithm, the covered representation and any predecessor references: `supersedes`, and `target_record_hash` with `target_decision_id` for a redaction event.
3. MUST carry the covered bytes, meaning the exact bytes that were hashed into `seal_hash`, unchanged. If they are not available, it MUST say so and why.
4. MUST state how the seal field was handled when those bytes were made: either the covered bytes do not contain `seal_hash`, or they contain it with every character of its value replaced by `0`. Zeroing keeps the length of the stored value. Other placeholders, such as an empty string or null, are not covered in 0.1.0. A seal stored in another encoding of the same 32 bytes is carried as lowercase hex. The export MUST also state whether the covered bytes include `affirmation_record`. That is a statement about the bytes, not a rule about what they must include.
5. MUST use either the original bytes or a canonical form named with a reference to a specification that fixes every byte. "Sorted JSON" and similar descriptions do not fix the bytes and are not enough.
6. MUST, for a signed entry, name the signature algorithm, the issuer-key reference, and where the signed bytes are defined. The signed bytes SHOULD include the profile, its version and the issuer-key reference, so that a signature cannot be presented under another key reference or profile. When a later version chooses a signature suite, this SHOULD becomes a MUST.
7. MUST NOT carry key material as a source of trust. It carries a key reference only.

## The verifier and its report

A verifier that uses this extension SHALL validate an affirmed-and-sealed record against its original sealed bytes without inserting defaults or rewriting the payload. A later normalization or migration produces an explicitly identified derived representation and preserves the original verification context, subject to the applicable retention policy (§6.4.2).

The verifier also:

- MUST take issuer trust from a trust policy it configured independently, never solely from a key or a checkpoint carried in the same export.
- MUST check each entry's statements that sit outside the seal against the covered bytes, where it can read them: `decision_id`, `record_type`, the predecessor references, the seal field handling and `affirmation_record_covered`. Where it cannot read them, it reports them as not checked. A matching seal alone does not show that an entry is the record it names. Where the bytes omit `record_type`, the check reads it as `decision`, as §6.2 says, and does not rewrite the bytes. The report carries `affirmation_record_covered` through, so a reader sees when the affirmation is outside the seal.
- MUST give exactly one entry result for each export entry. The report states the export's entry count, and each entry result names the index of its export entry and the `decision_id` that entry states. Each index from 0 to the count minus 1 appears once. JSON Schema cannot compare two documents, so a reader holding both checks this; the test runner does.
- MUST report these separately: structural validity, cryptographic verification, object-link verification, time assurance, identity assurance, content availability, and the scope of its conclusion. It MUST NOT merge them into one pass, fail or compliance result. The report schema has no place for one.
- MUST keep what it did not or could not check explicit (`not_checked`, `not_supported`, `unavailable`).
- MUST say where the value it compared a seal with came from. A `seal_hash` carried in the same export shows only that the bytes and the seal agree. It shows that they are the affirmed bytes only if the seal value comes from a source the verifier trusts independently.

## Chains, checkpoints and time

- An export MAY chain its entries: `link(i) = SHA-256(link(i-1) || digest(i))` over the 32-byte raw values, with 32 zero bytes before the first entry. `digest(i)` is the entry's seal, or its derived digest. Each entry carries the previous link, and the chain is checked from its first link. The chain binds the seals and their order, not which record each seal belongs to; the statement check covers that.
- A valid chain shows that the supplied sequence is consistent. It does not show that every event was recorded.
- A missing tail can be detected only against a checkpoint (the count and the last link) established independently of the export. Without one, a correctly linked prefix passes. A checkpoint supplied in the same export is not independent.
- A report MUST NOT describe a sequence as consistent with a checkpoint without naming that checkpoint. Even a matching checkpoint says nothing about events the issuer never recorded.
- A timestamp the issuer asserts, including `affirmation_record.timestamp`, is not independently trusted time, and the actor it names is not independently verified identity. The report records time or identity as verified only against an independent source it names.

## Transformed and unavailable records

- A transformed or re-serialised record MUST keep a link to the original sealed representation, by its original seal, and MUST identify the transformation. It is exported as a derived entry.
- Re-hashing a derived representation does not carry over the original seal. A seal recomputed after a migration (§6.2.3.2) is exported as the derived representation's digest, and the original seal is checked and reported on its own.
- An original that is not available, for example after a redaction event or at the end of its retention period, MUST be reported as unavailable. It is reported neither as verified nor as failed.

## Files and tests

| Path | What it is |
|---|---|
| `schemas/verification-export.schema.json` | The export (JSON Schema Draft 2020-12) |
| `schemas/verification-report.schema.json` | The verification report |
| `tests/cases.json` | The test cases, with their expected outcomes |
| `tests/run_checks.py` | Runs the cases, with the standard library and `jsonschema` only |

To run them from the repository root: `python extensions/portable-verification/tests/run_checks.py`. The exit code is 0 when every case behaves as expected and 1 otherwise.

- **Schema cases** change one thing in a valid export or report. The negative ones: an unknown profile version, the seal field handling not stated, "sorted JSON" with no specification, a key carried in the export, a re-hashed record presented as the original seal, a redaction event with no target, a single merged verdict, a compliance claim, a chain called "complete", a checkpoint claim with no checkpoint, unavailable content with a verified seal, an issuer timestamp or named actor reported as verified, a report entry with no statement check, `affirmation_record_covered` not carried through, and no entry count.
- **Digest cases** use SHA-256 over exact bytes: a changed payload is detected; a changed record re-sealed in the same export matches that seal but not the original one; JSON that is equal but re-indented, or has sorted keys, does not match the sealed bytes; inserting a default `record_type` breaks the match; the zeroed seal field is handled exactly.
- **Chain cases**: a middle omission and a reordering are detected. A missing tail passes without a checkpoint, and the runner says so; it fails against an independent checkpoint.
- **Statement cases** run the reference check over the covered bytes. It detects a relabelled entry whose seal still matches, a seal field handling the bytes do not show (including an empty placeholder), a wrong `affirmation_record_covered`, a left-out predecessor and a wrong `record_type`. Unavailable or unreadable bytes give "not checked".
- **Pairing cases** read a report with its export. They detect a missing entry, a duplicated entry, an entry count lowered to hide one, a relabelled result, statements reported as verified that do not match the bytes, and `affirmation_record_covered` not carried through.
- **Trust cases** use labels, not keys: an untrusted key, a key supplied in the export, a wrong key and a substituted key reference.

The digest and chain values are written in `cases.json`, so they can serve as simple vectors in other languages. The cases include no signature. A signature suite, signature vectors across languages, and key rotation and revocation are future work.

## Credit

Author: Laurent Lemonnier, iSoluce (CR-005). Prepared with AI assistance and reviewed by Laurent. The shape of this extension was agreed in issue #21.
