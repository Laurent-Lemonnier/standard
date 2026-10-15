# Anchoring

| | |
|---|---|
| Extension | Anchoring |
| Version | 0.1.0 |
| Status | Proposal. Not part of the Standard. |
| Written against | Core v1.3, reading edition rev. 11 (tag `v1.3-rev11`), with reference files 5.2.0 (tag `ref-5.2.0`), and portable verification 0.1.0 |
| Licences | This text: CC BY 4.0 ([LICENSE](../../LICENSE)). The schemas (`schemas/`) and the tests (`tests/`): Apache-2.0 ([LICENSES/Apache-2.0.txt](../../LICENSES/Apache-2.0.txt)) |

This extension says how to anchor sealed decision records with evidence from outside the issuer, and how a check of that evidence reports what it found. It defines two assertions: an independent timestamp, which shows that exact bytes existed by a time, and an independent checkpoint, which fixes a chain of records at one point. Each is an object beside the export or the records. Neither adds a field to a decision record, and neither stands for the other.

It is the first of two related profiles agreed in issue #29. The second, signatures (the person's signature and the organisation's seal), will come later and reuse the signed-bytes rule and the key states defined here.

## Scope, and what this extension does not claim

- The extension is optional. Its MUST, SHALL and SHOULD sentences bind only an implementation that says it uses anchoring 0.1.0.
- It does not change what a core field means or when it is required. Where this text and the Standard's text disagree, the Standard's text governs.
- It says nothing about what any law requires. Whether a timestamp has legal effect is outside this extension. A qualified time-stamp service is one source a verifier may configure; configuring one does not make a report a legal conclusion.
- The records remain input, not evidence. A verified timestamp shows that bytes existed by a time, according to an authority the verifier trusts. A matching checkpoint shows that the first entries of an export are the ones the issuer had committed. Neither shows that a record is true, complete or lawful.
- Using this extension makes no one "certified", "compliant" or "approved".

## What it reads

| Field or definition | Where | What the extension reads it for |
|---|---|---|
| `seal_hash` | Core §5.1(3), §6.2 | The 32 bytes a timestamp may cover |
| `affirmation_record.timestamp` | Core §5.1(3), §6.2 | The issuer's time, compared with an independent timestamp. It stays the issuer's statement |
| `decision_id` | Core §6.2.1 | Which record a seal belongs to |
| The export, its entries and their covered bytes | Portable verification 0.1.0, "The export" | Where the seals and the issuer's times are read |
| The chain, `link(i)`, the count and the last link | Portable verification 0.1.0, "Chains, checkpoints and time" | What a timestamp over a link covers, and what a checkpoint fixes |

The attachment and the report refer to records by their seals and their links. They are never inserted into one.

## Signed bytes (shared rule)

Every signature made under this rule, in this profile and in the related signatures profile, is made over bytes built in one fixed way, never over "the JSON":

```
signed_bytes = "DPS-SIG" 0x00 || lp(f1) || lp(f2) || ... || lp(fn)
lp(x)        = the length of x as 4 bytes, big-endian, then the bytes of x
```

- `"DPS-SIG" 0x00` is the 7 ASCII bytes `44 50 53 2D 53 49 47` and one zero byte.
- A text field is the UTF-8 encoding of the JSON string's value, with no escaping and no Unicode normalisation.
- A digest (a seal, a link) is its 32 raw bytes, never its hex.
- An integer is 8 bytes, big-endian, unsigned.
- A time signed as text has exactly the form `YYYY-MM-DDTHH:MM:SSZ`: UTC, to the second.
- Every field is length-prefixed, including those of fixed length, so that one parser reads every assertion type.
- The first four fields are always `profile`, `profile_version`, the assertion type and `key_ref`, in that order. A signature therefore cannot be presented under another profile, version, assertion type or key reference: each of them changes the bytes, even for the same key under two references.
- Each assertion type has one fixed field order. A new order needs a new assertion type or a new version.
- The verifier builds the signed bytes itself, from the fields it checks and with the profile, version and assertion type it expects. It never verifies a signature over bytes supplied with it.

In this profile, one assertion type is signed under the rule:

| Assertion type | Fields, in order |
|---|---|
| `checkpoint` | 1 `profile` (`dps-anchoring`), 2 `profile_version` (`0.1.0`), 3 the assertion type (`checkpoint`), 4 `key_ref`, 5 `chain_id`, 6 `count` (integer), 7 `head_link` (digest), 8 `checkpoint_time` (time) |

A checkpoint is signed with Ed25519 (RFC 8032), over the signed bytes themselves. The signatures profile will add its own assertion types and field orders under this rule. For example, the test checkpoint `cp_a` in `tests/vectors.json` (key `witness-a-1`, chain `urn:example:chain:issuer-1`, count 3, at 2026-09-27T12:00:00Z) has these 165 signed bytes:

```
4450532d534947 00                                                      "DPS-SIG" 0x00
0000000d 6470732d616e63686f72696e67                                    profile
00000005 302e312e30                                                    profile_version
0000000a 636865636b706f696e74                                          assertion type
0000000b 7769746e6573732d612d31                                        key_ref
0000001a 75726e3a6578616d706c653a636861696e3a6973737565722d31          chain_id
00000008 0000000000000003                                              count
00000020 461cf1cad5fe45a896737bb01ae396639da7ef5c424352ab0d029565e0228552  head_link
00000014 323032362d30392d32375431323a30303a30305a                      checkpoint_time
```

## The anchoring attachment

An attachment made under this extension:

1. MUST identify the profile and its version (`dps-anchoring`, `0.1.0`).
2. MAY state the issuer's `chain_id` for the export's chain. It is a reference: the verifier takes the chain it checks from its own configuration.
3. MUST carry each independent timestamp as its own object, and MAY carry references to checkpoint sources (`checkpoint_refs`). A reference is a hint, never a source of trust.
4. MUST NOT carry a time-stamping authority's certificate or key, a witness's key, or a checkpoint. It carries references only, as portable verification does (items 6 and 7 of its export rules).
5. MUST NOT state a time beside a token. The time comes only from the token.

An attachment is not sealed or chained. The `attachment_digest` in a report fixes which bytes were checked.

## An independent timestamp

- **What it covers.** The exact bytes its subject names: the 32 raw bytes of a record's `seal_hash` (`seal`, with its `decision_id`), the 32 raw bytes of `link(sequence)` of a chain (`chain_link`, with the `chain_id` and the `sequence`), or the raw bytes of a signature value (`signature`, naming what was signed: in 0.1.0, a checkpoint). A timestamp over a signature value shows that the signature existed by that time, which is what a key's revocation needs.
- **Format.** An RFC 3161 time-stamp token: a CMS SignedData with one signer over a TSTInfo (RFC 3161 §2.4.2, with ESSCertIDv2 as RFC 5816 allows). Its `messageImprint` is the SHA-256 of the subject's bytes. It is carried in DER, in padded base64 (`token_b64`), with a reference to the authority (`tsa_ref`).
- **Source of trust.** The authorities the verifier configured, each pinned by its certificate in the trust policy. Building a chain to a trusted list, and checking a certificate's revocation status, are out of scope: a verifier that needs them does them before it pins a certificate. A qualified time-stamp service is one example of an authority a verifier may configure.
- **What it proves.** These bytes existed no later than time T, according to an authority the verifier trusts. T is the token's `genTime`, plus its `accuracy` when it states one.
- **What it does not prove.** When the decision was made; that the bytes did not exist earlier; anything about their content; that the issuer's own times are right.

A verifier checks a timestamp as follows, and reports each check:

1. `token`: a ContentInfo carrying SignedData, with encapsulated content of type id-ct-TSTInfo, exactly one signer, and a TSTInfo of version 1, with no trailing bytes.
2. `message_imprint`: made with SHA-256, and equal to the SHA-256 of the subject's bytes.
3. `subject_bytes`: the subject's bytes are what it names. For a seal, the `seal_hash` of the record with that `decision_id`, in the export (the reference check) or in a record the verifier holds. For a link, `link(sequence)` recomputed from the export's seals by portable verification's rule. For a signature, the signature value of the checkpoint it names, among those the verifier holds.
4. `message_digest`: one signed content-type attribute, id-ct-TSTInfo, and one signed messageDigest attribute equal to the SHA-256 of the TSTInfo bytes as they appear in the token.
5. `tsa_signature`: `tsa_ref` names an authority in the trust policy, the token's signer identifier names its pinned certificate, and the signature over the signed attributes (their DER encoding as a SET OF, RFC 5652 §5.4) verifies with that certificate's key. A certificate carried in the token is never used.
6. `signer_certificate`: when the token has a signingCertificateV2 attribute, its first ESSCertIDv2 hash is the SHA-256 of the pinned certificate. A token without one is identified by its signer identifier alone, and the report says so (`not_checked`).
7. `tsa_state`: `genTime` is within the policy's window for the authority, and before `revoked_at` if the authority was superseded. A token from an authority revoked as compromised never counts: it cannot show its own time.

The timestamp is verified only when every check is verified, except `signer_certificate`, which may be not checked. The report gives T only for a verified timestamp.

The verifier then compares the issuer's own time for the subject with T: for a seal, the record's `affirmation_record.timestamp`; for a link, the latest of those times among the entries it chains; for a checkpoint's signature, its `checkpoint_time`. It reads a record's time only from covered bytes whose SHA-256 is the entry's seal. An issuer's time later than T is reported as inconsistent. This comparison is reported apart from the timestamp, which it does not change: the bytes still existed by T.

The reference check in `tests/` supports tokens signed with ECDSA P-256 and SHA-256, the algorithm of the vectors, and reports any other as not supported. A verifier may support others, such as RSA.

## An independent checkpoint

- **What it fixes.** A chain at one point: its identifier (`chain_id`), the number of entries (`count`), the last link (`head_link`, which is `link(count - 1)`), and the time (`checkpoint_time`). The count and the last link are the shape portable verification already uses.
- **Independent** means that the verifier obtains it from a source its trust policy configures for that chain, outside the export. The extension requires no particular medium. In 0.1.0 a witness signs the checkpoint, with assertion type `checkpoint` under the shared rule. A transparency log, or a third party that keeps checkpoints, are other sources a verifier may configure; this version defines no format for them.
- **Never independent:** a checkpoint found in the export or the attachment, such as portable verification's `issuer_checkpoint`, even when a witness the verifier trusts signed it. The issuer chose which checkpoint to carry.
- **What it proves.** The export's first `count` entries are the ones the issuer had committed when the checkpoint was made. A dropped tail, a dropped entry, a reordering or a rewrite before that point is detected, even one that was re-sealed and re-chained. Entries after the checkpoint are reported as not covered.
- **What it does not prove.** That the issuer recorded every event; anything after the checkpoint; that the witness checked any content, since it saw digests only; that `checkpoint_time` is right, since it is the witness's own statement.

A verifier checks a checkpoint as follows, and reports each check:

1. `independence`: obtained from a source in the trust policy, configured for the checkpoint's `chain_id`, and not from the export.
2. `signature`: `key_ref` is a key in the trust policy, listed for that source, in the role `witness`; and its signature verifies over the signed bytes the verifier builds.
3. `key_state`: the key's state when it signed (next section).

The checkpoint is verified only when all three are. Only then is the export compared with it: the links recomputed from the export's seals, or derived digests, in the export's order and from 32 zero bytes, must give `head_link` at entry `count - 1`. An export with fewer than `count` entries fails. Entries from `count` on are reported as not covered. A checkpoint for another chain than the one the verifier checks is not compared.

## The trust policy and key states

- The trust policy is the verifier's own configuration, never taken from an export, an attachment or a token. It lists the time-stamping authorities, the keys, and the checkpoint sources, each with the chains it is used for and, for a witness, its keys.
- A key reference names one key. A new key gets a new reference. Changing keys never rewrites an old signature or checkpoint.
- Each key has its holder, its role, `not_before` and `not_after`, and, if it was revoked, `revoked_at` and a reason: `superseded` (replaced, not suspected of misuse) or `compromised`. The roles are `witness`, and the `organisation` and `person` roles of the related signatures profile, so that one policy holds every key. Only a witness key signs a checkpoint: the issuer's own key cannot make a checkpoint independent, whatever source lists it.
- A signature is checked against the key's state when it was made. That time is the signer's own statement (`time_basis: stated_time`) unless a verified independent timestamp covers the signature value. Then the earliest such T is used (`time_basis: independent_timestamp`). Only the stated time can show that a signature was made after `not_before`, since a timestamp shows only when it existed at the latest.
  - A signature made outside the key's validity, from `not_before` to `not_after`, fails.
  - A key that was only superseded: the stated time is enough, if it is before `revoked_at`. The report gives it as the signer's statement, not as independent time.
  - A compromised key: the signature counts as made before `revoked_at` only if an independent timestamp earlier than `revoked_at` covers it. With none, the report says that the time cannot be established (`unavailable`). A timestamp at or after `revoked_at` fails.

## The verifier and its report

A verifier that uses this extension:

- MUST take every source of trust from its own trust policy: never from an export, an attachment or a token.
- MUST report each timestamp and each checkpoint as its own dimension: `verified`, `failed`, `not_checked`, `not_supported` or `unavailable`. Each names the source it was checked against: `tsa_ref` for a timestamp, `source_ref` and `key_ref` for a checkpoint. It MUST NOT merge them, with each other or with another extension's dimensions, into one pass, fail or compliance result. The report schema has no place for one.
- MUST give exactly one result for each timestamp in the attachment and for each checkpoint it obtained or tried to obtain, each with its index, and state their counts, the digests of the attachment and of the export, and the chain it checked.
- MUST report an issuer's time later than T as inconsistent, apart from the timestamp.
- MUST NOT report a checkpoint found in the export as independent.
- MUST report the entries after a checkpoint's count as not covered.
- MUST say, for each key state, what its time rests on.
- MUST state the scope of its conclusion. That scope never includes the time of the decision, the earliest time the bytes existed, events the issuer never recorded, or whether the witness reviewed any content.

JSON Schema cannot compare two documents, so a reader holding both the report and the documents it covers checks the counts, the digests, and that each dimension reported as verified is verified; the test runner does.

## Relation to portable verification, and what comes next

This extension reuses, by reference, portable verification's export and covered bytes (items 2 to 5 of its export rules), its chain rule, and its checkpoint shape. A portable verification export is anchored without changing it: the attachment sits beside it. Portable verification says that a missing tail can be detected only against a checkpoint established independently of the export, and that an issuer's timestamp is not independently trusted time. An independent checkpoint and an independent timestamp, as defined here, are what those sentences need. Using anchoring requires using portable verification only for checkpoints and links; a record's seal can be timestamped on its own.

Not in this version, and future work:

- The signatures profile: the person's signature and the organisation's seal, under the same signed-bytes rule and key states.
- Portable verification 0.2.0 and action binding 0.3.0, in which the signature of a signed entry or attachment moves from SHOULD to MUST, referring to these profiles for the suite and the signed bytes.

## Dependencies

The reference check and the vector generator use two packages besides `jsonschema`, pinned in `tests/requirements.txt` with their own dependencies:

- `cryptography` 50.0.2, for Ed25519, ECDSA and X.509 certificates.
- `asn1crypto` 1.5.1, for the RFC 3161 tokens. It is a small, pure-Python ASN.1 library with no dependencies, widely used and tested. Its `cms` and `tsp` modules define the CMS SignedData and the TSTInfo a token is made of. It keeps the bytes it parsed, so the signed attributes and the TSTInfo are checked exactly as they appear in the token.

The scripts use these libraries for every cryptographic step and implement no primitive themselves, because reference code gets copied. The runners of the other extensions do not use these packages, and `tools/requirements.txt` is unchanged.

## Files and tests

| Path | What it is |
|---|---|
| `schemas/anchoring-attachment.schema.json` | The attachment (JSON Schema Draft 2020-12) |
| `schemas/checkpoint.schema.json` | A witness-signed checkpoint |
| `schemas/trust-policy.schema.json` | The verifier's trust policy |
| `schemas/verification-report.schema.json` | The verification report |
| `tests/cases.json` | The test cases, with their expected outcomes |
| `tests/vectors.json` | The values the cases use: keys, records, exports, tokens, checkpoints, a policy, an attachment and a report |
| `tests/generate_vectors.py` | Writes `vectors.json`; with `--check`, says whether it is what the script writes |
| `tests/run_checks.py` | Runs the cases |
| `tests/requirements.txt` | The packages the two scripts need besides `tools/requirements.txt`, pinned |

To run them from the repository root: `pip install -r tools/requirements.txt -r extensions/anchoring/tests/requirements.txt`, then `python extensions/anchoring/tests/run_checks.py`. The exit code is 0 when every case behaves as expected and 1 otherwise.

Every key in the vectors is a test key only, derived from a published text: its seed is the SHA-256 of `dps-anchoring 0.1.0 test key ` followed by the key's name. An Ed25519 key's seed is its private key (RFC 8032). A time-stamping authority's ECDSA P-256 private scalar is the seed read as a big-endian integer, modulo n - 1, plus 1. Never derive a real key this way. The signatures are deterministic, Ed25519 by definition and ECDSA with the nonces of RFC 6979, so `vectors.json` is byte-reproducible. Each checkpoint in it gives its exact signed bytes in hex (`signed_bytes_hex`), and each token the bytes its imprint covers. Generating needs OpenSSL 3.2 or later, which the pinned `cryptography` includes; checking does not. The records and links are those of portable verification's cases, so the two sets of vectors agree.

- **Schema cases** change one thing in a valid attachment, checkpoint, trust policy or report. Among the negative ones: another profile or version, a timestamp with no authority or over a hash other than SHA-256, a subject that does not say what it covers, an authority's certificate, a witness key or a checkpoint carried in the attachment, a time stated beside the token, a checkpoint time in another form, a revocation with no reason or another reason, a key with no role, a merged verdict, a compliance claim, a timestamp verified with the token's own certificate, a time given for a timestamp that failed, an inconsistent issuer's time reported as verified, a checkpoint from the export reported as independent, a compromised key verified on its stated time, an export compared with a checkpoint that is not verified, and a sequence claimed complete. Seven cases check that the fixture exports are valid portable verification exports.
- **Vector cases** recompute SHA-256, the links, the length prefix, the test keys from their seeds, each checkpoint's signed bytes (one field by field, as above), every Ed25519 signature from its seed, and each token's imprint. They show that changing any of the first four fields changes the signed bytes, and that `vectors.json` is byte for byte what `generate_vectors.py` writes.
- **Timestamp cases** run the reference check of one timestamp. They detect a timestamp over other bytes; a subject naming a seal or a link that is not the export's, including the last link of a rewritten export; an authority that is not in the trust policy; a token signed by another authority, or by another key naming the pinned authority and carrying its own certificate; a signature that does not match; a token backdated after signing, whose messageDigest no longer matches; a signer identifier naming another certificate than the key that signed; an ESSCertIDv2 naming another certificate; an imprint made with SHA-512, or labelled SHA-512 over a SHA-256 value; content that is not a TSTInfo, a signed content type other than TSTInfo, bytes that are not a token, and a token with two signers; a genTime outside the authority's window, after it was superseded, or from an authority revoked as compromised. They report an issuer's time later than the timestamp as inconsistent, for a record and for a witness's checkpoint, and count the token's accuracy. They report as not checked a subject the verifier cannot recompute, and an issuer's time from bytes that are unavailable or do not match the seal; and as not supported a signature algorithm the check does not support.
- **Checkpoint cases** run the reference check of one checkpoint as the verifier obtained it. Against an independent checkpoint, they detect a dropped tail, a dropped entry, a reordering and a rewrite, and report entries after the checkpoint as not covered. They never report as independent a checkpoint from the export, even one a trusted witness signed or one said to come from a configured source. Domain separation catches a signature moved to another key reference for the same key, another profile, another version or another assertion type, and a changed count, last link or time. They reject a key the policy does not list, or does not list for the source, the issuer's own key, a witness key used outside its validity, a superseded key used after it was superseded, and a source or chain the policy does not configure. A superseded key passes on its stated time, reported as the signer's statement. A compromised key with no timestamp gives "the time cannot be established"; with an independent timestamp earlier than `revoked_at` it passes; at or after `revoked_at`, including through the token's accuracy, it fails. A timestamp from an authority the policy does not trust, or over another signature, does not count. A transparency log and an algorithm the check does not support are reported as not supported, and a source that gives nothing as unavailable.
- **Pairing cases** read the report with its documents. They detect a missing, duplicated or uncounted result, an attachment or an export changed after the report was made, another trust policy or chain, a relabelled authority, source or issuer's time, a changed last link, a time earlier than the token gives, a timestamp or a key state reported as verified that the reference check does not verify, a certificate hash the token does not have reported as verified, an inconsistent issuer's time reported as consistent or left out, a superseded key's stated time reported as independent, a dropped tail reported as matching, a failing comparison hidden as not checked, and entries after a checkpoint not reported as not covered.

## Credit

Proposed by Laurent Lemonnier, iSoluce. Prepared with AI assistance and reviewed by Laurent. The shape of this extension was agreed in issue #29.
