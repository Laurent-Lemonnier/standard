# Anchoring

| | |
|---|---|
| Extension | Anchoring |
| Version | 0.2.0 |
| Status | Proposal. Not part of the Standard. |
| Written against | Core v1.3, reading edition rev. 11 (tag `v1.3-rev11`), with reference files 5.2.0 (tag `ref-5.2.0`), and portable verification 0.1.0 |
| Licences | This text: CC BY 4.0 ([LICENSE](../../LICENSE)). The schemas (`schemas/`) and the tests (`tests/`): Apache-2.0 ([LICENSES/Apache-2.0.txt](../../LICENSES/Apache-2.0.txt)) |

This extension says how to anchor sealed decision records with evidence from outside the issuer, and how a check of that evidence reports what it found. It defines two assertions: an independent timestamp, which shows that exact bytes existed by a time, and an independent checkpoint, which fixes a chain of records at one point. Each is an object beside the export or the records. Neither adds a field to a decision record, and neither stands for the other.

It is the first of two related profiles agreed in issue #29. The second, signatures (the person's signature and the organisation's seal), will come later and reuse the signed-bytes rule and the key states defined here.

Version 0.2.0 changes 0.1.0 after review, and 0.1.0 documents are no longer valid. Each document states its version, and a checkpoint's signed bytes include it, so a 0.1.0 checkpoint does not verify as a 0.2.0 one. A checkpoint's `count` is now at most 2^53 - 1, a trust policy that lists one public key twice is refused, and a report says whether the policy was accepted. The reference check now gives a result for every input valid against the schemas, where 0.1.0 could stop on some, and reads an ESSCertIDv2 made with a hash other than SHA-256 as if there were none. The vectors now include a text field that is not ASCII, and RSA tokens: the reference check verifies RSA PKCS#1 v1.5 as well as ECDSA P-256, with the RSA test key RFC 9500 publishes. For the signatures profile, the shared rule now says how an absent optional value is signed, a timestamp's subject can name an assertion of that profile, and a key in the trust policy can carry what that profile needs.

## Scope, and what this extension does not claim

- The extension is optional. Its MUST, SHALL and SHOULD sentences bind only an implementation that says it uses anchoring 0.2.0.
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
- A text field is the UTF-8 encoding of the JSON string's value, with no escaping and no Unicode normalisation. Its length prefix counts bytes, not characters: `é` is two bytes. A string that has no UTF-8 encoding, because it holds a lone surrogate such as `\ud800`, cannot be signed.
- A digest (a seal, a link) is its 32 raw bytes, never its hex.
- An integer is written as a JSON integer, digits only with no fraction or exponent, and signed as 8 bytes, big-endian, unsigned. `3.0` is not a JSON integer, though JSON Schema accepts it as one.
- A time signed as text has exactly the form `YYYY-MM-DDTHH:MM:SSZ`: a real UTC time, to the second, with no leap second. The date exists, the hours run from 00 to 23, and the minutes and seconds from 00 to 59. Only the form is the encoder's concern: a time in that form that does not exist, such as 2026-02-30 or 23:59:60, is still encoded, as the text it is written in, and the signature is checked over it. It fails the check that reads it as a time, `key_state` for a `checkpoint_time`, and not the signature check, so that two implementations report the same dimension.
- An optional value that is absent is signed as the empty byte string: a length prefix of `00000000` and nothing after it. The field keeps its place, so the order stays fixed. Such a field is never empty when present, as a digest is always 32 bytes, so an absent value cannot be mistaken for a present one. A checkpoint has no optional field; the signatures profile signs an absent view digest this way.
- Every field is length-prefixed, including those of fixed length, so that one parser reads every assertion type.
- The first four fields are always `profile`, `profile_version`, the assertion type and `key_ref`, in that order. A signature therefore cannot be presented under another profile, version, assertion type or key reference: each of them changes the bytes, even for the same key known elsewhere by another reference.
- Each assertion type has one fixed field order. A new order needs a new assertion type or a new version.
- The verifier builds the signed bytes itself, from the fields it checks and with the profile, version and assertion type it expects. It never verifies a signature over bytes supplied with it.
- A value the rule cannot encode, or a time that cannot be read, makes the check that needs it fail, with the reason. It is never a reason for the verifier to stop.

In this profile, one assertion type is signed under the rule:

| Assertion type | Fields, in order |
|---|---|
| `checkpoint` | 1 `profile` (`dps-anchoring`), 2 `profile_version` (`0.2.0`), 3 the assertion type (`checkpoint`), 4 `key_ref`, 5 `chain_id`, 6 `count` (integer), 7 `head_link` (digest), 8 `checkpoint_time` (time) |

A checkpoint's `count` is at most 2^53 - 1 (9007199254740991): JSON readers agree exactly on every integer up to that (RFC 8259 §6), and may round a larger one. That is the same reason the rule uses length prefixes, and not a canonical JSON such as JCS (RFC 8785).

A checkpoint is signed with Ed25519 (RFC 8032), over the signed bytes themselves. The signatures profile will add its own assertion types and field orders under this rule. For example, the test checkpoint `cp_a` in `tests/vectors.json` (key `witness-a-1`, chain `urn:example:chain:issuer-1`, count 3, at 2026-09-27T12:00:00Z) has these 165 signed bytes:

```
4450532d534947 00                                                      "DPS-SIG" 0x00
0000000d 6470732d616e63686f72696e67                                    profile
00000005 302e322e30                                                    profile_version
0000000a 636865636b706f696e74                                          assertion type
0000000b 7769746e6573732d612d31                                        key_ref
0000001a 75726e3a6578616d706c653a636861696e3a6973737565722d31          chain_id
00000008 0000000000000003                                              count
00000020 461cf1cad5fe45a896737bb01ae396639da7ef5c424352ab0d029565e0228552  head_link
00000014 323032362d30392d32375431323a30303a30305a                      checkpoint_time
```

With a text field that is not ASCII, the prefix counts bytes. The test checkpoint `cp_accented` is `cp_a` for the chain `chaîne-émetteur-1`, which has 17 characters and 19 bytes in UTF-8. Its chain_id field is `00000013 636861c3ae6e652dc3a96d6574746575722d31`, and its signed bytes are 158. An encoder that counts characters writes `00000011` instead, and the signature does not verify over its bytes.

## The anchoring attachment

An attachment made under this extension:

1. MUST identify the profile and its version (`dps-anchoring`, `0.2.0`).
2. MAY state the issuer's `chain_id` for the export's chain. It is a reference: the verifier takes the chain it checks from its own configuration.
3. MUST carry each independent timestamp as its own object, and MAY carry references to checkpoint sources (`checkpoint_refs`). A reference is a hint, never a source of trust.
4. MUST NOT carry a time-stamping authority's certificate or key, a witness's key, or a checkpoint. It carries references only, as portable verification does (items 6 and 7 of its export rules).
5. MUST NOT state a time beside a token. The time comes only from the token.

An attachment is not sealed or chained. The `attachment_digest` in a report fixes which bytes were checked.

## An independent timestamp

- **What it covers.** The exact bytes its subject names: the 32 raw bytes of a record's `seal_hash` (`seal`, with its `decision_id`), the 32 raw bytes of `link(sequence)` of a chain (`chain_link`, with the `chain_id` and the `sequence`), or the raw bytes of a signature value (`signature`, naming what was signed: a checkpoint of this profile, or an assertion of the signatures profile, named as that profile names it, so that one attachment can carry the timestamps of both). A timestamp over a signature value shows that the signature existed by that time, which is what a key's revocation needs.
- **Format.** An RFC 3161 time-stamp token: a CMS SignedData with one signer over a TSTInfo (RFC 3161 §2.4.2, with ESSCertIDv2 as RFC 5816 allows). Its `messageImprint` is the SHA-256 of the subject's bytes. It is carried in DER, in padded base64 (`token_b64`), with a reference to the authority (`tsa_ref`).
- **Source of trust.** The authorities the verifier configured, each pinned by its certificate in the trust policy. Building a chain to a trusted list, and checking a certificate's revocation status, are out of scope: a verifier that needs them does them before it pins a certificate. A qualified time-stamp service is one example of an authority a verifier may configure.
- **What it proves.** These bytes existed no later than time T, according to an authority the verifier trusts. T is the token's `genTime`, plus its `accuracy` when it states one.
- **What it does not prove.** When the decision was made; that the bytes did not exist earlier; anything about their content; that the issuer's own times are right.

A verifier checks a timestamp as follows, and reports each check:

1. `token`: a ContentInfo carrying SignedData, with encapsulated content of type id-ct-TSTInfo, exactly one signer, and a TSTInfo of version 1, with no trailing bytes. Its `genTime` is in UTC (it ends in `Z`), and its `accuracy`, if any, is within the ranges of RFC 3161 §2.4.2: seconds not negative, millis and micros from 1 to 999. `genTime` plus the accuracy is a time the report can write, before the year 10000.
2. `message_imprint`: made with SHA-256, and equal to the SHA-256 of the subject's bytes.
3. `subject_bytes`: the subject's bytes are what it names. For a seal, the `seal_hash` of the record with that `decision_id`, in the export (the reference check) or in a record the verifier holds. For a link, `link(sequence)` recomputed from the export's seals by portable verification's rule, with `sequence` written as a JSON integer. For a signature, the signature value of the checkpoint it names, among those the verifier holds. For an assertion of the signatures profile, that profile checks this; the reference check here holds checkpoints only, and reports it as not checked.
4. `message_digest`: one signed content-type attribute, id-ct-TSTInfo, and one signed messageDigest attribute equal to the SHA-256 of the TSTInfo bytes as they appear in the token.
5. `tsa_signature`: `tsa_ref` names an authority in the trust policy, the token's signer identifier names its pinned certificate, the token's signature algorithm fits that certificate's key, and the signature over the signed attributes (their DER encoding as a SET OF, RFC 5652 §5.4) verifies with that key. A certificate carried in the token is never used.
6. `signer_certificate`: when the token has a signingCertificateV2 attribute, it is one attribute with one value; and when its first ESSCertIDv2 is made with SHA-256, that hash is the SHA-256 of the pinned certificate. A token without one, or whose first ESSCertIDv2 is made with another hash, is identified by its signer identifier alone, and the report says so (`not_checked`): the pinned key already fixes who signed.
7. `tsa_state`: `genTime` is within the policy's window for the authority, and before `revoked_at` if the authority was superseded. A token from an authority revoked as compromised never counts: it cannot show its own time.

The timestamp is verified only when every check is verified, except `signer_certificate`, which may be not checked. The report gives T only for a verified timestamp.

The verifier then compares the issuer's own time for the subject with T: for a seal, the record's `affirmation_record.timestamp`; for a link, the latest of those times among the entries it chains; for a checkpoint's signature, its `checkpoint_time`. It reads a record's time only from covered bytes whose SHA-256 is the entry's seal, and compares no time it cannot read, such as a `checkpoint_time` that is not a real UTC time (`not_checked`). An issuer's time later than T is reported as inconsistent. This comparison is reported apart from the timestamp, which it does not change: the bytes still existed by T.

The reference check in `tests/` supports tokens signed with ECDSA P-256 or with RSA PKCS#1 v1.5 (RSASSA-PKCS1-v1_5), each with SHA-256, the algorithms of the vectors, and reports any other, RSASSA-PSS among them, as not supported. A token whose algorithm the check supports but which does not fit the key of the pinned certificate, such as an ECDSA signature labelled RSA, fails. A verifier may support others.

## An independent checkpoint

- **What it fixes.** A chain at one point: its identifier (`chain_id`), the number of entries (`count`), the last link (`head_link`, which is `link(count - 1)`), and the time (`checkpoint_time`). The count and the last link are the shape portable verification already uses.
- **Independent** means that the verifier obtains it from a source its trust policy configures for that chain, outside the export. The extension requires no particular medium. In 0.2.0 a witness signs the checkpoint, with assertion type `checkpoint` under the shared rule. A transparency log, or a third party that keeps checkpoints, are other sources a verifier may configure; this version defines no format for them.
- **Never independent:** a checkpoint found in the export or the attachment, such as portable verification's `issuer_checkpoint`, even when a witness the verifier trusts signed it. The issuer chose which checkpoint to carry.
- **What it proves.** The export's first `count` entries are the ones the issuer had committed when the checkpoint was made. A dropped tail, a dropped entry, a reordering or a rewrite before that point is detected, even one that was re-sealed and re-chained. Entries after the checkpoint are reported as not covered.
- **What it does not prove.** That the issuer recorded every event; anything after the checkpoint; that the witness checked any content, since it saw digests only; that `checkpoint_time` is right, since it is the witness's own statement.

A verifier checks a checkpoint as follows, and reports each check:

1. `independence`: obtained from a source in the trust policy, configured for the checkpoint's `chain_id`, and not from the export.
2. `signature`: `key_ref` is a key in the trust policy, listed for that source, in the role `witness`; and its signature verifies over the signed bytes the verifier builds. A value the rule cannot encode fails here: a `count` that is not a JSON integer from 1 to 2^53 - 1, or a text field with no UTF-8 encoding. A `checkpoint_time` in the signed form that is not a real time does not: it is signed as written, and fails `key_state`.
3. `key_state`: the key's state when it signed (next section). A `checkpoint_time` that is not a real UTC time fails here, since that state cannot be read, and so does such a time in the policy's entry for the key.

The checkpoint is verified only when all three are. Only then is the export compared with it: the links recomputed from the export's seals, or derived digests, in the export's order and from 32 zero bytes, must give `head_link` at entry `count - 1`. An export with fewer than `count` entries fails. Entries from `count` on are reported as not covered. A checkpoint for another chain than the one the verifier checks is not compared.

## The trust policy and key states

- The trust policy is the verifier's own configuration, never taken from an export, an attachment or a token. It lists the time-stamping authorities, the keys, and the checkpoint sources, each with the chains it is used for and, for a witness, its keys.
- A key reference names one key. A new key gets a new reference. Changing keys never rewrites an old signature or checkpoint.
- Each key has its holder, its role, `not_before` and `not_after`, and, if it was revoked, `revoked_at` and a reason: `superseded` (replaced, not suspected of misuse) or `compromised`. The roles are `witness`, and the `organisation` and `person` roles of the related signatures profile, so that one policy holds every key. Only a witness key signs a checkpoint: the issuer's own key cannot make a checkpoint independent, whatever source lists it.
- One public key has one key reference, one holder and one role, and each reference in the policy names one entry. A verifier MUST refuse a policy that lists one public key twice, under two references, two holders or two roles, or that gives one reference to two entries. Otherwise the issuer's own key, listed a second time under a new reference in role `witness`, would make its checkpoints verify. The signatures profile relies on this rule, since there a key's role says what its signature means. A policy that lists an extra, distinct key is not refused for it. The comparison is of the key bytes, whatever each entry labels its `algorithm`, and however the bytes are written: an Ed25519 key is its 32 raw bytes; a P-256 key is its point, written compressed or uncompressed; an RSA key is its modulus and exponent, written in DER as an RSAPublicKey (RFC 8017) or a SubjectPublicKeyInfo (RFC 5280). The same 32 bytes labelled `Ed25519` in one entry and `EdDSA` or `ed25519` in another are one key, and the policy is refused. The check sees only the policy: one that lists the issuer's key once, in role `witness`, is an error only its author can see. Where a checkpoint's signature is verified, `public_key_hex` is read strictly, lowercase hex pairs and nothing else: a value the schema's pattern lets through, such as a final newline (which `$` matches before in some engines), is not a key, and the signature fails with the reason. The refusal of a policy that lists one key twice keeps the lenient read, so that a copy written with a stray newline is still refused as the same key.
- The refusal is reported once, as the report's `trust_policy` (`failed`, with the reason), and consistently: every check that relies on the policy is failed with the same reason ("... not checked: the trust policy is refused (...)"). For a timestamp, these are `tsa_signature` and `tsa_state`; for a checkpoint, `independence`, `signature` and `key_state`. The checks that do not rely on the policy still run, such as a timestamp's `token`, `message_imprint`, `subject_bytes` and `message_digest`, and no export is compared with a checkpoint that is not verified. The signatures profile reports a refusal in the same way.
- A time in the policy that is not a real UTC time, or a pinned certificate that cannot be read, does not refuse the policy: it fails the check that relies on that entry, `tsa_state` or `tsa_signature` for an authority and `key_state` for a key.
- A key may also carry what the signatures profile needs for a person's or an organisation's key: `identity_source_ref`, `webauthn` (a relying party identifier and its origins) and `certificate_b64`. One policy can then hold every key. Anchoring ignores these members.
- A signature is checked against the key's state when it was made. That time is the signer's own statement (`time_basis: stated_time`) unless a verified independent timestamp covers the signature value. Then the earliest such T is used (`time_basis: independent_timestamp`). Only the stated time can show that a signature was made after `not_before`, since a timestamp shows only when it existed at the latest.
  - A signature made outside the key's validity, from `not_before` to `not_after`, fails.
  - A key that was only superseded: the stated time is enough, if it is before `revoked_at`. The report gives it as the signer's statement, not as independent time.
  - A compromised key: the signature counts as made before `revoked_at` only if an independent timestamp earlier than `revoked_at` covers it. With none, the report says that the time cannot be established (`unavailable`). A timestamp at or after `revoked_at` fails.

## The verifier and its report

A verifier that uses this extension:

- MUST take every source of trust from its own trust policy: never from an export, an attachment or a token.
- MUST give a result for every document valid against these schemas, and never stop on one. A value it cannot encode, or a time it cannot read, is reported as failed, with the reason.
- MUST report each timestamp and each checkpoint as its own dimension: `verified`, `failed`, `not_checked`, `not_supported` or `unavailable`. Each names the source it was checked against: `tsa_ref` for a timestamp, `source_ref` and `key_ref` for a checkpoint. It MUST NOT merge them, with each other or with another extension's dimensions, into one pass, fail or compliance result. The report schema has no place for one.
- MUST give exactly one result for each timestamp in the attachment and for each checkpoint it obtained or tried to obtain, each with its index, and state their counts, the digests of the attachment and of the export, the chain it checked, and whether it accepted the trust policy (`trust_policy`).
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
- A witness-signed checkpoint delivered beside the export, as its own dimension: the prefix it fixes verified, and its freshness reported as not established, since the issuer chose which checkpoint to carry. It is not independent in this version.

## Dependencies

The reference check and the vector generator use two packages besides `jsonschema`, pinned in `tests/requirements.txt` with their own dependencies:

- `cryptography` 50.0.2, for Ed25519, ECDSA, RSA and X.509 certificates.
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

To run them from the repository root: `pip install -r tools/requirements.txt -r extensions/anchoring/tests/requirements.txt`, then `python extensions/anchoring/tests/run_checks.py`. The exit code is 0 when every case behaves as expected and 1 otherwise. Every document a case gives is valid against its schema, unless the case says otherwise, and a case in which the reference check raises an exception fails, whatever it expects.

Every key in the vectors is a test key only. All but one are derived from a published text: the seed is the SHA-256 of `dps-anchoring 0.1.0 test key ` followed by the key's name. The text is unchanged in 0.2.0, so the keys are those of 0.1.0. An Ed25519 key's seed is its private key (RFC 8032). A time-stamping authority's ECDSA P-256 private scalar is the seed read as a big-endian integer, modulo n - 1, plus 1. The one exception is the key of the second time-stamping authority (`tsa-rsa-1`): the 2048-bit RSA test key that RFC 9500 §2.1 publishes under the name `testRSA2048`, reconstructed in `generate_vectors.py` from its parameters as the RFC prints them, so that no RSA key had to be generated here. `vectors.json` carries its public modulus and exponent, and a case checks them against the RFC's text. Never derive a real key this way, and never use a published key for anything real. The signatures are deterministic, Ed25519 by definition, ECDSA with the nonces of RFC 6979 and RSA PKCS#1 v1.5 by construction, so `vectors.json` is byte-reproducible. Each checkpoint in it gives its exact signed bytes in hex (`signed_bytes_hex`), and each token the bytes its imprint covers. One chain identifier, `chaîne-émetteur-1`, is not ASCII. Generating needs OpenSSL 3.2 or later, which the pinned `cryptography` includes; checking does not. The records and links are those of portable verification's cases, so the two sets of vectors agree.

- **Schema cases** change one thing in a valid attachment, checkpoint, trust policy or report. Among the negative ones: another profile or an earlier version, a timestamp with no authority or over a hash other than SHA-256, a subject that does not say what it covers, an authority's certificate, a witness key or a checkpoint carried in the attachment, a time stated beside the token, a checkpoint time in another form, a revocation with no reason or another reason, a key with no role, a checkpoint count above 2^53 - 1, a merged verdict, a compliance claim, a timestamp verified with the token's own certificate, a time given for a timestamp that failed, an inconsistent issuer's time reported as verified, a checkpoint from the export reported as independent, a compromised key verified on its stated time, an export compared with a checkpoint that is not verified, a sequence claimed complete, no statement of whether the trust policy was accepted, and a refused policy with results still verified. For the signatures profile, they accept a signature subject naming an approval or a seal of that profile, and a key with the members that profile needs; they reject an affirmation named with a stage, a seal that does not say what it seals, an approval said to be of another profile, a checkpoint named by a record, a passkey with no origins, and a key member neither profile defines. Some positive cases show what JSON Schema cannot reject, so the reference check must: a count written as `3.0`, a sequence written as `2.0`, a checkpoint time that does not exist or is a leap second, a policy time that does not exist, one public key listed twice, and the same key under two algorithm labels, and a witness key written with a final newline, which the schema admits and the check fails (K67). Seven cases check that the fixture exports are valid portable verification exports.
- **Vector cases** recompute SHA-256, the links, the length prefix (of an ASCII and a non-ASCII text), the test keys from their seeds and the RSA key's modulus and exponent against RFC 9500's text, each test certificate's key, each checkpoint's signed bytes (two field by field, as above), every Ed25519 signature from its seed, and each token's imprint. They show that changing any of the first four fields changes the signed bytes, that prefixes counting characters instead of bytes give other bytes, over which `cp_accented`'s signature does not verify, and that `vectors.json` is byte for byte what `generate_vectors.py` writes.
- **Timestamp cases** run the reference check of one timestamp. They detect a timestamp over other bytes; a subject naming a seal or a link that is not the export's, including the last link of a rewritten export; an authority that is not in the trust policy; a token signed by another authority, or by another key naming the pinned authority and carrying its own certificate; a signature that does not match; a token backdated after signing, whose messageDigest no longer matches; a signer identifier naming another certificate than the key that signed; an ESSCertIDv2 naming another certificate; an imprint made with SHA-512, or labelled SHA-512 over a SHA-256 value; content that is not a TSTInfo, a signed content type other than TSTInfo, bytes that are not a token, and a token with two signers; a genTime outside the authority's window, after it was superseded, or from an authority revoked as compromised. They detect a signingCertificateV2 attribute with no value, a genTime not in UTC, an accuracy that is negative, outside RFC 3161's range or past the year 9999, and a sequence written as `2.0`; most of these stopped the 0.1.0 check. They refuse a trust policy with one `tsa_ref` for two entries, or with a witness's public key listed twice: the authority's checks then fail. A policy time that is not a real UTC time (a date that does not exist, a leap second) fails that authority's state, and a pinned certificate that cannot be read its signature. They report an issuer's time later than the timestamp as inconsistent, for a record and for a witness's checkpoint, and count the token's accuracy. They report as not checked a subject the verifier cannot recompute, an issuer's time from bytes that are unavailable or do not match the seal, a checkpoint time that does not exist, a subject naming an assertion of the signatures profile, and the certificate hash of an ESSCertIDv2 made with SHA-512, the timestamp still verified; and as not supported a signature algorithm the check does not support (ECDSA with SHA-384, and RSASSA-PSS). With the RSA authority, whose key is RFC 9500's `testRSA2048`, they verify a token signed with RSA PKCS#1 v1.5, with and without an ESSCertIDv2, and detect a token over other bytes, a signature changed after signing, an authority the policy does not list or no longer lists, and a token presented as the ECDSA authority's; a supported algorithm that does not fit the pinned key, an ECDSA signature labelled RSA or the reverse, fails.
- **Checkpoint cases** run the reference check of one checkpoint as the verifier obtained it. Against an independent checkpoint, they detect a dropped tail, a dropped entry, a reordering and a rewrite, and report entries after the checkpoint as not covered. They never report as independent a checkpoint from the export, even one a trusted witness signed or one said to come from a configured source. Domain separation catches a signature moved to another key reference for the same key (in a policy that knows the key by that reference), another profile, an earlier version or another assertion type, and a changed count, last link or time. They report as failed, never stopping, a count written as `3.0` or of 2^64, a checkpoint time that does not exist or is a leap second, and a chain identifier with no UTF-8 encoding. A checkpoint whose chain identifier is not ASCII verifies; signed with prefixes that count characters, or presented in another Unicode normalisation form, it fails. They reject a key the policy does not list, or does not list for the source, the issuer's own key, a witness key used outside its validity, a superseded key used after it was superseded, and a source or chain the policy does not configure. They refuse a policy that lists the issuer's public key a second time, under a new reference in role witness (its checkpoint verified in 0.1.0), or a witness's key under a second reference or with another holder, or that gives one key or source reference to two entries; the signature, the key state and the independence then fail, and a source that gives nothing is failed, not unavailable. The keys are compared by their bytes: the issuer's key relisted as a witness is refused when its own entry is labelled `EdDSA` or `ed25519` (a check comparing labels accepted it), a P-256 key written once uncompressed and once compressed is one key, and so is an RSA key written once as an RSAPublicKey and once as a SubjectPublicKeyInfo; two distinct keys under one label are accepted. They accept a policy with an extra, distinct key: a person's passkey with the members of the signatures profile, which anchoring ignores. A leap second as the witness's revocation time fails its key state. A further case passes by design, and the runner states its limit: the issuer's key, listed once in role witness, verifies. A superseded key passes on its stated time, reported as the signer's statement. A compromised key with no timestamp gives "the time cannot be established"; with an independent timestamp earlier than `revoked_at` it passes; at or after `revoked_at`, including through the token's accuracy, it fails. A timestamp from an authority the policy does not trust, or over another signature, does not count. A transparency log and an algorithm the check does not support are reported as not supported, and a source that gives nothing as unavailable. A witness key written with a final newline in the policy fails the signature, read strictly, where the lenient read verified it.
- **Pairing cases** read the report with its documents. They detect a missing, duplicated or uncounted result, a wrong count, an index or a count written as `0.0`, `1.0` or `3.0` (an index so written stopped the 0.1.0 reader), a report made with a trust policy that the reader refuses, a refused policy reported as accepted and an accepted one as refused, an attachment or an export changed after the report was made, another trust policy or chain, a relabelled authority, source or issuer's time, an RSA token reported against the ECDSA authority or verified with a changed signature, a changed last link, a time earlier than the token gives, a timestamp or a key state reported as verified that the reference check does not verify, a certificate hash the token does not have reported as verified, an inconsistent issuer's time reported as consistent or left out, a superseded key's stated time reported as independent, a dropped tail reported as matching, a failing comparison hidden as not checked, and entries after a checkpoint not reported as not covered. They accept a refused policy reported as refused, with nothing verified against it.

## Credit

Author: Laurent Lemonnier, iSoluce. Prepared with AI assistance and reviewed by Laurent. The shape of this extension was agreed in issue #29.
