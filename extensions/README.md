# Extensions

An extension is an optional addition that sits beside the Standard without changing it.

- **Optional.** An extension's MUST, SHALL and SHOULD sentences bind only an implementation that says it uses that extension, at that version.
- **Beside the Standard.** An extension reads core fields and adds its own attachment. It does not change what a core field means or when it is required. Where an extension and the Standard's text disagree, the Standard's text governs.
- **Versioned on its own.** Each extension has its own version number and names the core release it was written against.
- **Not part of the Standard's releases.** Each extension version gets its own tag once it leaves Proposal, and a tagged version does not change. The Standard's release manifests and checksum lists do not include extensions.
- **No claims.** An extension says nothing about what any law requires. The records remain input, not evidence, and using an extension makes no one "certified", "compliant" or "approved".

Licences: in this folder, text is CC BY 4.0 ([LICENSE](../LICENSE)), and schemas and code are Apache-2.0 ([LICENSES/Apache-2.0.txt](../LICENSES/Apache-2.0.txt)). Each extension's README states which of its files are which.

| Extension | Version | Status | Written against |
|---|---|---|---|
| [Portable verification](portable-verification/) | 0.3.0 | Proposal | Core v1.3 rev. 11 (`v1.3-rev11`), reference files 5.2.0 (`ref-5.2.0`) |
| [Action binding](action-binding/) | 0.3.0 | Proposal | Core v1.3 rev. 11 (`v1.3-rev11`), reference files 5.2.0 (`ref-5.2.0`) |
| [Anchoring](anchoring/) | 0.2.0 | Proposal | Core v1.3 rev. 11 (`v1.3-rev11`), reference files 5.2.0 (`ref-5.2.0`) |
| [Signatures](signatures/) | 0.2.0 | Proposal | Core v1.3 rev. 11 (`v1.3-rev11`), reference files 5.2.0 (`ref-5.2.0`) |

## Names for typed references

Another format may cite a document of the Standard by a typed digest reference: a name, a digest algorithm and a digest. The Standard declares the names, so that a name means one thing wherever it appears. A name never changes meaning. A rule that computed a different digest would get a new name; these two do not change.

| Name | Identifies | Digest |
|---|---|---|
| `org.decisionprovenancestandard.decision_record` | one decision record, as closed by its seal | the record's seal, `seal_hash` (Core §5.1(3), §6.2): SHA-256 over the covered bytes, as [portable verification](portable-verification/) carries them (its items 3 and 4), in lowercase hexadecimal; the same value as the entry's `seal_hash` |
| `org.decisionprovenancestandard.action_binding_attachment` | one action-binding attachment, as issued | the plain SHA-256 of the attachment's bytes as issued, in lowercase hexadecimal: the `attachment_digest` the [action binding](action-binding/) report states; not the sealed digest, which the signatures profile computes with the signature value replaced |

How a reference is carried in another format, its member names and its purpose values, is that format's matter and is not defined here. A reference that verifies shows that the cited bytes are the document named, and nothing about what the document states: that is for the document's own check, which reports it.

