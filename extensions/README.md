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
| [Portable verification](portable-verification/) | 0.1.0 | Proposal | Core v1.2 rev. 10 (`v1.2-rev10`), reference files 5.1.2 (`ref-5.1.2`) |
| [Action binding](action-binding/) | 0.2.0 | Proposal | Core v1.3 rev. 11 (`v1.3-rev11`), reference files 5.2.0 (`ref-5.2.0`) |
| [Anchoring](anchoring/) | 0.2.0 | Proposal | Core v1.3 rev. 11 (`v1.3-rev11`), reference files 5.2.0 (`ref-5.2.0`) |
| [Signatures](signatures/) | 0.2.0 | Proposal | Core v1.3 rev. 11 (`v1.3-rev11`), reference files 5.2.0 (`ref-5.2.0`) |
