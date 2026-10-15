# Contributing to the Decision Provenance Standard&trade;

Thank you for helping improve the Standard. This page explains how to take part, what we ask of every contribution, and what happens to it.

## Two ways to take part

- **Open an issue.** Use one issue per proposal, defect or question, and pick the matching form. Say which release you read, for example "Core v1.3, rev. 11" and "reference files 5.2.0".
- **Open a pull request.** Pull requests are welcome for anything in this repository. For a large change, an issue first saves everyone time.

## What we ask of every contribution

### 1. Sign off every commit (DCO 1.1)

- Every commit must carry a sign-off line, which certifies the [Developer Certificate of Origin, version 1.1](https://developercertificate.org/). In short, it says you wrote the contribution, or otherwise have the right to submit it under the license of the files you change.
- `git commit -s` adds the line for you:

  ```
  Signed-off-by: Your Name <you@example.com>
  ```

- Sign off as yourself, with the name or email of the commit's author. An automated check verifies every commit in a pull request.
- If you forgot:
  - `git commit --amend -s` fixes the last commit
  - `git rebase --signoff <base>` fixes several
  - then force-push your branch

### 2. Contributions come in under the same license they go out under

There is no separate agreement to sign. By contributing, you license your contribution under the license of the folder you change:

| You change | Your contribution is licensed under |
|---|---|
| Text (`spec/`, `governance/`, and the other documentation files at the repository root, including `CITATION.cff` and `NOTICE`) | Creative Commons Attribution 4.0 (CC BY 4.0) |
| `standard/v5.0/`, including its Markdown files (all of 5.x, including corrections) | MIT |
| Code (`tools/`, `tests/`, `.github/`) and any folder of reference files or tooling added later | Apache License 2.0 |
| `extensions/` | Text: Creative Commons Attribution 4.0 (CC BY 4.0). Schemas and code: Apache License 2.0 |

Contributing gives no rights in the name "Decision Provenance Standard" or its mark. See [NOTICE](NOTICE).

### 3. Tell us about AI assistance and other helpers

- If a substantial part of your text or code was generated with an AI tool, say so in the pull request.
- Name anyone else who helped and should be credited.

## What happens to your proposal

1. **We label it:** wording fix, rule change, defect, or add-on (an optional extension that sits beside the Standard without changing it).
2. **Rule changes go to the Steward.** A change is a rule change if it touches a MUST, SHALL, SHOULD or MAY sentence, a field, an allowed value, a conformance signal, or a "required at this state" rule. Some sections are protected and always need the Steward's approval. See [GOVERNANCE.md](GOVERNANCE.md).
3. **We classify its effect on people already using the Standard:**
   - **Patch:** fixes wording or an error and changes no rule.
   - **Minor:** adds or clarifies without making any previously valid record or Charter invalid. The Standard promises this for every minor release.
   - **Major:** makes some previously valid records or Charters invalid. It needs at least 12 months' notice and a migration note.
4. **The Steward decides what the Standard says.** We may merge your change, merge part of it, rewrite it, or decline it. You decide how your contribution is credited. We name you only in the form you approve.

## Practical notes for pull requests

- **Editing the text.**
  - Edit the section file in `spec/`, then update that document's `current_sha256` in `spec/editions.json`, so every text change is declared. When it differs, `python tools/check_split.py` prints the exact value to paste.
  - Adding, removing or renaming a section file also needs a matching change to `spec/editions.json`.
  - The core files keep the Windows line endings (CRLF) they were published with; the other documents use Unix line endings (LF). Make sure your editor does not convert them. The check fails if it does.
- **Text and reference files must agree.** If your change affects both, change both in the same pull request.
- **Fixing a known defect.** The differences between the text and reference release 5.2.0 are listed in `tests/known-defects/cases.json`. If your pull request fixes one, set that defect's `status` to `fixed` in the same pull request, so the fix is protected from then on.
- **Compatibility.** When renaming an allowed value, keep the old value accepted and mark it deprecated. Old values are removed only in a major release.
- **The checks** run on every pull request: the text split, the reference files, the known-defects report, the DCO sign-off, the leak guard, the governance records, and whether the declaration kit in `kit/` (Apache-2.0) is in sync with its sources. To run them locally:

  ```
  pip install -r tools/requirements.txt
  python tools/check_split.py
  python tools/check_reference_files.py
  python tests/known-defects/run_checks.py
  python tools/check_dco.py origin/main..HEAD
  python tools/check_leaks.py --base origin/main
  python tools/check_governance.py
  python kit/declaration/build.py --check --kit-only
  ```
- **The leak guard** looks only at what your pull request adds, and fails if it finds a private record number, a local folder path or an internal name from its list. Text already in the repository never fails it. A four-digit record number passes only if that record is in `governance/decisions/`.
- **The governance check** reads the Charter and the records in `governance/`: every field the text requires, the closing fields of each closed record against the merge that affirmed it, and each seal. It needs a full clone with its tags (`git fetch --tags`), because it reads merge commits and release tags.
- **Changing a checker.** The text split, the leak guard and the governance check each run the copy already on `main`, so your change to one of them takes effect only after it is merged (your own copy must pass too). If a change to `spec/`, `governance/` or the schemas in `standard/` needs a change to the checker that judges it, send the checker change first, in its own pull request. A new release's digests are added to the text-split checker after the release is tagged.
- **Waiting checks are normal.** For contributors from outside the organization, GitHub waits for a maintainer to approve running the checks on each pull request. We approve them; you don't need to do anything.
)

## What we can't accept

- Claims that the Standard, or following it, makes anyone "certified", "compliant" or "approved". Conformance is self-declared and no one certifies it.
- Legal advice or legal conclusions written as rules of the Standard. The Standard records how decisions were made; it does not say what the law requires.
- Material you don't have the right to contribute.

## Security

If you find a problem that could let someone forge or alter records undetected, or tamper with the published downloads, please report it privately. See [SECURITY.md](SECURITY.md).

## Credit

- We credit what you found or proposed: in the pull request history, in the release notes, and in the [contributors list](CONTRIBUTORS.md).
- Contributing does not make anyone an adopter, partner or endorser of the Standard.
