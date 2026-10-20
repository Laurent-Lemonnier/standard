# SPDX-License-Identifier: Apache-2.0
"""Checks for the portable verification extension, version 0.2.0 (a proposal).

Runs the cases in cases.json over the values in vectors.json, which generate_vectors.py writes:

  schema cases     an export or a report from vectors.json, changed by a patch, against the extension's schemas
  vector cases     the values in vectors.json recomputed: SHA-256, the signed bytes of an entry's signature, the test
                   keys from their seed texts, the tokens' imprints, the agreement with the signatures vectors, the
                   reference report of the base export, and vectors.json itself, byte for byte
  digest cases     SHA-256 over exact bytes: seals, mutation, re-serialisation, the seal field, a derived digest
  chain cases      the link rule: omission, reordering, truncation, and which checkpoints count
  statement cases  the reference check of an entry's statements outside the seal, over its covered bytes
  signature cases  the reference check of one entry's signature: the signatures 0.2.0 organisation seal of kind
                   record, with the key the trust policy gives, its state when it signed, and the independent
                   timestamps over its value from the signatures attachment beside the export
  export seal      the reference check of the export's seal, read from the attachment beside the export
  pairing cases    a report read with its export, the attachment beside it and the policy: one entry result per
                   export entry, and nothing reported as verified that is not (JSON Schema cannot compare documents)

The reference check of a signature, of a key's state, of a timestamp and of the export's seal is the signatures
extension's own reference check, loaded from extensions/signatures/tests/run_checks.py, so that the two cannot
drift: an entry's signature is that profile's seal, and this check builds the seal from the entry and hands it over.
Standard library, jsonschema, and the signatures runner's requirements (cryptography, asn1crypto).

Usage:  python extensions/portable-verification/tests/run_checks.py
Exit code 0 = every case behaves as expected, 1 = a case does not.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

from jsonschema import Draft202012Validator

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCHEMAS = {
    "export": HERE.parent / "schemas" / "verification-export.schema.json",
    "report": HERE.parent / "schemas" / "verification-report.schema.json",
}
OTHER_SCHEMAS = {
    # The trust policy is anchoring 0.2.0's; the attachment beside the export is signatures 0.2.0's.
    "trust_policy": ROOT / "extensions" / "anchoring" / "schemas" / "trust-policy.schema.json",
    "sig_attachment": ROOT / "extensions" / "signatures" / "schemas" / "signatures-attachment.schema.json",
}
SIGNATURES_RUNNER = ROOT / "extensions" / "signatures" / "tests" / "run_checks.py"
PROFILE, VERSION = "dps-portable-verification", "0.2.0"
SIGNATURES_PROFILE, SIGNATURES_VERSION = "dps-signatures", "0.2.0"
SIGNED_BYTES_REF = f"{SIGNATURES_PROFILE} {SIGNATURES_VERSION} organisation_seal"
ZERO_LINK = bytes(32)
READABLE = {"application/json"}  # media types the reference statement check reads
PREDECESSORS = ("supersedes", "target_record_hash", "target_decision_id")
ZEROED = '"seal_hash":"' + "0" * 64 + '"'
SIGNATURE_DIMENSIONS = ("status", "key_state", "time_assurance")
SEAL_DIMENSIONS = ("status", "signature", "subject", "key_state")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sig = load_module("signatures_run_checks", SIGNATURES_RUNNER)  # the signatures 0.2.0 reference check
strict_json, compact, b64decode = sig.strict_json, sig.compact, sig.b64decode


class Raised(Exception):
    """The reference check raised on schema-valid input: the case fails, the run goes on."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def next_link(previous_hex, digest_hex):
    previous = bytes.fromhex(previous_hex) if previous_hex else ZERO_LINK
    return hashlib.sha256(previous + bytes.fromhex(digest_hex)).hexdigest()


def errors(validator, doc):
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message[:100]}"
            for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))]


# ---------------------------------------------------------------- the entry's statements (as in 0.1.0)

def entry_digest(entry):
    """What the entry's covered bytes are compared with, and what its signature signs: the seal, or the derived digest."""
    return entry["seal"]["seal_hash"] if "seal" in entry else entry["derived_digest"]


def statement_check(entry):
    """Reference check: an export entry's statements that sit outside the seal, against its covered bytes."""
    if entry["content"]["availability"] != "available":
        return "not_checked", ["the covered bytes are unavailable"]
    if entry["covered_representation"]["media_type"] not in READABLE:
        return "not_checked", ["this check cannot read the media type"]
    try:
        record = strict_json(base64.b64decode(entry["content"]["covered_bytes_b64"], validate=True))
    except ValueError as exc:
        return "not_checked", [f"the covered bytes cannot be read: {exc}"]
    if not isinstance(record, dict):
        return "not_checked", ["the covered bytes are not a JSON object"]
    wrong, notes = [], []
    if record.get("decision_id") != entry["decision_id"]:
        wrong.append("decision_id")
    if "record_type" not in record:
        notes.append("record_type is absent from the covered bytes and read as decision (Core §6.2)")
    if record.get("record_type", "decision") != entry["record_type"]:
        wrong.append("record_type")
    stated = entry.get("predecessors", {})
    for k in PREDECESSORS:
        a, b = record.get(k), stated.get(k)
        if k == "target_record_hash" and isinstance(a, str):
            a = a.lower()  # the export carries hex in lowercase
        if a != b:
            wrong.append(k)
    seal = entry.get("seal")
    if seal:
        value = record.get("seal_hash")
        if seal["seal_field_handling"] == "seal_hash_absent":
            handled = "seal_hash" not in record
        else:  # seal_hash_zeroed: a non-empty value made only of 0; other placeholders are not covered
            handled = isinstance(value, str) and value != "" and set(value) == {"0"}
        if not handled:
            wrong.append("seal_field_handling")
        if ("affirmation_record" in record) != seal["affirmation_record_covered"]:
            wrong.append("affirmation_record_covered")
    if wrong:
        return "failed", ["does not match the covered bytes: " + ", ".join(wrong)] + notes
    return "verified", notes


def seal_digest_check(entry):
    """The Core seal: the covered bytes against the digest the entry states (same_export: the value compared with is
    the export's own statement)."""
    if entry["content"]["availability"] != "available":
        return {"status": "unavailable", "findings": ["the covered bytes are unavailable, so the digest cannot be "
                                                      "recomputed"]}
    try:
        raw = base64.b64decode(entry["content"]["covered_bytes_b64"], validate=True)
    except ValueError as exc:
        return {"status": "failed", "findings": [f"the covered bytes cannot be read: {exc}"]}
    if sha256(raw) != entry_digest(entry):
        return {"status": "failed", "findings": ["the covered bytes do not match the digest the entry states"]}
    return {"status": "verified", "reference_source": "same_export"}


# ---------------------------------------------------------------- the entry's signature (signatures 0.2.0, by reference)

def seal_assertion(entry):
    """The entry's signature as the signatures profile's organisation seal of kind record, built from the entry
    itself: nothing in it is taken from the signature member but the key reference, the time and the value."""
    s = entry["signature"]
    return {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION, "assertion": "organisation_seal",
            "sealed": {"kind": "record", "id": entry["decision_id"], "digest": entry_digest(entry)},
            "sealed_at": s["sealed_at"], "signature": {"algorithm": s["algorithm"], "key_ref": s["key_ref"],
                                                       "value_b64": s["value_b64"]}}


def held_assertions(export, attachment):
    """Where a timestamp's signature value is looked for: the entries' signatures, as seals, and the attachment's own
    assertions."""
    held = [seal_assertion(e) for e in export["entries"] if "signature" in e]
    if attachment:
        held += attachment.get("organisation_seals", []) + attachment.get("person_signatures", [])
    return held


def policy_key(policy, key_ref):
    return next((k for k in policy["keys"] if k["key_ref"] == key_ref), None)


def check_entry_signature(entry, policy, policy_result, ts_results):
    """The entry's signature as one dimension: the signatures check of the seal built from the entry (signature, then
    the key's state when it signed), with the holder the policy gives. The subject needs no check of its own: the
    verifier builds the signed bytes from the entry's own identifier and digest."""
    if "signature" not in entry:
        return {"status": "not_checked", "findings": ["the entry carries no signature"]}
    s = entry["signature"]
    out = {"key_ref": s["key_ref"], "algorithm": s["algorithm"]}
    if entry["content"]["availability"] != "available":
        out.update(status="unavailable", findings=["the entry's signature covers a digest whose bytes are unavailable; "
                                                   "it is not checked"])
        return out
    a = seal_assertion(entry)
    signature, key, _ = sig.checked_signature(a, sig.seal_signed_bytes, policy, policy_result, "organisation",
                                              sig.SEAL_SUITES)
    out.update({k: v for k, v in signature.items() if k != "status"})
    if key is not None:
        out["holder"] = key["holder"]
    if signature["status"] == "verified":
        out["key_state"] = sig.key_state(key, "sealed_at", s["sealed_at"],
                                         sig.covering_timestamps(b64decode(s["value_b64"]), ts_results))
    elif policy_result["status"] != "verified":
        out["key_state"] = sig.refused(policy_result, "the key state")
    else:
        out["key_state"] = {"status": "not_checked"}
    out["status"] = sig.combine(signature["status"], out["key_state"]["status"])
    return out


def time_assurance(entry, signature, ts_results):
    """Verified only against a verified independent timestamp over the entry's signature value, where that signature
    verifies on this entry: a timestamp over bytes that are not this entry's signature shows nothing about it."""
    if "signature" not in entry:
        return {"status": "not_checked", "basis": "issuer_assertion"}
    if entry["content"]["availability"] != "available":
        return {"status": "not_checked", "basis": "issuer_assertion",
                "findings": ["the entry's signature is not checked, so no timestamp over it counts"]}
    if signature.get("key_state", {}).get("status") == "not_checked":  # the signature itself did not verify
        return {"status": "not_checked", "basis": "issuer_assertion",
                "findings": ["the entry's signature is not verified, so a timestamp over its value shows nothing "
                             "about this entry"]}
    covering = sig.covering_timestamps(b64decode(entry["signature"]["value_b64"]), ts_results)
    if not covering:
        return {"status": "not_checked", "basis": "issuer_assertion",
                "findings": ["no verified independent timestamp covers the entry's signature; sealed_at is the "
                             "issuer's statement"]}
    i, r = min(covering, key=lambda c: c[1]["_upper"])
    t = r["existed_no_later_than"]
    return {"status": "verified", "basis": "independent_source", "source_ref": r["tsa_ref"], "no_later_than": t,
            "timestamp_index": i,
            "findings": [f"the entry's signature, and so the digest it names, existed no later than {t} "
                         f"({r['tsa_ref']}); not when the decision was made or affirmed"]}


def check_export_seal(attachment, export, policy, policy_result, ts_results):
    """The seal of kind export in the attachment beside the export, checked as the signatures profile checks it:
    the signature, the sealed digest against the export's bytes as received, the key's state."""
    seals = [s for s in (attachment or {}).get("organisation_seals", []) if s["sealed"]["kind"] == "export"]
    if not seals:
        return None
    seal = seals[0]
    r = sig.check_seal(seal, policy, policy_result, {"export": export, "action_binding": {}}, ts_results)
    out = {"status": r["status"], "key_ref": r["key_ref"]}
    key = policy_key(policy, seal["signature"]["key_ref"])
    if key is not None:
        out["holder"] = key["holder"]
    out.update(sealed_id=seal["sealed"]["id"], sealed_at=seal["sealed_at"], signature=r["signature"],
               subject=r["subject"], key_state=r["key_state"])
    if len(seals) > 1:
        out["findings"] = [f"the attachment carries {len(seals)} seals of kind export; the first is reported"]
    return out


# ---------------------------------------------------------------- the whole export: the reference report

def object_links(export):
    """supersedes, target_record_hash and derived_from among the supplied entries."""
    by_id = {}
    for e in export["entries"]:
        by_id.setdefault(e["decision_id"], []).append(e)
    findings, failed = [], False
    for e in export["entries"]:
        p = e.get("predecessors", {})
        for k in ("supersedes", "target_decision_id"):
            if k in p and p[k] not in by_id:
                findings.append(f"{e['decision_id']} names {p[k]} ({k}), which is not among the supplied entries")
        if "target_record_hash" in p and p["target_decision_id"] in by_id:
            seals = {x["seal"]["seal_hash"] for x in by_id[p["target_decision_id"]] if "seal" in x}
            if p["target_record_hash"] not in seals:
                failed = True
                findings.append(f"{e['decision_id']} names a seal of {p['target_decision_id']} that is not the one "
                                "supplied")
        if "derived_from" in e:
            originals = [x for x in by_id.get(e["decision_id"], []) if "seal" in x]
            if not originals:
                findings.append(f"the original of the derived entry of {e['decision_id']} is not among the supplied "
                                "entries")
            elif e["derived_from"]["original_seal_hash"] not in {x["seal"]["seal_hash"] for x in originals}:
                failed = True
                findings.append(f"the derived entry of {e['decision_id']} names an original seal that is not the "
                                "supplied original's")
    out = {"status": "failed" if failed else "verified"}
    if findings:
        out["findings"] = findings
    return out


def sequence_check(export):
    head, consistent = None, True
    for e in export["entries"]:
        c = e.get("chain")
        if c is None:
            continue
        if c["previous_link"] != head:
            consistent = False
        head = next_link(head, entry_digest(e))
    return {"status": "verified" if consistent else "failed", "completeness": "not_established",
            "findings": ["no independent checkpoint was supplied"]}


def original_seal_check(entry, export):
    """A derived entry: the original seal, checked on its own against the supplied original, where there is one."""
    o = entry["derived_from"]["original_seal_hash"]
    original = next((x for x in export["entries"] if x["decision_id"] == entry["decision_id"] and "seal" in x
                     and x["seal"]["seal_hash"] == o), None)
    if original is None:
        return {"original_seal_hash": o, "status": "unavailable",
                "findings": ["the original sealed representation is not among the supplied entries"]}
    r = seal_digest_check(original)
    out = {"original_seal_hash": o, "status": r["status"]}
    if r.get("findings"):
        out["findings"] = r["findings"]
    return out


def reference_report(export, attachment, policy):
    """What a verifier using this extension reports for one export read with the attachment beside it and the
    policy. Nothing here catches an exception: the check gives a result for every schema-valid input, and the runner
    fails a case in which it raises."""
    policy_result = sig.check_policy(policy)
    held = held_assertions(export, attachment)
    ts_results = [sig.check_timestamp(t, policy, policy_result, held) for t in (attachment or {}).get("timestamps", [])]
    entries = []
    for i, e in enumerate(export["entries"]):
        status, findings = statement_check(e)
        statement = {"status": status}
        if "seal" in e:
            statement["affirmation_record_covered"] = e["seal"]["affirmation_record_covered"]
        if findings:
            statement["findings"] = findings
        availability = {"status": e["content"]["availability"]}
        if availability["status"] == "unavailable":
            availability["reason"] = e["content"]["reason"]
            if "reason_ref" in e["content"]:
                availability["reason_ref"] = e["content"]["reason_ref"]
        signature = check_entry_signature(e, policy, policy_result, ts_results)
        r = {"export_index": i, "decision_id": e["decision_id"],
             "representation": "derived" if "derived_from" in e else "original_sealed",
             "structural_validity": {"status": "verified"}, "statement_check": statement,
             "cryptographic_verification": {"seal_digest": seal_digest_check(e), "signature": signature},
             "content_availability": availability, "time_assurance": time_assurance(e, signature, ts_results),
             "identity_assurance": {"status": "not_checked", "basis": "issuer_assertion"}}
        if "derived_from" in e:
            r["original_seal_check"] = original_seal_check(e, export)
        entries.append(r)
    report = {"profile": f"{PROFILE}-report", "profile_version": VERSION, "export_digest": sha256(compact(export)),
              "export_entry_count": len(export["entries"]), "trust_policy_ref": policy["policy_ref"],
              "trust_policy": policy_result}
    if attachment is not None:
        report["signatures_attachment_digest"] = sha256(compact(attachment))
    report.update(structural_validity={"status": "verified"}, entries=entries,
                  object_links={**object_links(export), "sequence": sequence_check(export)})
    export_seal = check_export_seal(attachment, export, policy, policy_result, ts_results)
    if export_seal is not None:
        report["export_seal"] = export_seal
    report["scope_of_conclusion"] = {"covers": "supplied_export_only",
                                     "not_assessed": ["legal_requirements", "conformance_level",
                                                      "events_not_in_export", "truth_of_record_content"]}
    return report


def reference(check, *args):
    try:
        return check(*args)
    except Exception as exc:
        raise Raised(f"the reference check raised {type(exc).__name__} on schema-valid input: {exc}") from exc


# ---------------------------------------------------------------- a report read with its documents

def verified_but_not(label, got, want, problems, what):
    if got == "verified" and want != "verified":
        problems.append(f"{label}: {what} reported verified; the reference check finds {want}")


def read_with_export(report, export, attachment, policy):
    """What a reader holding a report, its export, the attachment beside it and the policy checks; JSON Schema cannot
    compare two documents. A report may say less than the reference check (not_checked where it could have checked);
    it may not say more."""
    ref = reference_report(export, attachment, policy)
    entries, results = export["entries"], report["entries"]
    problems = []
    if report["export_digest"] != ref["export_digest"]:
        problems.append("export_digest is not the digest of the export read with the report")
    if report["export_entry_count"] != len(entries):
        problems.append(f"export_entry_count is {report['export_entry_count']}; the export has {len(entries)} entries")
    if report["trust_policy_ref"] != policy["policy_ref"]:
        problems.append("trust_policy_ref is not the policy the documents are read with")
    if report["trust_policy"]["status"] != ref["trust_policy"]["status"]:
        problems.append(f"the trust policy reported {report['trust_policy']['status']}; the reference check finds "
                        f"{ref['trust_policy']['status']}")
    if report.get("signatures_attachment_digest") != ref.get("signatures_attachment_digest"):
        problems.append("signatures_attachment_digest is not the digest of the attachment read with the report"
                        if attachment is not None else "signatures_attachment_digest named, and no attachment read")
    indexes = sorted(r["export_index"] for r in results)
    if indexes != list(range(len(entries))):
        problems.append(f"results name export entries {indexes}; each of 0 to {len(entries) - 1} must appear once")
    for r in results:
        i = r["export_index"]
        if i >= len(entries):
            continue
        e, x = entries[i], ref["entries"][i]
        label = f"entry {i}"
        if r["decision_id"] != e["decision_id"]:
            problems.append(f"{label}: decision_id differs from the export entry's")
        if r["representation"] != x["representation"]:
            problems.append(f"{label}: representation differs from the export entry")
        if "seal" in e and r["statement_check"].get("affirmation_record_covered") != e["seal"]["affirmation_record_covered"]:
            problems.append(f"{label}: affirmation_record_covered not carried through")
        verified_but_not(label, r["statement_check"]["status"], x["statement_check"]["status"], problems, "statements")
        cv, xcv = r["cryptographic_verification"], x["cryptographic_verification"]
        verified_but_not(label, cv["seal_digest"]["status"], xcv["seal_digest"]["status"], problems, "the seal digest")
        s, xs = cv["signature"], xcv["signature"]
        if "signature" not in e and s["status"] != "not_checked":
            problems.append(f"{label}: the entry carries no signature; its signature is reported {s['status']}")
        verified_but_not(label, s["status"], xs["status"], problems, "the signature")
        if s["status"] == xs["status"] == "verified":
            if s.get("holder") != xs.get("holder") or s.get("key_ref") != xs.get("key_ref"):
                problems.append(f"{label}: the signature's key or holder is not the policy's")
            ks, xks = s["key_state"], xs["key_state"]
            if any(ks.get(k) != xks.get(k) for k in ("time_basis", "time", "timestamp_index", "revocation_reason")):
                problems.append(f"{label}: the key state's time and its basis not reported as found")
        t, xt = r["time_assurance"], x["time_assurance"]
        verified_but_not(label, t["status"], xt["status"], problems, "time")
        if t["status"] == xt["status"] == "verified" and any(
                t.get(k) != xt.get(k) for k in ("source_ref", "no_later_than", "timestamp_index")):
            problems.append(f"{label}: the timestamp's authority, time or index not reported as found")
        if r["identity_assurance"]["status"] == "verified":
            problems.append(f"{label}: identity reported verified; this extension has no independent source for it")
        if "original_seal_check" in r:
            verified_but_not(label, r["original_seal_check"]["status"],
                             x.get("original_seal_check", {}).get("status"), problems, "the original seal")
    if ("export_seal" in report) != ("export_seal" in ref):
        problems.append("an export seal reported, and none read beside the export" if "export_seal" in report else
                        "the attachment carries the export's seal, and the report does not report it")
    elif "export_seal" in report:
        s, xs = report["export_seal"], ref["export_seal"]
        verified_but_not("export seal", s["status"], xs["status"], problems, "the seal")
        for d in ("signature", "subject", "key_state"):
            verified_but_not("export seal", s[d]["status"], xs[d]["status"], problems, d)
        if s["status"] == xs["status"] == "verified" and (s.get("holder"), s["key_ref"], s["sealed_id"]) != (
                xs.get("holder"), xs["key_ref"], xs["sealed_id"]):
            problems.append("export seal: the key, holder or reference not as found")
    ol, xol = report["object_links"], ref["object_links"]
    verified_but_not("object links", ol["status"], xol["status"], problems, "the links")
    verified_but_not("object links", ol["sequence"]["status"], xol["sequence"]["status"], problems, "the sequence")
    return problems


# ---------------------------------------------------------------- the cases

def context_for(c, v, validators):
    """The documents a case reads: the export, the attachment beside it (or none), the policy, each patched."""
    base = v["base_context"]
    export = sig.apply_patch(v["exports"][c.get("export", base["export"])], c.get("export_patch", []), v)
    att_name = c.get("attachment", base["attachment"])
    attachment = None
    if att_name is not None:
        attachment = sig.apply_patch(v["signatures_attachments"][att_name], c.get("attachment_patch", []), v,
                                     {"export": sha256(compact(export))})
    policy = sig.apply_patch(v["trust_policy"], c.get("policy_patch", []), v)
    for name, doc, validator in (("export", export, "export"), ("trust policy", policy, "trust_policy"),
                                 ("attachment", attachment, "sig_attachment")):
        if doc is not None and errors(validators[validator], doc):
            raise ValueError(f"the {name} must be schema-valid for this case: {errors(validators[validator], doc)[0]}")
    return export, attachment, policy


def schema_case(c, v, validators):
    base = v["base_report"] if c["schema"] == "report" else v["exports"][c.get("base", "signed")]
    digests = {k: sha256(compact(v["exports"][k])) for k in v["exports"]}
    instance = sig.apply_patch(base, c["patch"], v, digests)
    found = errors(validators[c["schema"]], instance)
    return ("pass" if not found else "fail"), found


def load_generator():
    return load_module("pv_generate_vectors", HERE / "generate_vectors.py")


def vector_case(c, v):
    kind, bad = c["check"], []
    if kind == "known_vector":
        return ("match" if sha256(c["text"].encode()) == c["digest"] else "mismatch"), ""
    elif kind == "record_digests":
        bad = [k for k, r in v["records"].items() if sha256(r["text"].encode("utf-8")) != r["digest"]]
    elif kind == "chain_links":
        head = None
        for i, k in enumerate(("R0", "R1", "R2", "D2")):
            head = next_link(head, v["records"][k]["digest"])
            if head != v["chain"]["links"][f"L{i}"]:
                bad.append(f"L{i}")
    elif kind == "entry_signed_bytes":
        # The bytes an entry's signature signs, rebuilt by the signatures rule from the export entry alone.
        for name, i in c["entries"].items():
            e = v["exports"][c["export"]]["entries"][i]
            if sig.seal_signed_bytes(seal_assertion(e)).hex() != v["entry_signatures"][name]["signed_bytes_hex"]:
                bad.append(name)
            if e["signature"] != v["entry_signatures"][name]["signature"]:
                bad.append(f"{name}: the export's member")
    elif kind == "signatures_vectors_agree":
        theirs = strict_json((ROOT / "extensions" / "signatures" / "tests" / "vectors.json").read_bytes())
        for name, vector in c["seals"].items():
            mine, seal = v["entry_signatures"][name], theirs["organisation_seals"][vector]
            if (mine["signature"]["value_b64"], mine["signed_bytes_hex"], mine["signature"]["sealed_at"]) != (
                    seal["assertion"]["signature"]["value_b64"], seal["signed_bytes_hex"], seal["assertion"]["sealed_at"]):
                bad.append(f"{name} is not {vector}")
        if v["trust_policy"] != theirs["trust_policy"]:
            bad.append("the trust policy is not the signatures vectors' policy")
        if v["exports"]["unsigned"]["entries"] != theirs["exports"]["full"]["entries"]:
            bad.append("the unsigned export's entries are not the signatures vectors' full export's")
    elif kind == "test_keys":
        g = load_generator()
        for name, k in v["test_keys"].items():
            if k["algorithm"] == "Ed25519":
                public = g.sg.raw_public(g.sg.ed25519_key(k["seed_text"])).hex()
            else:
                public = g.sg.point_public(g.sg.p256_key(k["seed_text"])).hex()
            if public != k["public_key_hex"]:
                bad.append(name)
    elif kind == "token_imprints":
        from asn1crypto import cms, tsp
        for n, t in v["tokens"].items():
            encap = cms.ContentInfo.load(b64decode(t["token_b64"]))["content"]["encap_content_info"]
            mi = tsp.TSTInfo.load(encap["content"].contents)["message_imprint"]
            if mi["hashed_message"].native != hashlib.sha256(bytes.fromhex(t["imprint_of_hex"])).digest():
                bad.append(n)
    elif kind == "export_seal_digest":
        for name, export in c["seals"].items():
            if v["export_seals"][name]["assertion"]["sealed"]["digest"] != sha256(compact(v["exports"][export])):
                bad.append(name)
    elif kind == "base_report":
        base = v["base_context"]
        made = reference(reference_report, v["exports"][base["export"]], v["signatures_attachments"][base["attachment"]],
                         v["trust_policy"])
        if made != v["base_report"]:
            differing = [k for k in set(made) | set(v["base_report"]) if made.get(k) != v["base_report"].get(k)]
            bad.append("the reference report of the base export is not base_report: " + ", ".join(sorted(differing)))
    elif kind == "duplicate_member":
        # Covered bytes naming a member twice, sealed as written: not read; a reader keeping the last member reads
        # one record, one keeping the first reads another, and only the issuer can write that.
        raw = v["records"][c["record"]]["text"].encode("utf-8")
        try:
            strict_json(raw)
            bad.append("read a document that names a member twice")
        except ValueError:
            pass
        last = json.loads(raw)  # json.loads keeps the last member
        first = json.loads(raw, object_pairs_hook=lambda items: dict(reversed(items)))  # keeps the first member
        if last.get(c["member"]) != c["last"] or first.get(c["member"]) != c["first"]:
            bad.append("the last-member and first-member readings")
        if sha256(raw) != v["records"][c["record"]]["digest"]:
            bad.append("the digest")
    elif kind == "reproduction":
        if load_generator().render() != (HERE / "vectors.json").read_bytes():
            bad.append("vectors.json is not what generate_vectors.py writes")
    else:
        raise ValueError(f"unknown check {kind!r}")
    return ("mismatch" if bad else "match"), ", ".join(bad)


def digest_case(c, v):
    recs = {k: {"text": r["text"], "seal_hash": r["digest"]} for k, r in v["records"].items()}
    kind = c["check"]
    if kind == "base_export":
        problems = []
        for i, (e, k) in enumerate(zip(v["exports"]["signed"]["entries"], ("R0", "R1", "R2"))):
            raw = base64.b64decode(e["content"]["covered_bytes_b64"], validate=True)
            if raw != recs[k]["text"].encode("utf-8"):
                problems.append(f"entry {i}: bytes")
            if sha256(raw) != e["seal"]["seal_hash"]:
                problems.append(f"entry {i}: seal")
            if e["chain"]["previous_link"] != (v["chain"]["links"][f"L{i - 1}"] if i else None):
                problems.append(f"entry {i}: previous_link")
        return ("mismatch" if problems else "match"), "; ".join(problems)
    if kind == "derived_digest":
        d, o = recs["D2"], recs["R2"]
        same_value = strict_json(d["text"].encode("utf-8")) == strict_json(o["text"].encode("utf-8"))
        return ("match" if same_value and d["text"] != o["text"] and sha256(d["text"].encode()) == d["seal_hash"]
                and d["seal_hash"] != o["seal_hash"] else "mismatch"), "equal as JSON: yes"
    rec = recs[c["record"]]
    text, note = rec["text"], ""
    if "edit" in c:
        found = text.count(c["edit"]["replace"])
        if found != 1:
            raise ValueError(f"the edit must match once; it matches {found} times")
        text = text.replace(c["edit"]["replace"], c["edit"]["with"])
    if "reserialise" in c:
        value = strict_json(text.encode("utf-8"))
        text = json.dumps(value, indent=2) if c["reserialise"] == "indent_2" else json.dumps(
            value, sort_keys=True, separators=(",", ":"))
        if strict_json(text.encode("utf-8")) != strict_json(rec["text"].encode("utf-8")) or text == rec["text"]:
            raise ValueError("the copy must be equal as JSON and differ in bytes")
        note = "equal as JSON: yes"
    if kind == "seal":
        return ("match" if sha256(text.encode()) == rec["seal_hash"] else "mismatch"), note
    if kind == "reseal":
        # Whoever changed the record also replaces the seal in the export with one over the new bytes.
        new_seal = sha256(text.encode())
        return {"same_export_seal": "match", "original_seal": "match" if new_seal == rec["seal_hash"] else "mismatch"}, ""
    if kind == "zeroed_seal":
        if text.count(ZEROED) != 1:
            raise ValueError("the record must carry one zeroed seal_hash")
        stored = text.replace(ZEROED, '"seal_hash":"' + rec["seal_hash"] + '"')
        hashed = stored.replace('"seal_hash":"' + rec["seal_hash"] + '"', ZEROED) if c["hash_as"] == "zeroed" else stored
        return ("match" if sha256(hashed.encode()) == rec["seal_hash"] else "mismatch"), ""
    raise ValueError(f"unknown check {kind!r}")


def chain_case(c, v):
    order = ("R0", "R1", "R2", "D2")
    links = [v["chain"]["links"][f"L{i}"] for i in range(4)]
    # Each supplied entry keeps the digest and the previous link it was exported with.
    entries = [(v["records"][order[i]]["digest"], links[i - 1] if i else None) for i in c["supplied"]]
    head = None
    for digest, previous_link in entries:
        if previous_link != head:
            return "inconsistent", ""
        head = next_link(head, digest)
    cp = c["checkpoint"]
    if cp is None or cp["source"] != "independent":
        return "consistent", "completeness not established"
    if (cp["count"], cp["head_link"]) == (len(entries), head):
        return "consistent_with_checkpoint", ""
    return "inconsistent_with_checkpoint", ""


def statement_case(c, v, validators):
    export = sig.apply_patch(v["exports"][c.get("export", "signed")], c.get("patch", []), v)
    entry = export["entries"][c["entry"]]
    if "bytes_from" in c:
        entry["content"]["covered_bytes_b64"] = base64.b64encode(v["records"][c["bytes_from"]]["text"].encode()).decode()
    if errors(validators["export"], export):
        return "error", "the export must be schema-valid for this case: " + errors(validators["export"], export)[0]
    status, findings = statement_check(entry)
    seal = seal_digest_check(entry)["status"]
    return {"statements": status, "seal": {"verified": "match", "failed": "mismatch"}.get(seal, seal)}, "; ".join(findings)


def signature_case(c, v, validators):
    export, attachment, policy = context_for(c, v, validators)
    report = reference(reference_report, export, attachment, policy)
    r = report["entries"][c["entry"]]
    s = r["cryptographic_verification"]["signature"]
    summary = {"policy": report["trust_policy"]["status"], "status": s["status"],
               "key_state": s.get("key_state", {}).get("status", "not_checked"),
               "time_assurance": r["time_assurance"]["status"]}
    if s.get("key_state", {}).get("status") == "verified":
        summary["time_basis"] = s["key_state"]["time_basis"]
    for k in ("holder", "certificate"):
        if k in c["expected"]:
            summary[k] = s.get(k)
    if "no_later_than" in c["expected"]:
        summary["no_later_than"] = r["time_assurance"].get("no_later_than")
    if "seal_digest" in c["expected"]:
        summary["seal_digest"] = r["cryptographic_verification"]["seal_digest"]["status"]
    detail = s.get("findings", []) + s.get("key_state", {}).get("findings", []) + r["time_assurance"].get("findings", [])
    return summary, "; ".join(detail)


def expected_signature(c):
    full = {"policy": "verified", "status": "verified", "key_state": "verified", "time_assurance": "not_checked",
            "time_basis": "stated_time"}
    full.update(c["expected"])
    if full["key_state"] != "verified":
        full.pop("time_basis", None)
    return full


def export_seal_case(c, v, validators):
    export, attachment, policy = context_for(c, v, validators)
    report = reference(reference_report, export, attachment, policy)
    s = report.get("export_seal")
    if s is None:
        return {"status": "none"}, "no seal of kind export beside the export"
    summary = {"policy": report["trust_policy"]["status"], **{d: (s[d] if d == "status" else s[d]["status"])
                                                             for d in SEAL_DIMENSIONS}}
    if s["key_state"]["status"] == "verified":
        summary["time_basis"] = s["key_state"]["time_basis"]
    if "holder" in c["expected"]:
        summary["holder"] = s.get("holder")
    detail = [f"{d}: {f}" for d in SEAL_DIMENSIONS[1:] for f in s[d].get("findings", [])] + s.get("findings", [])
    return summary, "; ".join(detail)


def expected_seal(c):
    if c["expected"].get("status") == "none":  # no seal of kind export beside the export
        return {"status": "none"}
    full = {"policy": "verified", **{d: "verified" for d in SEAL_DIMENSIONS}, "time_basis": "stated_time"}
    full.update(c["expected"])
    if full["key_state"] != "verified":
        full.pop("time_basis", None)
    return full


def pairing_case(c, v, validators):
    export, attachment, policy = context_for(c, v, validators)
    digests = {"export": sha256(compact(export))}
    if attachment is not None:
        digests["attachment"] = sha256(compact(attachment))
    report = sig.apply_patch(v["base_report"], c.get("report_patch", []), v, digests)
    if errors(validators["report"], report):
        return "error", "the report must be schema-valid for this case: " + errors(validators["report"], report)[0]
    problems = reference(read_with_export, report, export, attachment, policy)
    return ("inconsistent" if problems else "consistent"), "; ".join(problems)


def main():
    sys.stdout.reconfigure(errors="backslashreplace")
    # Every document this check reads, its fixtures included, is read with duplicate members rejected (I-JSON).
    cases = strict_json((HERE / "cases.json").read_bytes())
    v = strict_json((HERE / "vectors.json").read_bytes())
    validators = {}
    for name, p in SCHEMAS.items():
        schema = strict_json(p.read_bytes())
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)
        print(f"[ok  ] schemas/{p.name}: valid JSON Schema 2020-12")
    for name, p in OTHER_SCHEMAS.items():
        validators[name] = Draft202012Validator(strict_json(p.read_bytes()))
    print(f"[ok  ] the trust policy is anchoring's, the attachment beside the export is signatures': "
          f"{OTHER_SCHEMAS['trust_policy'].relative_to(ROOT).as_posix()}, "
          f"{OTHER_SCHEMAS['sig_attachment'].relative_to(ROOT).as_posix()}")
    print(f"[ok  ] the signature, key state, timestamp and seal checks are signatures 0.2.0's: "
          f"{SIGNATURES_RUNNER.relative_to(ROOT).as_posix()}")

    same = lambda c: c["expected"]  # noqa: E731
    groups = [
        ("schema", cases["schema_cases"], lambda c: schema_case(c, v, validators), same),
        ("vector", cases["vector_cases"], lambda c: vector_case(c, v), same),
        ("digest", cases["digest_cases"], lambda c: digest_case(c, v), same),
        ("chain", cases["chain_cases"], lambda c: chain_case(c, v), same),
        ("statement", cases["statement_cases"], lambda c: statement_case(c, v, validators), same),
        ("signature", cases["signature_cases"], lambda c: signature_case(c, v, validators), expected_signature),
        ("export seal", cases["export_seal_cases"], lambda c: export_seal_case(c, v, validators), expected_seal),
        ("pairing", cases["pairing_cases"], lambda c: pairing_case(c, v, validators), same),
    ]
    failed, total, limits = [], 0, []
    for group, group_cases, run, expect in groups:
        print(f"\n{group} cases:")
        for c in group_cases:
            total += 1
            try:
                got, detail = run(c)
            except Raised as exc:  # the reference check stopped on schema-valid input: the case fails
                got, detail = "raised", str(exc)
            except Exception as exc:  # a malformed case fails, it does not stop the run
                got, detail = "error", f"{type(exc).__name__}: {exc}"
            want = expect(c)
            ok = got == want and want not in ("error", "raised")
            label = c.get("schema", group)
            print(f"[{'ok' if ok else 'FAIL':4}] {c['id']:4} {label:11} {c['description']}")
            if not ok:
                failed.append(c["id"])
                shown = "; ".join(detail[:2]) if isinstance(detail, list) else detail
                if isinstance(got, dict) and isinstance(want, dict):
                    got = {k: x for k, x in got.items() if want.get(k) != x}
                print(f"         expected {c['expected']}, got {got}" + (f": {shown[:300]}" if shown else ""))
            if c.get("limitation"):
                limits.append((c["id"], c["limitation"]))

    print("\nLimitations these cases show (they pass by design):")
    for cid, text in limits:
        print(f"  {cid}: {text}")
    if failed:
        print(f"\nFAIL: {len(failed)} of {total} case(s) do not behave as expected: {', '.join(failed)}")
        return 1
    print(f"\nPASS: all {total} cases behave as expected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
