# SPDX-License-Identifier: Apache-2.0
"""Checks for the action binding extension, version 0.3.0 (a proposal).

Runs the cases in cases.json over the values in vectors.json, which generate_vectors.py writes:

  schema cases     an attachment from vectors.json or the base report, changed by a patch, against the extension's
                   schemas; and the fixture records against the core decision-record schema
  vector cases     the values in vectors.json recomputed: SHA-256, the signed bytes of each copy of the seal rebuilt
                   from the attachment alone, the test keys from their seed texts, the tokens' imprints, the seals'
                   digests, the agreement with the signatures vectors, the reference report, vectors.json itself, and
                   the texts that name a member twice
  digest cases     SHA-256 over exact bytes: action specifications (changes and re-serialisation), and the seal of
                   the affirmed fixture record
  binding cases    the reference check of one attachment's stages, with or without its decision record
  signature cases  the reference check of one attachment's issuer signature: the copy of the signatures 0.2.0
                   organisation seal of kind attachment, with the key the trust policy gives, its state when it
                   signed, and the independent timestamps over its value from the signatures attachment read beside
  pairing cases    a report read with its attachments, the records, the attachment beside and the policy: one result
                   per attachment and per decision record, the attachment's digest, one result per specification,
                   review and attempt, and nothing reported as verified that is not (JSON Schema cannot compare two
                   documents)

In these cases, an attachment's bytes as received are its JSON text as the runner writes it: UTF-8, no whitespace,
members in the order given (json.dumps with separators (",", ":") and ensure_ascii False), except the texts in
vectors.json, read as written. Times are the issuer's, compared as instants.

The reference check of a signature, of a key's state and of a timestamp is the signatures extension's own reference
check, loaded from extensions/signatures/tests/run_checks.py, so that the two cannot drift: an attachment's copy is
that profile's seal, and this check builds the seal from the attachment and hands it over. Standard library,
jsonschema, and the signatures runner's requirements (cryptography, asn1crypto). Every document is read with
duplicate members rejected.

Usage:  python extensions/action-binding/tests/run_checks.py
Exit code 0 = every case behaves as expected, 1 = a case does not.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
from datetime import datetime

from jsonschema import Draft202012Validator

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCHEMAS = {
    "attachment": HERE.parent / "schemas" / "execution-evidence.schema.json",
    "report": HERE.parent / "schemas" / "verification-report.schema.json",
}
OTHER_SCHEMAS = {
    "core_record": ROOT / "standard" / "v5.0" / "schemas" / "decision-record.schema.json",
    # The trust policy is anchoring 0.2.0's; the attachment read beside is signatures 0.2.0's.
    "trust_policy": ROOT / "extensions" / "anchoring" / "schemas" / "trust-policy.schema.json",
    "sig_attachment": ROOT / "extensions" / "signatures" / "schemas" / "signatures-attachment.schema.json",
}
SIGNATURES_RUNNER = ROOT / "extensions" / "signatures" / "tests" / "run_checks.py"
PROFILE, VERSION = "dps-action-binding", "0.3.0"
SIGNATURES_PROFILE, SIGNATURES_VERSION = "dps-signatures", "0.2.0"
SIGNED_BYTES_REF = f"{SIGNATURES_PROFILE} {SIGNATURES_VERSION} organisation_seal"
READABLE = {"application/json"}  # media types the reference statement checks read
SPEC_MEMBERS = ("operation", "target", "parameters", "input_version_refs", "policy_version")
SUMMARY_MEMBERS = ("operation", "target", "policy_version", "input_version_refs")
KNOWN_OUTCOMES = {"approved", "rejected", "escalated"}  # review_log.outcome words this check reads
DIMENSIONS = (
    "specification_digests", "specification_statements", "record_statements", "action_binding",
    "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance",
)
CARRIED = ("observed", "executed", "reviews")  # compared in a binding case only when it lists them
RANK = {"verified": 0, "not_checked": 1, "unavailable": 2, "failed": 3}
REFS = ("proposal_ref", "review_ref", "from_ref", "authorised_by", "request_ref", "recheck_ref", "attempt_ref")
ZEROED = '"seal_hash":"' + "0" * 64 + '"'
NOT_ASSESSED = ["legal_requirements", "conformance_level", "events_not_in_attachment", "truth_of_recorded_claims",
                "what_the_reviewer_saw"]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sig = load_module("signatures_run_checks", SIGNATURES_RUNNER)  # the signatures 0.2.0 reference check
strict_json, b64decode = sig.strict_json, sig.b64decode


class Raised(Exception):
    """The reference check raised on schema-valid input: the case fails, the run goes on."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def when(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def same_instant(a, b):
    """True or False for two times compared as instants; None when one cannot be read as an instant (not a
    time, or a time with no offset)."""
    try:
        x, y = when(a), when(b)
    except (AttributeError, TypeError, ValueError):
        return None
    if x.tzinfo is None or y.tzinfo is None:
        return None
    return x == y


def attachment_bytes(att):
    """The attachment's bytes as received, by the convention of these cases (see the docstring)."""
    return json.dumps(att, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def errors(validator, doc):
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message[:100]}"
            for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))]


# ---------------------------------------------------------------- the stages (as in 0.2.0)

def check_specification(spec):
    """One specification: its bytes against its digest, and its summary (outside the digest) against its bytes."""
    if spec["content"]["availability"] != "available":
        return ("unavailable", ["the bytes are unavailable"]), ("not_checked", ["the bytes are unavailable"])
    raw = base64.b64decode(spec["content"]["bytes_b64"], validate=True)
    digest = ("verified", []) if sha256(raw) == spec["spec_digest"] else ("failed", ["the bytes do not match spec_digest"])
    if spec["representation"]["media_type"] not in READABLE:
        return digest, ("not_checked", ["this check cannot read the media type"])
    try:
        body = strict_json(raw)
    except ValueError as exc:
        return digest, ("not_checked", [f"the bytes cannot be read: {exc}"])
    if not isinstance(body, dict):
        return digest, ("not_checked", ["the bytes are not a JSON object"])
    wrong = [m for m in SPEC_MEMBERS if m not in body]
    wrong += [m for m in SUMMARY_MEMBERS if m in body and body[m] != spec["summary"][m]]
    if wrong:
        return digest, ("failed", ["the summary does not match the bytes: " + ", ".join(wrong)])
    return digest, ("verified", [])


def check_record(att, record_raw):
    """The stages' statements about core fields, against the decision record the verifier holds.

    Verified only when every approval is backed by a core field and every backed statement matches. A matching
    decision_id shows consistency only: a verifier usually finds the record by that same id."""
    unbacked = [f"{s['stage_id']}: no core field backs this approval; the record does not show it"
                for s in att["stages"] if s["kind"] == "outcome" and s["outcome"] == "approved" and "core_ref" not in s]
    if record_raw is None:
        return "not_checked", ["the decision record was not supplied"] + unbacked
    try:
        record = strict_json(record_raw)
    except ValueError as exc:
        return "not_checked", [f"the record cannot be read: {exc}"] + unbacked
    if not isinstance(record, dict):
        return "not_checked", ["the record is not a JSON object"] + unbacked
    wrong, unread = [], list(unbacked)
    if record.get("decision_id") != att["decision_id"]:
        wrong.append("decision_id")
    for s in att["stages"]:
        if s["kind"] == "proposal" and s["origin"] == "ai":
            if (record.get("drafting_authority") or {}).get("deployer_role_pointer") != s["deployer_role_pointer"]:
                wrong.append(f"{s['stage_id']}: drafting_authority")
        if s["kind"] != "outcome" or "core_ref" not in s:
            continue
        ref = s["core_ref"]
        if ref["field"] == "affirmation_record":
            a = record.get("affirmation_record") or {}
            pairs = [("actor_identity", "actor_ref"), ("timestamp", "at"), ("method", "method")]
        else:
            log, i = record.get("review_log") or [], ref["index"]
            if not isinstance(i, int) or isinstance(i, bool):  # JSON Schema accepts 0.0 as an integer
                unread.append(f"{s['stage_id']}: review_log index {i!r} is not written as an integer")
                continue
            a = log[i] if i < len(log) else {}
            pairs = [("reviewer", "actor_ref"), ("reviewed_at", "at"), ("outcome", "outcome")]
        for core_key, stage_key in pairs:
            name = f"{s['stage_id']}: {ref['field']}.{core_key}"
            value = a.get(core_key)
            if value is None:
                wrong.append(name)
            elif core_key in ("timestamp", "reviewed_at"):
                same = same_instant(value, s[stage_key])
                if same is None:
                    unread.append(f"{name}: the time cannot be read as an instant")
                elif not same:
                    wrong.append(name)
            elif core_key == "outcome" and value not in KNOWN_OUTCOMES:
                unread.append(f"{name}: {value!r} is not a word this check knows")
            elif value != s[stage_key]:
                wrong.append(name)
    if wrong:
        return "failed", ["does not match the decision record: " + ", ".join(wrong)] + unread
    if unread:
        return "not_checked", unread
    return "verified", []


def check_attachment(att, record_raw=None):
    """Reference check of one schema-valid attachment's stages. Every dimension is reported on its own."""
    stages = att["stages"]
    pos, by_id, dupes = {}, {}, []
    for i, s in enumerate(stages):
        if s["stage_id"] in by_id:
            dupes.append(s["stage_id"])
            continue
        pos[s["stage_id"]], by_id[s["stage_id"]] = i, s
    kinds = {k: [s for s in stages if s["kind"] == k] for k in
             ("proposal", "review", "outcome", "change_authorisation", "request", "recheck", "attempt", "result")}
    out = {}

    # Specifications: each digest, and each summary, on its own; the dimension keeps the worst status.
    per_spec = [check_specification(spec) for spec in att["action_specifications"]]
    for n, dim in enumerate(("specification_digests", "specification_statements")):
        results = [r[n] for r in per_spec]
        status = max((r[0] for r in results), key=RANK.get)
        out[dim] = (status, [f"specification {i}: {f}" for i, r in enumerate(results) for f in r[1]])
    out["record_statements"] = check_record(att, record_raw)

    # Binding: what was shown, approved, requested and attempted is the same specification.
    bad = []
    carried = {spec["spec_digest"] for spec in att["action_specifications"]}
    for s in stages:
        for key in ("spec_digest", "shown_spec_digest", "approved_spec_digest"):
            if key in s and s[key] not in carried:
                bad.append(f"{s['stage_id']}: names a specification the attachment does not carry")

    def ref(s, key, kind):
        target = by_id.get(s[key])
        if target is None or target["kind"] not in kind:
            bad.append(f"{s['stage_id']}: {key} names no {' or '.join(kind)} stage")
            return None
        return target

    # A review shown something other than its proposal is reported, not failed; whoever edited it is the author
    # of that change, and the review names them.
    reviews = []
    for s in kinds["review"]:
        shown, editor = "proposal_not_named", None
        if "proposal_ref" in s:
            proposal = ref(s, "proposal_ref", ("proposal",))
            if proposal and proposal["spec_digest"] == s["shown_spec_digest"]:
                shown = "as_proposed"
            elif proposal:
                shown, editor = "differs_from_proposal", s.get("edited_by")
                if editor is None:
                    bad.append(f"{s['stage_id']}: shown something other than {proposal['stage_id']} proposed, and does "
                               "not name who edited it")
        reviews.append([s["stage_id"], shown, editor])
    out["reviews"] = reviews
    index = {}
    for i, spec in enumerate(att["action_specifications"]):
        index.setdefault(spec["spec_digest"], i)

    bound = {}  # stage id of an approval or authorised change -> (digest it binds, request limit)
    answered, backing, shown_approved, refused = {}, {}, set(), {}
    for s in kinds["outcome"]:
        review = ref(s, "review_ref", ("review",))
        if s["review_ref"] in answered:
            bad.append(f"{s['stage_id']}: {s['review_ref']} already has an outcome ({answered[s['review_ref']]}); "
                       "a review has one outcome")
        answered.setdefault(s["review_ref"], s["stage_id"])
        if "core_ref" in s:
            field = (s["core_ref"]["field"], s["core_ref"].get("index"))
            if field in backing:
                bad.append(f"{s['stage_id']}: {s['core_ref']['field']} already backs {backing[field]}; "
                           "a core field backs at most one outcome")
            backing.setdefault(field, s["stage_id"])
        if review and s["actor_ref"] != review["reviewer_ref"]:
            bad.append(f"{s['stage_id']}: the outcome is not given by the person shown the specification")
        if s["outcome"] != "approved" and review:
            refused.setdefault(review["shown_spec_digest"], (s["stage_id"], s["outcome"]))
        if s["outcome"] == "approved":
            if review and s["approved_spec_digest"] != review["shown_spec_digest"]:
                bad.append(f"{s['stage_id']}: the approved specification differs from the one shown")
            elif review:
                shown_approved.add(s["approved_spec_digest"])
            bound[s["stage_id"]] = (s["approved_spec_digest"], s.get("request_limit", 1))
    # A change is authorised by a named person: never the proposer, nor a service named in the attachment.
    machine = {p.get(k) for p in kinds["proposal"] for k in ("deployer_role_pointer", "system_name", "actor_ref")}
    machine |= {q["requested_by"] for q in kinds["request"]} | {x["executor_ref"] for x in kinds["attempt"]}
    machine.discard(None)
    changed, users = set(), {}  # users: approval or change -> the changes and requests that use it, in order

    def use(s, auth_id):
        limit = bound[auth_id][1]
        users.setdefault(auth_id, []).append(s["stage_id"])
        if len(users[auth_id]) > limit:
            bad.append(f"{s['stage_id']}: {auth_id} covers {limit} request(s), already used by "
                       f"{', '.join(users[auth_id][:-1])}")

    for s in kinds["change_authorisation"]:
        if s["actor_ref"] in machine:
            bad.append(f"{s['stage_id']}: authorised by {s['actor_ref']}, which proposed, requested or executes "
                       "the action; a change is authorised by a named person")
        if s["spec_digest"] in refused:
            bad.append(f"{s['stage_id']}: reaches a specification that {refused[s['spec_digest']][0]} "
                       f"{refused[s['spec_digest']][1]}; overriding that needs a new review")
        source = ref(s, "from_ref", ("outcome", "change_authorisation"))
        if source is None:
            continue
        if source["stage_id"] not in bound:
            bad.append(f"{s['stage_id']}: changes an outcome that is not an approval")
            continue
        if s["spec_digest"] == bound[source["stage_id"]][0]:
            bad.append(f"{s['stage_id']}: names the specification it changes; a change names a different one")
        use(s, source["stage_id"])  # a change uses up one request of what it changes
        bound[s["stage_id"]] = (s["spec_digest"], s.get("request_limit", 1))
        changed.add(s["spec_digest"])
    seen_ids = set()
    for s in kinds["request"]:
        if s["request_id"] in seen_ids:
            bad.append(f"{s['stage_id']}: duplicate request_id {s['request_id']!r}")
        seen_ids.add(s["request_id"])
        auth = ref(s, "authorised_by", ("outcome", "change_authorisation"))
        if auth is None:
            continue
        if auth["stage_id"] not in bound:
            bad.append(f"{s['stage_id']}: rests on {auth['stage_id']} ({auth.get('outcome', 'unbound change')}); only "
                       "an approval or an authorised change authorises a request")
            continue
        use(s, auth["stage_id"])
        if s["spec_digest"] != bound[auth["stage_id"]][0]:
            bad.append(f"{s['stage_id']}: the requested specification differs from the one approved")
    # However many approvals and changes bind a specification, its requests number at most the largest limit.
    for d in dict.fromkeys(q["spec_digest"] for q in kinds["request"]):
        limits = [limit for digest, limit in bound.values() if digest == d]
        count = sum(q["spec_digest"] == d for q in kinds["request"])
        if limits and count > max(limits):
            bad.append(f"specification {index.get(d)}: requested {count} times; the most any approval or change "
                       f"of it covers is {max(limits)}")
    for s in kinds["attempt"]:
        request = ref(s, "request_ref", ("request",))
        if request and s["spec_digest"] != request["spec_digest"]:
            bad.append(f"{s['stage_id']}: the attempted specification differs from the one requested")
    out["action_binding"] = ("failed", bad) if bad else ("verified", [])

    # Each executed specification: shown to a reviewer and approved, or reached only through a change.
    executed = []
    for s in kinds["attempt"]:
        i = index.get(s["spec_digest"])
        if i is None or any(e[0] == i for e in executed):
            continue
        reached = ("shown_to_reviewer" if s["spec_digest"] in shown_approved else
                   "via_change_only" if s["spec_digest"] in changed else "unbound")
        executed.append([i, reached])
    out["executed"] = executed

    # Order: each stage comes after the stages it names, in the list and in the issuer's times.
    bad = [f"stage_id {d!r} is used more than once" for d in dupes]
    for s in stages:
        for key in REFS:
            target = by_id.get(s.get(key))
            if target is None or s["stage_id"] in dupes:
                continue
            if pos[target["stage_id"]] > pos.get(s["stage_id"], -1):
                bad.append(f"{s['stage_id']} is listed before {target['stage_id']}, which it names")
            elif when(target["at"]) > when(s["at"]):
                bad.append(f"{s['stage_id']} is dated before {target['stage_id']}, which it names")
    out["stage_order"] = ("failed", bad) if bad else ("verified", [])

    # Recheck: the latest recheck of the request before each attempt authorises it, and serves only it.
    bad, used = [], {}
    for s in kinds["attempt"]:
        rc = by_id.get(s["recheck_ref"])
        if rc is None or rc["kind"] != "recheck" or rc["request_ref"] != s["request_ref"]:
            bad.append(f"{s['stage_id']}: no recheck of its request is recorded")
            continue
        if pos[rc["stage_id"]] > pos[s["stage_id"]] or when(rc["at"]) > when(s["at"]):
            bad.append(f"{s['stage_id']}: the recheck comes after the attempt")
        if rc["result"] != "authorised":
            bad.append(f"{s['stage_id']}: attempted after a recheck that found {rc['result']}")
        later = [r for r in kinds["recheck"] if r["request_ref"] == s["request_ref"]
                 and pos[rc["stage_id"]] < pos.get(r["stage_id"], -1) < pos[s["stage_id"]]]
        if any(r["result"] != "authorised" for r in later):
            bad.append(f"{s['stage_id']}: a later recheck before the attempt did not authorise it")
        if rc["stage_id"] in used:
            bad.append(f"{s['stage_id']}: reuses the recheck of {used[rc['stage_id']]}")
        used[rc["stage_id"]] = s["stage_id"]
    if bad:
        out["authorisation_recheck"] = ("failed", bad)
    elif kinds["attempt"] or kinds["recheck"]:
        out["authorisation_recheck"] = ("verified", [])
    else:
        out["authorisation_recheck"] = ("not_checked", ["no recheck or attempt is recorded"])

    # Results: exactly one observed result for each attempt, carried through with its basis as recorded.
    bad, observed = [], []
    attempt_ids = {s["stage_id"] for s in kinds["attempt"]}
    for r in kinds["result"]:
        if r["attempt_ref"] not in attempt_ids:
            bad.append(f"{r['stage_id']}: names no attempt")
    for s in kinds["attempt"]:
        found = [r for r in kinds["result"] if r["attempt_ref"] == s["stage_id"]]
        if len(found) == 1:
            observed.append([s["stage_id"], found[0]["observed"], found[0]["basis"]])
            continue
        value = "missing" if not found else "multiple"
        bad.append(f"{s['stage_id']}: {'no' if value == 'missing' else 'more than one'} observed result")
        observed.append([s["stage_id"], value, None])
    if bad:
        out["observed_results"] = ("failed", bad)
    elif kinds["attempt"]:
        out["observed_results"] = ("verified", [])
    else:
        out["observed_results"] = ("not_checked", ["no execution attempt is recorded"])
    out["execution_state"] = ("attempted" if kinds["attempt"] else
                              "requested_not_attempted" if kinds["request"] else "not_requested")
    out["observed"] = observed

    # Rationale: a rationale recorded after its outcome is never presented as contemporaneous.
    bad = []
    for s in kinds["outcome"] + kinds["change_authorisation"]:
        r = s["rationale"]
        if r["timing"] == "contemporaneous" and when(r["recorded_at"]) > when(s["at"]):
            bad.append(f"{s['stage_id']}: recorded after the outcome, presented as contemporaneous")
        if r["timing"] == "later_supplemented" and when(r["recorded_at"]) <= when(s["at"]):
            bad.append(f"{s['stage_id']}: said to be supplemented later, but dated with the outcome")
    out["rationale_provenance"] = ("failed", bad) if bad else ("verified", [])
    out["per_spec"] = per_spec
    return out


# ---------------------------------------------------------------- the issuer signature (signatures 0.2.0, by reference)

def bytes_for_seal(att):
    """The attachment's bytes as received with every character of the copy's value replaced by A: what the seal of
    kind attachment digests, as the signatures profile has it."""
    att = copy.deepcopy(att)
    att["issuer_signature"]["value_b64"] = "A" * len(att["issuer_signature"]["value_b64"])
    return attachment_bytes(att)


def seal_assertion(att, raw=None):
    """The attachment's copy as the signatures profile's organisation seal of kind attachment, built from the
    attachment itself: its decision_id, the digest of its bytes with the value replaced, the copy's sealed_at. Only
    the key reference, the time and the value are taken from the copy. raw, when given, is the attachment's writing
    as received, used for the digest instead of the compact writing."""
    s = att["issuer_signature"]
    digest = sha256(raw if raw is not None else bytes_for_seal(att))
    return {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION, "assertion": "organisation_seal",
            "sealed": {"kind": "attachment", "id": att["decision_id"], "digest": digest},
            "sealed_at": s["sealed_at"], "signature": {"algorithm": s["algorithm"], "key_ref": s["key_ref"],
                                                       "value_b64": s["value_b64"]}}


def held_assertions(attachments, beside):
    """Where a timestamp's signature value is looked for: the attachments' copies, as seals, and the attachment
    beside's own assertions."""
    held = [seal_assertion(a) for a in attachments if "issuer_signature" in a]
    if beside:
        held += beside.get("organisation_seals", []) + beside.get("person_signatures", [])
    return held


def policy_key(policy, key_ref):
    return next((k for k in policy["keys"] if k["key_ref"] == key_ref), None)


def latest_stage_time(att):
    """The latest of the issuer's stage times, as an instant, or None where one cannot be read."""
    try:
        return max(when(s["at"]) for s in att["stages"])
    except (ValueError, TypeError, KeyError):
        return None


def check_issuer_signature(att, policy, policy_result, ts_results):
    """The copy of the seal as one dimension: the signatures check of the seal built from the attachment (the
    signature, then the key's state when it signed), with the holder the policy gives. It attests only that the
    issuer recorded these claims."""
    if "issuer_signature" not in att:
        return {"status": "not_checked", "findings": ["the attachment carries no issuer signature"]}
    s = att["issuer_signature"]
    out = {"key_ref": s["key_ref"], "algorithm": s["algorithm"]}
    a = seal_assertion(att)
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
    out["attests"] = "issuer_recorded_claims_only"
    out["status"] = sig.combine(signature["status"], out["key_state"]["status"])
    # The copy's sealed_at is a time over the whole attachment: one earlier than the latest stage the attachment
    # records is inconsistent with the issuer's own times. A finding, not a failure of the signature.
    stated, latest = sig.instant(s["sealed_at"]), latest_stage_time(att)
    if stated is not None and latest is not None and stated < latest:
        out.setdefault("findings", []).append(f"sealed_at {s['sealed_at']} is earlier than the latest stage the "
                                              f"attachment records ({sig.iso(latest)}); both are the issuer's times")
    return out


def time_assurance(att, signature, ts_results):
    """Verified only against a verified independent timestamp over this attachment's verified issuer signature."""
    if "issuer_signature" not in att:
        return {"status": "not_checked", "basis": "issuer_assertion"}
    if signature["status"] != "verified":  # the dimension, not only its signature: a failed key state counts too
        return {"status": "not_checked", "basis": "issuer_assertion",
                "findings": ["the issuer signature is not verified, so a timestamp over its value shows nothing about "
                             "this attachment; the key state reports the timestamp's time"]}
    covering = sig.covering_timestamps(b64decode(att["issuer_signature"]["value_b64"]), ts_results)
    if not covering:
        return {"status": "not_checked", "basis": "issuer_assertion",
                "findings": ["no verified independent timestamp covers the issuer signature; sealed_at is the "
                             "issuer's statement"]}
    i, r = min(covering, key=lambda c: c[1]["_upper"])
    t = r["existed_no_later_than"]
    findings = [f"the issuer signature, and so the attachment's bytes as issued, existed no later than {t} "
                f"({r['tsa_ref']}); not when any stage happened"]
    # A stage the attachment dates after the time by which its signed bytes existed: the issuer's stage times are
    # inconsistent with the timestamp. A finding, not a failure: the times are the issuer's statements.
    latest = latest_stage_time(att)
    if latest is not None and latest > r["_upper"]:
        findings.append(f"the attachment records a stage at {sig.iso(latest)}, later than {t}, by which its signed "
                        "bytes existed: the issuer's stage times are inconsistent with the timestamp")
    return {"status": "verified", "basis": "independent_source", "source_ref": r["tsa_ref"], "no_later_than": t,
            "timestamp_index": i, "findings": findings}


# ---------------------------------------------------------------- the whole set: the reference report

def with_findings(status, findings):
    out = {"status": status}
    if findings:
        out["findings"] = findings
    return out


def result_for(i, att, record_raw, policy, policy_result, ts_results):
    got = check_attachment(att, record_raw)
    signature = check_issuer_signature(att, policy, policy_result, ts_results)
    r = {"attachment_index": i, "decision_id": att["decision_id"], "attachment_digest": sha256(attachment_bytes(att)),
         "structural_validity": {"status": "verified"},
         "specifications": [{"spec_index": k, "spec_digest": spec["spec_digest"],
                             "digest": with_findings(*got["per_spec"][k][0]),
                             "statements": with_findings(*got["per_spec"][k][1])}
                            for k, spec in enumerate(att["action_specifications"])],
         "reviews": [{"review_stage_id": x[0], "shown": x[1], **({"edited_by": x[2]} if x[2] else {})}
                     for x in got["reviews"]],
         "executed_specifications": [{"spec_index": x[0], "reached_by": x[1]} for x in got["executed"]],
         "record_statements": with_findings(*got["record_statements"]),
         "action_binding": with_findings(*got["action_binding"]),
         "stage_order": {**with_findings(got["stage_order"][0], []), "time_basis": "issuer_assertion",
                         **({"findings": got["stage_order"][1]} if got["stage_order"][1] else {})},
         "authorisation_recheck": with_findings(*got["authorisation_recheck"]),
         "observed_results": {"status": got["observed_results"][0], "execution_state": got["execution_state"],
                              "attempts": [{"attempt_stage_id": x[0], "observed": x[1],
                                            **({"basis": x[2]} if x[2] else {})} for x in got["observed"]],
                              **({"findings": got["observed_results"][1]} if got["observed_results"][1] else {})},
         "rationale_provenance": with_findings(*got["rationale_provenance"]),
         "identity_assurance": {"status": "not_checked", "basis": "issuer_assertion"},
         "authority_assurance": {"status": "not_checked", "basis": "issuer_assertion"},
         "time_assurance": time_assurance(att, signature, ts_results),
         "issuer_signature": signature,
         "legal_signature": {"status": "not_checked", "basis": "issuer_assertion",
                             "findings": ["no legal signature is referenced"]}}
    return r, got


def reference_report(attachments, records, policy, beside):
    """What a verifier using this extension reports for a set of attachments read with the records it holds, the
    signatures attachment beside them and the policy. Nothing here catches an exception."""
    policy_result = sig.check_policy(policy)
    held = held_assertions(attachments, beside)
    ts_results = [sig.check_timestamp(t, policy, policy_result, held) for t in (beside or {}).get("timestamps", [])]
    results = [result_for(i, a, records.get(a["decision_id"]), policy, policy_result, ts_results)[0]
               for i, a in enumerate(attachments)]
    report = {"profile": f"{PROFILE}-report", "profile_version": VERSION, "attachment_count": len(attachments),
              "trust_policy_ref": policy["policy_ref"], "trust_policy": policy_result}
    if beside is not None:
        report["signatures_attachment_digest"] = sha256(attachment_bytes(beside))
    report["results"] = results
    report["scope_of_conclusion"] = {"covers": "supplied_attachments_only", "not_assessed": NOT_ASSESSED}
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


def read_with_attachments(report, attachments, records, policy, beside):
    """What a reader holding a report, its attachments, the records, the attachment beside and the policy checks;
    JSON Schema cannot compare two documents. A report may say less than the reference check; not more."""
    ref = reference_report(attachments, records, policy, beside)
    problems = []
    if report["attachment_count"] != len(attachments):
        problems.append(f"attachment_count is {report['attachment_count']}; there are {len(attachments)} attachments")
    if report["trust_policy_ref"] != policy["policy_ref"]:
        problems.append("trust_policy_ref is not the policy the documents are read with")
    if report["trust_policy"]["status"] != ref["trust_policy"]["status"]:
        problems.append(f"the trust policy reported {report['trust_policy']['status']}; the reference check finds "
                        f"{ref['trust_policy']['status']}")
    if report.get("signatures_attachment_digest") != ref.get("signatures_attachment_digest"):
        problems.append("signatures_attachment_digest is not the digest of the attachment read beside"
                        if beside is not None else "signatures_attachment_digest named, and nothing read beside")
    indexes = sorted(r["attachment_index"] for r in report["results"])
    if indexes != list(range(len(attachments))):
        problems.append(f"results name attachments {indexes}; each of 0 to {len(attachments) - 1} must appear once")
    for label, ids in (("results", [r["decision_id"] for r in report["results"]]),
                       ("attachments", [a["decision_id"] for a in attachments])):
        twice = sorted({d for d in ids if ids.count(d) > 1})
        if twice:
            problems.append(f"{label} name {', '.join(twice)} more than once; there is one attachment per decision record")
    for r in report["results"]:
        i = r["attachment_index"]
        if i >= len(attachments):
            continue
        a, x = attachments[i], ref["results"][i]
        if r["decision_id"] != a["decision_id"]:
            problems.append(f"result {i}: decision_id differs from the attachment's")
        if r["attachment_digest"] != x["attachment_digest"]:
            problems.append(f"result {i}: attachment_digest is not the digest of the attachment read with it")
        specs = a["action_specifications"]
        if sorted(s["spec_index"] for s in r["specifications"]) != list(range(len(specs))):
            problems.append(f"result {i}: one specification result for each of its {len(specs)} specifications")
        for s in r["specifications"]:
            k = s["spec_index"]
            if k >= len(specs):
                continue
            if s["spec_digest"] != specs[k]["spec_digest"]:
                problems.append(f"result {i}: specification {k} digest differs from the attachment's")
            for key in ("digest", "statements"):
                if s[key]["status"] == "verified" and x["specifications"][k][key]["status"] != "verified":
                    problems.append(f"result {i}: specification {k} {key} reported verified, but it is not")
        for key in ("record_statements", "action_binding", "stage_order", "authorisation_recheck",
                    "observed_results", "rationale_provenance"):
            if r[key]["status"] == "verified" and x[key]["status"] != "verified":
                problems.append(f"result {i}: {key} reported verified, but the reference check finds {x[key]['status']}")
        o, xo = r["observed_results"], x["observed_results"]
        if o["execution_state"] != xo["execution_state"]:
            problems.append(f"result {i}: execution_state is {o['execution_state']}; the attachment shows {xo['execution_state']}")
        if [[y["attempt_stage_id"], y["observed"], y.get("basis")] for y in o["attempts"]] != [
                [y["attempt_stage_id"], y["observed"], y.get("basis")] for y in xo["attempts"]]:
            problems.append(f"result {i}: observed results and their basis not carried through as recorded")
        if r["executed_specifications"] != x["executed_specifications"]:
            problems.append(f"result {i}: executed specifications not reported as they were reached")
        if r["reviews"] != x["reviews"]:
            problems.append(f"result {i}: reviews not reported as the attachment records them")
        s, xs = r["issuer_signature"], x["issuer_signature"]
        if "issuer_signature" not in a and s["status"] != "not_checked":
            problems.append(f"result {i}: the attachment carries no issuer signature; it is reported {s['status']}")
        verified_but_not(f"result {i}", s["status"], xs["status"], problems, "the issuer signature")
        if s["status"] == xs["status"] == "verified":
            if s.get("holder") != xs.get("holder") or s.get("key_ref") != xs.get("key_ref"):
                problems.append(f"result {i}: the issuer signature's key or holder is not the policy's")
            ks, xks = s["key_state"], xs["key_state"]
            if any(ks.get(k) != xks.get(k) for k in ("time_basis", "time", "timestamp_index", "revocation_reason")):
                problems.append(f"result {i}: the key state's time and its basis not reported as found")
        t, xt = r["time_assurance"], x["time_assurance"]
        verified_but_not(f"result {i}", t["status"], xt["status"], problems, "time")
        if t["status"] == xt["status"] == "verified" and any(
                t.get(k) != xt.get(k) for k in ("source_ref", "no_later_than", "timestamp_index")):
            problems.append(f"result {i}: the timestamp's authority, time or index not reported as found")
    return problems


# ---------------------------------------------------------------- the cases

def context_for(c, v, data, validators):
    """The documents a case reads: the attachments it covers, the records, the attachment beside (or none), the
    policy, each patched and schema-valid."""
    base = v["base_context"]
    names = c.get("covers", base["covers"])
    patches = c.get("attachment_patches", {})
    attachments = [sig.apply_patch(v["attachments"][n], patches.get(n, []), v) for n in names]
    digests = {f"attachment:{n}": sha256(attachment_bytes(a)) for n, a in zip(names, attachments)}
    beside_name = c.get("attachment", base["attachment"])
    beside = None
    if beside_name is not None:
        beside = sig.apply_patch(v["signatures_attachments"][beside_name], c.get("beside_patch", []), v, digests)
        digests["beside"] = sha256(attachment_bytes(beside))
    policy = sig.apply_patch(v["trust_policy"], c.get("policy_patch", []), v)
    for a in attachments:
        if errors(validators["attachment"], a):
            raise ValueError(f"the attachment must be schema-valid for this case: {errors(validators['attachment'], a)[0]}")
    if beside is not None and errors(validators["sig_attachment"], beside):
        raise ValueError("the attachment beside must be schema-valid for this case")
    if errors(validators["trust_policy"], policy):
        raise ValueError("the trust policy must be schema-valid for this case")
    held = [data["records"][n] for n in c.get("records", base["records"])]
    records = {strict_json(t.encode("utf-8"))["decision_id"]: t.encode("utf-8") for t in held}
    return attachments, records, policy, beside, digests


def schema_case(c, v, data, validators):
    if c["schema"] == "core_record":
        instance = strict_json(data["records"][c["record"]].encode("utf-8"))
    else:
        base = v["attachments"][c["base"]] if c["schema"] == "attachment" else v["base_report"]
        instance = sig.apply_patch(base, c["patch"], v)
    found = errors(validators[c["schema"]], instance)
    return ("pass" if not found else "fail"), found


def load_generator():
    return load_module("ab_generate_vectors", HERE / "generate_vectors.py")


def vector_case(c, v, data):
    kind, bad = c["check"], []
    if kind == "known_vector":
        return ("match" if sha256(c["text"].encode()) == c["digest"] else "mismatch"), ""
    elif kind == "copies_verify":
        policy_result = sig.check_policy(v["trust_policy"])
        for name in c["attachments"]:
            a = v["attachments"][name]
            r, _, _ = sig.checked_signature(seal_assertion(a), sig.seal_signed_bytes, v["trust_policy"], policy_result,
                                            "organisation", sig.SEAL_SUITES)
            if r["status"] != "verified":
                bad.append(name)
    elif kind == "signatures_vectors_agree":
        theirs = strict_json((ROOT / "extensions" / "signatures" / "tests" / "vectors.json").read_bytes())
        for name, decision in (("B0", "DR-2099-101"), ("B1", "DR-2099-102")):
            if v["attachments"][name] != theirs["action_binding_attachments"][decision]:
                bad.append(f"{name} is not the signatures vectors' attachment of {decision}")
        seal = theirs["organisation_seals"]["seal_attachment"]["assertion"]
        b0 = v["attachments"]["B0"]["issuer_signature"]
        if (b0["value_b64"], b0["sealed_at"], b0["key_ref"]) != (seal["signature"]["value_b64"], seal["sealed_at"],
                                                                seal["signature"]["key_ref"]):
            bad.append("B0's copy is not seal_attachment")
        if v["seals"]["seal_b0"]["assertion"] != seal:
            bad.append("seal_b0 is not seal_attachment")
        if v["trust_policy"] != theirs["trust_policy"]:
            bad.append("the trust policy is not the signatures vectors' policy")
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
    elif kind == "seal_digests":
        for name, att in c["seals"].items():
            if v["seals"][name]["assertion"]["sealed"]["digest"] != sha256(bytes_for_seal(v["attachments"][att])):
                bad.append(name)
    elif kind == "base_report":
        base = v["base_context"]
        records = {strict_json(data["records"][n].encode("utf-8"))["decision_id"]: data["records"][n].encode("utf-8")
                   for n in base["records"]}
        made = reference(reference_report, [v["attachments"][n] for n in base["covers"]], records, v["trust_policy"],
                         v["signatures_attachments"][base["attachment"]])
        if made != v["base_report"]:
            differing = [k for k in set(made) | set(v["base_report"]) if made.get(k) != v["base_report"].get(k)]
            bad.append("the reference report is not base_report: " + ", ".join(sorted(differing)))
    elif kind == "reproduction":
        if load_generator().render() != (HERE / "vectors.json").read_bytes():
            bad.append("vectors.json is not what generate_vectors.py writes")
    elif kind == "duplicate_member":
        # A text naming a member twice, sealed as a reader keeping the last member reads it: not read under this
        # extension; such a reader verifies the signature over the text's bytes, and one keeping the first member
        # reads another document, whose signature does not verify (another identifier, or other signed bytes).
        t = v["texts"][c["text"]]
        raw = t["attachment_text"].encode("utf-8")
        try:
            strict_json(raw)
            bad.append("read a document that names a member twice")
        except ValueError:
            pass
        last = json.loads(raw)  # json.loads keeps the last member
        first = json.loads(raw, object_pairs_hook=lambda items: dict(reversed(items)))  # keeps the first member
        if (sig.pointer_get(last, t["differs_at"]), sig.pointer_get(first, t["differs_at"])) != (t["last_member"],
                                                                                                t["first_member"]):
            bad.append("the last-member and first-member readings")
        policy_result = sig.check_policy(v["trust_policy"])
        quoted = f'"value_b64":"{last["issuer_signature"]["value_b64"]}"'.encode("utf-8")
        replaced = raw.replace(quoted, b'"value_b64":"' + b"A" * len(last["issuer_signature"]["value_b64"]) + b'"')
        if raw.count(quoted) != 1 or sha256(replaced) != t["sealed_digest"]:
            bad.append("the sealed digest over the text's bytes")
        for reading, want in ((last, "verified"), (first, "failed")):
            r, _, _ = sig.checked_signature(seal_assertion(reading, replaced), sig.seal_signed_bytes, v["trust_policy"],
                                            policy_result, "organisation", sig.SEAL_SUITES)
            if r["status"] != want:
                bad.append(f"the {'last' if reading is last else 'first'}-member reading: {r['status']}")
    else:
        raise ValueError(f"unknown check {kind!r}")
    return ("mismatch" if bad else "match"), ", ".join(bad)


def digest_case(c, v, data):
    specs = data["specifications"]
    if c["check"] == "known_vector":
        return ("match" if sha256(c["text"].encode()) == c["digest"] else "mismatch"), ""
    if c["check"] == "spec_digests":
        bad = [k for k, s in specs.items() if sha256(s["text"].encode()) != s["spec_digest"]]
        return ("mismatch" if bad else "match"), ", ".join(bad)
    if c["check"] == "base_attachments":
        problems = []
        for name, carries in c["carries"].items():
            for i, spec in enumerate(v["attachments"][name]["action_specifications"]):
                raw = base64.b64decode(spec["content"]["bytes_b64"], validate=True)
                if raw != specs[carries[i]]["text"].encode() or sha256(raw) != spec["spec_digest"]:
                    problems.append(f"{name} specification {i}")
        return ("mismatch" if problems else "match"), "; ".join(problems)
    if c["check"] == "record_seal":
        # As the repository's governance records are sealed: SHA-256 of the whole record with the seal_hash value
        # replaced by 64 zeros (portable verification's seal_hash_zeroed).
        text = data["records"][c["record"]]
        seal = strict_json(text.encode("utf-8"))["seal_hash"]
        stored = '"seal_hash":"' + seal + '"'
        if text.count(stored) != 1:
            raise ValueError("the record must carry its seal_hash once")
        return ("match" if sha256(text.replace(stored, ZEROED).encode()) == seal else "mismatch"), ""
    if c["check"] != "spec":
        raise ValueError(f"unknown check {c['check']!r}")
    spec = specs[c["spec"]]
    text, note = spec["text"], ""
    if "edit" in c:
        found = text.count(c["edit"]["replace"])
        if found != 1:
            raise ValueError(f"the edit must match once; it matches {found} times")
        text = text.replace(c["edit"]["replace"], c["edit"]["with"])
    if "reserialise" in c:
        value = strict_json(text.encode("utf-8"))
        if c["reserialise"] == "indent_2":
            text = json.dumps(value, indent=2)
        else:
            text = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if strict_json(text.encode("utf-8")) != strict_json(spec["text"].encode("utf-8")) or text == spec["text"]:
            raise ValueError("the copy must be equal as JSON and differ in bytes")
        note = "equal as JSON: yes"
    # Compared with the specification's own digest, or with a named variant's (a one-change copy of it).
    against = specs[c.get("variant", c["spec"])]["spec_digest"]
    return ("match" if sha256(text.encode()) == against else "mismatch"), note


def binding_case(c, v, data, validators):
    att = sig.apply_patch(v["attachments"][c["attachment"]], c["patch"], v)
    found = errors(validators["attachment"], att)
    if found:
        return "error", f"the attachment must be schema-valid for this case: {found[0][:120]}"
    record = None if c["record"] is None else data["records"][c["record"]].encode("utf-8")
    got = check_attachment(att, record)
    findings = [f"{d}: {f}" for d in DIMENSIONS for f in got[d][1]]
    summary = {d: got[d][0] for d in DIMENSIONS}
    summary["execution_state"] = got["execution_state"]
    for key in CARRIED:
        if key in c["expected"]:
            summary[key] = got[key]
    return summary, "; ".join(findings)


def expected_binding(c):
    """Every dimension is expected verified, with an attempt, unless the case says otherwise."""
    full = {d: "verified" for d in DIMENSIONS}
    full["execution_state"] = "attempted"
    full.update(c["expected"])
    return full


def signature_case(c, v, data, validators):
    attachments, records, policy, beside, _ = context_for(c, v, data, validators)
    report = reference(reference_report, attachments, records, policy, beside)
    r = report["results"][c.get("index", 0)]
    s = r["issuer_signature"]
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
    if "stage_after_timestamp" in c["expected"]:
        summary["stage_after_timestamp"] = any("inconsistent with the timestamp" in f
                                               for f in r["time_assurance"].get("findings", []))
    if "timestamp_index" in c["expected"]:
        summary["timestamp_index"] = r["time_assurance"].get("timestamp_index")
    if "sealed_at_note" in c["expected"]:
        summary["sealed_at_note"] = ("earlier_than_a_stage" if any(f.startswith("sealed_at") and "earlier" in f
                                                                   for f in s.get("findings", [])) else None)
    detail = s.get("findings", []) + s.get("key_state", {}).get("findings", []) + r["time_assurance"].get("findings", [])
    return summary, "; ".join(detail)


def expected_signature(c):
    full = {"policy": "verified", "status": "verified", "key_state": "verified", "time_assurance": "not_checked",
            "time_basis": "stated_time"}
    full.update(c["expected"])
    if full["key_state"] != "verified":
        full.pop("time_basis", None)
    return full


def pairing_case(c, v, data, validators):
    attachments, records, policy, beside, digests = context_for(c, v, data, validators)
    # report: "reference" starts from the reference report of the documents the case reads, instead of base_report,
    # so that a case can change one dimension of a report that is otherwise right.
    base = (reference(reference_report, attachments, records, policy, beside) if c.get("report") == "reference"
            else v["base_report"])
    report = sig.apply_patch(base, c.get("report_patch", []), v, digests)
    if errors(validators["report"], report):
        return "error", "the report must be schema-valid for this case: " + errors(validators["report"], report)[0]
    problems = reference(read_with_attachments, report, attachments, records, policy, beside)
    return ("inconsistent" if problems else "consistent"), "; ".join(problems)


def main():
    sys.stdout.reconfigure(errors="backslashreplace")
    # Every document this check reads, its fixtures included, is read with duplicate members rejected (I-JSON).
    data = strict_json((HERE / "cases.json").read_bytes())
    v = strict_json((HERE / "vectors.json").read_bytes())
    validators = {}
    for name, p in SCHEMAS.items():
        schema = strict_json(p.read_bytes())
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)
        print(f"[ok  ] schemas/{p.name}: valid JSON Schema 2020-12")
    for name, p in OTHER_SCHEMAS.items():
        validators[name] = Draft202012Validator(strict_json(p.read_bytes()))
    print(f"[ok  ] the trust policy is anchoring's, the attachment read beside is signatures': "
          f"{OTHER_SCHEMAS['trust_policy'].relative_to(ROOT).as_posix()}, "
          f"{OTHER_SCHEMAS['sig_attachment'].relative_to(ROOT).as_posix()}")
    print(f"[ok  ] the signature, key state and timestamp checks are signatures 0.2.0's: "
          f"{SIGNATURES_RUNNER.relative_to(ROOT).as_posix()}")

    same = lambda c: c["expected"]  # noqa: E731
    groups = [
        ("schema", data["schema_cases"], lambda c: schema_case(c, v, data, validators), same),
        ("vector", data["vector_cases"], lambda c: vector_case(c, v, data), same),
        ("digest", data["digest_cases"], lambda c: digest_case(c, v, data), same),
        ("binding", data["binding_cases"], lambda c: binding_case(c, v, data, validators), expected_binding),
        ("signature", data["signature_cases"], lambda c: signature_case(c, v, data, validators), expected_signature),
        ("pairing", data["pairing_cases"], lambda c: pairing_case(c, v, data, validators), same),
    ]
    failed, total, limits = [], 0, []
    for group, cases, run, expect in groups:
        print(f"\n{group} cases:")
        for c in cases:
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
