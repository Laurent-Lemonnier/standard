# SPDX-License-Identifier: Apache-2.0
"""Writes vectors.json for the action binding extension, version 0.3.0 (a proposal).

Everything in vectors.json is computed from published inputs, so that another implementation can recompute it:

  attachments       A0 (an approved and executed payment) and A1 (a rejected one), from the templates in cases.json,
                    A0 signed by org-seal-1: its issuer_signature is the copy of the signatures 0.2.0 organisation seal
                    of kind attachment, five members, sealed_at written in place; A0_older, the same record's earlier
                    attachment with fewer stages, signed; and B0 and B1, the signatures vectors' attachments of
                    DR-2099-101 and DR-2099-102 as they stand there, copied and checked
  issuer signatures the copy as the cases need it: made with another key, under another profile, version or kind,
                    over bytes replaced with another placeholder, stated at a time that is not real, changed after
                    signing, and so on
  beside            a signatures 0.2.0 attachment read beside the attachments: the seal of A0 as that profile carries
                    it, and independent timestamps over signature values, with variants
  texts             A0 written with a member named twice (decision_id; sealed_at inside the copy), sealed as a reader
                    keeping the last member reads it: not read under this extension
  test keys         the signatures and anchoring test keys the vectors use, by their seed texts: never real keys
  trust_policy      the signatures vectors' policy, verbatim (anchoring 0.2.0's shape)
  base_report       the reference report of A0 and A1 read with the attachment beside them and the policy

It loads the signatures generator for the keys, the signed bytes, the seals and the RFC 3161 tokens, so that nothing
is defined twice, and checks that B0's copy is byte for byte the signatures vectors' seal_attachment.

Usage:  python extensions/action-binding/tests/generate_vectors.py            writes vectors.json
        python extensions/action-binding/tests/generate_vectors.py --check    compares, writes nothing
"""
import base64
import copy
import importlib.util
import json
import pathlib
import sys

from jsonschema import Draft202012Validator

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / "vectors.json"
SIGNATURES = ROOT / "extensions" / "signatures"
ANCHORING_VECTORS = ROOT / "extensions" / "anchoring" / "tests" / "vectors.json"
PROFILE, VERSION = "dps-action-binding", "0.3.0"
REPORT_PROFILE = "dps-action-binding-report"
SIGNATURES_PROFILE, SIGNATURES_VERSION = "dps-signatures", "0.2.0"
SIGNED_BYTES_REF = f"{SIGNATURES_PROFILE} {SIGNATURES_VERSION} organisation_seal"
SEALED_AT = {"A0": "2026-10-01T10:00:00Z", "A0_older": "2026-10-01T09:13:00Z"}
HOLDER = "Example issuer (test only)"
ORG_KEYS = ("org-seal-1", "org-seal-0", "org-seal-x")
PERSON_KEYS = ("person-a-1",)
ANCHORING_ED25519 = ("witness-a-1",)
ANCHORING_P256 = ("tsa-example-1", "tsa-example-2")
B64_LENGTH = 88  # an Ed25519 signature in padded base64


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sg = load_module("signatures_generate_vectors", SIGNATURES / "tests" / "generate_vectors.py")
sha256, b64, compact, when = sg.sha256, sg.b64, sg.compact, sg.when


def strict_json(raw):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate key {k!r}")
            out[k] = v
        return out
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda n: (_ for _ in ()).throw(ValueError(n)))


def copy_member(key_ref, sealed_at, value_b64):
    return {"algorithm": "Ed25519", "key_ref": key_ref, "signed_bytes_ref": SIGNED_BYTES_REF, "sealed_at": sealed_at,
            "value_b64": value_b64}


def seal_object(key_ref, kind, ident, digest_hex, sealed_at):
    return {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION, "assertion": "organisation_seal",
            "sealed": {"kind": kind, "id": ident, "digest": digest_hex}, "sealed_at": sealed_at,
            "signature": {"algorithm": "Ed25519", "key_ref": key_ref}}


def sign_attachment(keys, template, key_name, sealed_at, *, kind="attachment", signed_as=None, presented=None,
                    placeholder="A", bytes_as=None):
    """The attachment with its copy of the seal: the copy is put in with its value made of A, the bytes are digested,
    the seal signed over the digest (and the attachment's decision_id and sealed_at), and the value written in.
    signed_as changes the bytes the key signs; presented changes the copy after signing; placeholder changes the
    character the issuer replaced the value with (the rule says A); bytes_as, when given, is the issuer's own writing
    of the attachment (bytes), used instead of the compact writing. Returns the attachment, the seal and the bytes
    the key signed."""
    att = copy.deepcopy(template)
    att["issuer_signature"] = copy_member(key_name, sealed_at, placeholder * B64_LENGTH)
    written = bytes_as(att) if bytes_as else compact(att)
    seal = seal_object(key_name, kind, att["decision_id"], sha256(written).hex(), sealed_at)
    made_over = sg.signed_bytes(sg.seal_fields(seal, **(signed_as or {})))
    value = b64(keys[key_name].sign(made_over))
    seal["signature"]["value_b64"] = value
    att["issuer_signature"]["value_b64"] = value
    att["issuer_signature"].update(presented or {})
    return att, seal, made_over


def build():
    cases = strict_json((HERE / "cases.json").read_bytes())
    signatures = strict_json((SIGNATURES / "tests" / "vectors.json").read_bytes())
    anchoring = strict_json(ANCHORING_VECTORS.read_bytes())
    attachment_schema = strict_json((HERE.parent / "schemas" / "execution-evidence.schema.json").read_bytes())
    sig_attachment_schema = strict_json((SIGNATURES / "schemas" / "signatures-attachment.schema.json").read_bytes())
    templates = cases["templates"]
    for t in templates.values():
        if t["profile_version"] != VERSION or "issuer_signature" in t:
            raise ValueError("a template is a 0.3.0 attachment with no signature")

    # ---- keys, from their seed texts, checked against the vectors that publish them
    ed = {n: sg.ed25519_key(sg.SEED_PREFIX + n) for n in ORG_KEYS + PERSON_KEYS}
    ed.update({n: sg.ed25519_key(sg.ANCHORING_SEED_PREFIX + n) for n in ANCHORING_ED25519})
    ecc = {n: sg.p256_key(sg.ANCHORING_SEED_PREFIX + n) for n in ANCHORING_P256}
    test_keys = {}
    for n in ORG_KEYS + PERSON_KEYS + ANCHORING_ED25519:
        prefix = sg.ANCHORING_SEED_PREFIX if n in ANCHORING_ED25519 else sg.SEED_PREFIX
        test_keys[n] = {"algorithm": "Ed25519", "seed_text": prefix + n, "public_key_hex": sg.raw_public(ed[n]).hex(),
                        "published_in": "extensions/anchoring/tests/vectors.json" if n in ANCHORING_ED25519 else
                        "extensions/signatures/tests/vectors.json"}
    for n in ANCHORING_P256:
        test_keys[n] = {"algorithm": "ECDSA P-256", "seed_text": sg.ANCHORING_SEED_PREFIX + n,
                        "public_key_hex": sg.point_public(ecc[n]).hex(),
                        "published_in": "extensions/anchoring/tests/vectors.json"}
    for n, k in test_keys.items():
        source = anchoring if n in ANCHORING_ED25519 + ANCHORING_P256 else signatures
        if k["public_key_hex"] != source["test_keys"][n]["public_key_hex"]:
            raise ValueError(f"{n}: the key no longer matches the vectors it is published in")
    tsa_certs = {n: base64.b64decode(anchoring["tsa_certificates"][n]["certificate_b64"]) for n in ANCHORING_P256}

    # ---- the attachments and the copies of the seal the cases put in
    attachments, sigs, seals = {}, {}, {}
    a0_template, a1_template = templates["A0"], templates["A1"]
    older_template = copy.deepcopy(a0_template)
    older_template["stages"] = older_template["stages"][:3]  # the proposal, the review and the approval only

    def sig(name, about, template, key, sealed_at, **kw):
        att, seal, _ = sign_attachment(ed, template, key, sealed_at, **kw)
        sigs[name] = {"about": about, "signed_with": key, "for": att["decision_id"],
                      "issuer_signature": att["issuer_signature"]}
        return att, seal

    attachments["A0"], seal_a0 = sig("a0", "org-seal-1 seals A0, the attachment of DR-2099-101: the copy of the seal is "
                                     "its issuer_signature", a0_template, "org-seal-1", SEALED_AT["A0"])
    attachments["A1"] = copy.deepcopy(a1_template)
    attachments["A0_older"], seal_older = sig(
        "a0_older", "org-seal-1 seals the same record's earlier attachment, with the proposal, the review and the "
        "approval only: a valid signature, which says nothing about whether a later attachment exists",
        older_template, "org-seal-1", SEALED_AT["A0_older"])
    # A1, the rejection of DR-2099-102, signed: another record's signed attachment, for a timestamp over a signature
    # that is not A0's.
    attachments["A1_signed"], _ = sig("a1", "org-seal-1 seals A1, the attachment of DR-2099-102", a1_template,
                                      "org-seal-1", "2026-10-02T10:00:00Z")
    seals["seal_a0"] = {"about": "the seal of A0 as the signatures profile carries it beside the attachment",
                        "assertion": seal_a0}
    seals["seal_a0_older"] = {"about": "the seal of A0_older", "assertion": seal_older}

    sig("a0_org0", "org-seal-0, superseded on 2026-10-05, signs A0 before", a0_template, "org-seal-0", SEALED_AT["A0"])
    sig("a0_org0_late", "org-seal-0, stated as signing A0 after it was superseded", a0_template, "org-seal-0",
        "2026-10-06T09:00:00Z")
    sig("a0_org_x", "org-seal-x, a key the policy does not list, signs A0", a0_template, "org-seal-x", SEALED_AT["A0"])
    sig("a0_person", "person-a-1, a key in role person, signs A0", a0_template, "person-a-1", SEALED_AT["A0"])
    sig("a0_witness", "witness-a-1, a key in role witness, signs A0", a0_template, "witness-a-1", SEALED_AT["A0"])
    sig("a0_feb30", "sealed_at 2026-02-30T10:00:00Z: the schema admits the form, but it is not a real UTC time",
        a0_template, "org-seal-1", "2026-02-30T10:00:00Z")
    sig("a0_before_validity", "org-seal-1, stated as signing before the key's not_before", a0_template, "org-seal-1",
        "2025-12-31T23:00:00Z")
    sig("a0_other_profile", "the key signed the same fields under profile dps-anchoring", a0_template, "org-seal-1",
        SEALED_AT["A0"], signed_as={"profile": "dps-anchoring"})
    sig("a0_other_version", "the key signed the same fields under signatures profile_version 0.3.0", a0_template,
        "org-seal-1", SEALED_AT["A0"], signed_as={"version": "0.3.0"})
    sig("a0_as_record", "the key signed the same fields with sealed.kind record: an attachment is an attachment",
        a0_template, "org-seal-1", SEALED_AT["A0"], kind="record")
    sig("a0_wrong_placeholder", "the issuer replaced the value by 0 instead of A before digesting: not the rule, so "
        "the digest the verifier builds is another", a0_template, "org-seal-1", SEALED_AT["A0"], placeholder="0")
    sig("a0_time_changed", "signed at 10:00:00Z, the copy stating 10:05:00Z: the time is signed and under the digest",
        a0_template, "org-seal-1", SEALED_AT["A0"], presented={"sealed_at": "2026-10-01T10:05:00Z"})
    sig("a0_moved_to_org0", "A0's signature presented under key reference org-seal-0", a0_template, "org-seal-1",
        SEALED_AT["A0"], presented={"key_ref": "org-seal-0"})
    sig("a0_moved_to_a1", "A0's copy, as it stands, for the cases to put on A1: the bytes and the identifier are "
        "another attachment's", a0_template, "org-seal-1", SEALED_AT["A0"])
    bad = copy.deepcopy(sigs["a0"])
    bad["about"] = "A0's copy with the last byte of its signature changed"
    bad["issuer_signature"]["value_b64"] = b64(sg.flip_last_byte(base64.b64decode(bad["issuer_signature"]["value_b64"])))
    sigs["a0_bad_signature"] = bad

    # A0 whose last stage is dated after the copy's sealed_at: the issuer states a seal before its own last stage.
    late_template = copy.deepcopy(a0_template)
    late_template["stages"][-1]["at"] = "2026-10-01T10:30:00Z"
    attachments["A0_late_stage"], _ = sig("a0_late_stage", "org-seal-1 signs A0 with its result stage dated 10:30, "
                                          "the copy stating 10:00: the signature stands, and the check notes the "
                                          "inconsistency between the issuer's own times", late_template, "org-seal-1",
                                          SEALED_AT["A0"])

    # A copy whose sealed_at is not the seal's, with the same value: the issuer sealed A0's bytes with 10:05 written in
    # the copy, and signed the fields with 10:00. Only the issuer can write it. The copy fails here (the verifier
    # builds the bytes with 10:05); the seal beside verifies, and signatures' copy check does not take the copy for
    # a copy of it.
    other_time = copy.deepcopy(a0_template)
    other_time["issuer_signature"] = copy_member("org-seal-1", "2026-10-01T10:05:00Z", "A" * B64_LENGTH)
    seal_other = seal_object("org-seal-1", "attachment", other_time["decision_id"], sha256(compact(other_time)).hex(),
                             SEALED_AT["A0"])
    seal_other["signature"]["value_b64"] = b64(ed["org-seal-1"].sign(sg.signed_bytes(sg.seal_fields(seal_other))))
    other_time["issuer_signature"]["value_b64"] = seal_other["signature"]["value_b64"]
    attachments["A0_copy_other_time"] = other_time
    seals["seal_a0_other_time"] = {"about": "org-seal-1's seal of A0 written with 10:05 in its copy, the seal stating "
                                            "10:00: beside the attachment it verifies, and the copy does not agree",
                                   "assertion": seal_other}

    # ---- the signatures vectors' attachments of DR-2099-101 and DR-2099-102, as they stand there
    for name, decision in (("B0", "DR-2099-101"), ("B1", "DR-2099-102")):
        attachments[name] = copy.deepcopy(signatures["action_binding_attachments"][decision])
    theirs = signatures["organisation_seals"]["seal_attachment"]["assertion"]
    if attachments["B0"]["issuer_signature"] != copy_member("org-seal-1", theirs["sealed_at"],
                                                              theirs["signature"]["value_b64"]):
        raise ValueError("B0's copy is not the signatures vectors' seal_attachment")
    b0_check = copy.deepcopy(attachments["B0"])
    b0_check["issuer_signature"]["value_b64"] = "A" * B64_LENGTH
    if sha256(compact(b0_check)).hex() != theirs["sealed"]["digest"]:
        raise ValueError("B0's bytes with the value replaced are not what seal_attachment sealed")
    seals["seal_b0"] = {"about": "the signatures vectors' seal_attachment: the seal of B0", "assertion": theirs}

    validator = Draft202012Validator(attachment_schema)
    for name, att in attachments.items():
        found = sorted(validator.iter_errors(att), key=lambda e: list(e.absolute_path))
        if found:
            raise ValueError(f"attachment {name} is not valid against the attachment schema: {found[0].message}")

    # ---- beside the attachments: the seal of A0 and timestamps over signature values
    tsa1 = (ecc["tsa-example-1"], tsa_certs["tsa-example-1"])
    tsa2 = (ecc["tsa-example-2"], tsa_certs["tsa-example-2"])
    tokens, timestamps = {}, {}

    def of_copy(name, sealed_id=None):
        s = sigs[name]
        return {"assertion": "organisation_seal", "key_ref": s["issuer_signature"]["key_ref"],
                "sealed_kind": "attachment", "sealed_id": sealed_id or s["for"]}

    def ts(name, about, value_b64, of, signer, gen_time, serial, tsa_ref="tsa-example-1", **kw):
        value = base64.b64decode(value_b64)
        token, _ = sg.make_token(signer[0], signer[1], value, when(gen_time), serial, **kw)
        tokens[name] = {"about": about, "imprint_of_hex": value.hex(), "token_b64": b64(token)}
        timestamps[name] = {"assertion": "timestamp", "subject": {"kind": "signature", "of": of, "value_b64": value_b64},
                            "hash_algorithm": "SHA-256", "tsa_ref": tsa_ref, "token_b64": b64(token)}

    v_a0 = sigs["a0"]["issuer_signature"]["value_b64"]
    ts("a0", "TSA 1 over A0's signature value", v_a0, of_copy("a0"), tsa1, "2026-10-01T10:30:00Z", 601)
    ts("a0_early", "TSA 1 over A0's signature value, before the time the issuer states", v_a0, of_copy("a0"), tsa1,
       "2026-10-01T09:30:00Z", 602)
    ts("a0_tsa2", "TSA 2, which the policy does not list, over A0's signature value", v_a0, of_copy("a0"), tsa2,
       "2026-10-01T10:30:00Z", 603, tsa_ref="tsa-example-2")
    ts("a0_named_a1", "TSA 1 over A0's signature value, its subject naming DR-2099-102", v_a0,
       of_copy("a0", "DR-2099-102"), tsa1, "2026-10-01T10:30:00Z", 604)
    v_org0 = sigs["a0_org0"]["issuer_signature"]["value_b64"]
    ts("a0_org0_before", "TSA 1 over a0_org0's signature value, before org-seal-0 was revoked (2026-10-05)", v_org0,
       of_copy("a0_org0"), tsa1, "2026-10-01T10:30:00Z", 605)
    ts("a0_org0_after", "TSA 1 over a0_org0's signature value, after org-seal-0 was revoked", v_org0, of_copy("a0_org0"),
       tsa1, "2026-10-06T10:00:00Z", 606)
    v_bad = sigs["a0_bad_signature"]["issuer_signature"]["value_b64"]
    ts("a0_bad_signature", "TSA 1 over the changed signature value, which verifies on nothing", v_bad, of_copy("a0"),
       tsa1, "2026-10-01T10:30:00Z", 607)
    ts("a0_older", "TSA 1 over A0_older's signature value: another attachment's signature, named like A0's (same "
       "record, key and kind)", sigs["a0_older"]["issuer_signature"]["value_b64"], of_copy("a0_older"), tsa1,
       "2026-10-01T09:20:00Z", 608)
    ts("a1_signed", "TSA 1 over A1_signed's signature value: another record's signature",
       sigs["a1"]["issuer_signature"]["value_b64"], of_copy("a1"), tsa1, "2026-10-02T10:30:00Z", 610)
    ts("a0_late_stage", "TSA 1 over A0_late_stage's signature value at 10:15, while the attachment dates its result "
       "stage 10:30", sigs["a0_late_stage"]["issuer_signature"]["value_b64"], of_copy("a0_late_stage"), tsa1,
       "2026-10-01T10:15:00Z", 609)

    beside = {
        "beside": {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION,
                   "organisation_seals": [seals["seal_a0"]["assertion"]], "timestamps": [timestamps["a0"]]},
        "seal_only": {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION,
                      "organisation_seals": [seals["seal_a0"]["assertion"]]},
        "a1_timestamp": {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION,
                         "organisation_seals": [seals["seal_a0"]["assertion"]], "timestamps": [timestamps["a1_signed"]]},
    }
    sig_validator = Draft202012Validator(sig_attachment_schema)
    for name, att in beside.items():
        if list(sig_validator.iter_errors(att)):
            raise ValueError(f"attachment {name} is not valid against the signatures attachment schema")
    ts_validator = Draft202012Validator({"$ref": "#/$defs/timestamp", "$defs": sig_attachment_schema["$defs"]})
    for name, t in timestamps.items():
        if list(ts_validator.iter_errors(t)):
            raise ValueError(f"timestamp {name} is not valid against the signatures attachment schema")

    # ---- A0 written with a member named twice, sealed as a reader keeping the last member reads it
    texts = {}

    def dup_text(name, about, member_old, member_new, differs_at, first, last):
        def writing(att):
            written = compact(att)
            if written.count(member_old) != 1:
                raise ValueError(f"{name}: the member is not written once")
            return written.replace(member_old, member_new, 1)
        att, seal, _ = sign_attachment(ed, a0_template, "org-seal-1", SEALED_AT["A0"], bytes_as=writing)
        written = writing(att)  # the value in place now
        last_wins = json.loads(written)
        if last_wins != att:
            raise ValueError(f"{name}: a reader keeping the last member does not find the attachment as signed")
        texts[name] = {"about": about, "attachment_text": written.decode("utf-8"), "differs_at": differs_at,
                       "first_member": first, "last_member": last, "sealed_digest": seal["sealed"]["digest"]}

    dup_text("dup_decision_id", "A0 naming decision_id twice, DR-2099-042 first and DR-2099-101 last, sealed as a reader "
             "keeping the last member reads it. Not read under this extension: such a reader verifies the signature, "
             "one keeping the first reads another record's attachment, and only the issuer can write that.",
             b'"decision_id":"DR-2099-101"', b'"decision_id":"DR-2099-042","decision_id":"DR-2099-101"',
             "/decision_id", "DR-2099-042", "DR-2099-101")
    dup_text("dup_sealed_at", "A0 whose copy names sealed_at twice, 09:00 first and 10:00 last, sealed as a reader "
             "keeping the last member reads it. Not read under this extension: such a reader verifies the signature, "
             "one keeping the first builds other signed bytes.",
             b'"sealed_at":"2026-10-01T10:00:00Z"', b'"sealed_at":"2026-10-01T09:00:00Z","sealed_at":"2026-10-01T10:00:00Z"',
             "/issuer_signature/sealed_at", "2026-10-01T09:00:00Z", "2026-10-01T10:00:00Z")

    # ---- the policy and the reference report of A0 and A1 read with the attachment beside them
    policy = copy.deepcopy(signatures["trust_policy"])
    report = copy.deepcopy(cases["report_template"])
    report["profile_version"] = VERSION
    report["trust_policy_ref"] = policy["policy_ref"]
    report["trust_policy"] = {"status": "verified"}
    report["signatures_attachment_digest"] = sha256(compact(beside["beside"])).hex()
    r0, r1 = report["results"]
    r0["attachment_digest"] = sha256(compact(attachments["A0"])).hex()
    r1["attachment_digest"] = sha256(compact(attachments["A1"])).hex()
    r0["issuer_signature"] = {"status": "verified", "key_ref": "org-seal-1", "algorithm": "Ed25519", "holder": HOLDER,
                              "reference_source": "trust_policy", "certificate": "verified",
                              "key_state": {"status": "verified", "key_ref": "org-seal-1",
                                            "time_basis": "independent_timestamp", "time": "2026-10-01T10:30:00Z",
                                            "timestamp_index": 0},
                              "attests": "issuer_recorded_claims_only"}
    r0["time_assurance"] = {"status": "verified", "basis": "independent_source", "source_ref": "tsa-example-1",
                            "no_later_than": "2026-10-01T10:30:00Z", "timestamp_index": 0,
                            "findings": ["the issuer signature, and so the attachment's bytes as issued, existed no "
                                         "later than 2026-10-01T10:30:00Z (tsa-example-1); not when any stage "
                                         "happened"]}
    ordered = {}
    for k in ("profile", "profile_version", "attachment_count", "trust_policy_ref", "trust_policy",
              "signatures_attachment_digest", "results", "scope_of_conclusion"):
        ordered[k] = report[k]

    return {
        "about": f"Test vectors for the action binding extension {VERSION}, written by generate_vectors.py from the "
                 "templates in cases.json and published inputs. A0 and A0_older are signed by org-seal-1: the copy of "
                 "the signatures 0.2.0 organisation seal of kind attachment, five members, sealed_at written in place, "
                 "the sealed digest over the bytes with the value replaced by A. B0 and B1 are the signatures vectors' "
                 "attachments; B0's copy is their seal_attachment, byte for byte. Test keys only, derived from their "
                 "published seed texts: never real keys. Documents are read as JSON with no whitespace, in UTF-8, by "
                 "the convention of these cases, except the texts, which are read as written.",
        "test_keys": test_keys,
        "attachments": attachments,
        "issuer_signatures": sigs,
        "seals": seals,
        "tokens": tokens,
        "timestamps": timestamps,
        "signatures_attachments": beside,
        "texts": texts,
        "trust_policy": policy,
        "base_context": {"covers": ["A0", "A1"], "records": ["R0", "R1"], "attachment": "beside"},
        "base_report": ordered,
    }


def render():
    return (json.dumps(build(), indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv):
    data = render()
    if argv[1:] == ["--check"]:
        same = OUT.exists() and OUT.read_bytes() == data
        print(("PASS: vectors.json is what this script writes, byte for byte." if same else
               "FAIL: vectors.json differs from what this script writes."))
        return 0 if same else 1
    if argv[1:]:
        print(__doc__)
        return 1
    OUT.write_bytes(data)
    print(f"wrote {OUT.name} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
