# SPDX-License-Identifier: Apache-2.0
"""Writes vectors.json for the portable verification extension, version 0.2.0 (a proposal).

Everything in vectors.json is computed from published inputs, so that another implementation can recompute it:

  records           R0, R1, R2 and R4 as the anchoring and signatures vectors hold them (R0 to R2 from portable
                    verification 0.1.0's cases), R3 (R2 with an empty seal placeholder), and D2, a derived
                    representation of R2: the same JSON value written with its members sorted and no whitespace
  test keys         the signatures extension's test keys, by their seed texts: the organisation's keys org-seal-1
                    (current), org-seal-0 (superseded) and org-seal-x (not in the policy), person-a-1, and
                    anchoring's witness-a-1 and time-stamping authority tsa-example-1. No new key: the seed text of
                    each is the one its own extension publishes, and the public keys are checked against those
                    vectors. Test keys only, never real keys.
  exports           signed (R0, R1, R2, each entry signed by org-seal-1), with_derived (D2 added as a derived entry,
                    signed), unsigned (the same three entries with no signature)
  entry signatures  the signature member of an entry under this version: the signatures 0.2.0 organisation seal of
                    kind record over the entry's decision_id and its seal_hash (or derived_digest), with the variants
                    the cases need (another key, another profile, the wrong digest, a time that is not real, ...)
  beside            a signatures 0.2.0 attachment read beside the export: its seal of kind export over the signed
                    export's bytes as issued, and independent timestamps over signature values, with variants
  trust_policy      the signatures vectors' policy, verbatim (anchoring 0.2.0's shape)
  base_report       the reference report of the signed export read with the attachment beside it

The seals of R0 and R2 are byte for byte the signatures vectors' seal_record_r0 and seal_record_r2, and this script
checks that they are, so that the three sets of vectors agree. It uses the signatures generator's own functions
(keys, signed bytes, seals, RFC 3161 tokens) by loading that script, so that nothing is defined twice.

Usage:  python extensions/portable-verification/tests/generate_vectors.py            writes vectors.json
        python extensions/portable-verification/tests/generate_vectors.py --check    compares, writes nothing
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
OUT = HERE / "vectors.json"
SIGNATURES = ROOT / "extensions" / "signatures"
ANCHORING_VECTORS = ROOT / "extensions" / "anchoring" / "tests" / "vectors.json"
PROFILE, VERSION = "dps-portable-verification", "0.2.0"
REPORT_PROFILE = "dps-portable-verification-report"
SIGNATURES_PROFILE, SIGNATURES_VERSION = "dps-signatures", "0.2.0"
SIGNED_BYTES_REF = f"{SIGNATURES_PROFILE} {SIGNATURES_VERSION} organisation_seal"
EXPORT_ID = "urn:example:export:issuer-1:2026-09-28"  # the issuer's own reference for the signed export
EXPORT_SEALED_AT = "2026-09-28T09:00:00Z"
CANONICAL_REF = "urn:example:canonical-json:sorted-members-no-whitespace:1"
SEALED_AT = {"R0": "2026-09-25T11:30:00Z", "R1": "2026-09-26T10:30:00Z", "R2": "2026-09-27T10:30:00Z",
             "D2": "2026-09-27T16:00:00Z"}
ORG_KEYS = ("org-seal-1", "org-seal-0", "org-seal-x")
PERSON_KEYS = ("person-a-1",)
ANCHORING_ED25519 = ("witness-a-1",)
ANCHORING_P256 = ("tsa-example-1", "tsa-example-2")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sg = load_module("signatures_generate_vectors", SIGNATURES / "tests" / "generate_vectors.py")
sha256, b64, compact, when, text = sg.sha256, sg.b64, sg.compact, sg.when, sg.text


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


def value(record_text):
    """A fixture record's value, read strictly like every other document."""
    return strict_json(record_text.encode("utf-8"))


def link(previous, digest_hex):
    return sha256((previous or bytes(32)) + bytes.fromhex(digest_hex))


# ---------------------------------------------------------------- an entry's signature: a signatures 0.2.0 seal

def seal_object(key_ref, kind, ident, digest_hex, sealed_at):
    return {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION, "assertion": "organisation_seal",
            "sealed": {"kind": kind, "id": ident, "digest": digest_hex}, "sealed_at": sealed_at,
            "signature": {"algorithm": "Ed25519", "key_ref": key_ref}}


def entry_signature(keys, key_name, ident, digest_hex, sealed_at, *, kind="record", signed_as=None, presented=None):
    """The signature member of an export entry: org-seal-1 (or another key) seals the record's digest under the
    signatures 0.2.0 organisation seal of kind record. signed_as changes the bytes the key signs (another profile,
    version, type or key reference); presented changes what the member says after signing."""
    seal = seal_object(key_name, kind, ident, digest_hex, sealed_at)
    made_over = sg.signed_bytes(sg.seal_fields(seal, **(signed_as or {})))
    member = {"algorithm": "Ed25519", "key_ref": key_name, "signed_bytes_ref": SIGNED_BYTES_REF,
              "sealed_at": sealed_at, "value_b64": b64(keys[key_name].sign(made_over))}
    member.update(presented or {})
    as_presented = seal_object(member["key_ref"], "record", ident, digest_hex, member["sealed_at"])
    out = {"signed_with": key_name, "for": {"decision_id": ident, "digest": digest_hex}, "signature": member,
           "signed_bytes_hex": sg.signed_bytes(sg.seal_fields(as_presented)).hex()}
    if made_over.hex() != out["signed_bytes_hex"]:
        out["signature_made_over_hex"] = made_over.hex()
    return out


# ---------------------------------------------------------------- records and exports

def original_entry(name, record_text, seal_hex, sequence, previous_link):
    entry = {
        "decision_id": value(record_text)["decision_id"],
        "record_type": "decision",
        "covered_representation": {"kind": "original_bytes", "media_type": "application/json"},
        "content": {"availability": "available", "covered_bytes_b64": b64(record_text.encode("utf-8"))},
        "seal": {"seal_hash": seal_hex, "seal_algorithm": "SHA-256",
                 "seal_field_handling": "seal_hash_zeroed" if name == "R2" else "seal_hash_absent",
                 "affirmation_record_covered": True},
    }
    if name == "R1":
        entry["predecessors"] = {"supersedes": "DR-2099-001"}
    entry["chain"] = {"sequence": sequence, "previous_link": previous_link}
    return entry


def derived_entry(record_text, original_seal_hex, derived_hex, sequence, previous_link):
    return {
        "decision_id": value(record_text)["decision_id"],
        "record_type": "decision",
        "covered_representation": {"kind": "canonical_form", "media_type": "application/json",
                                   "canonicalisation": "members sorted by name, no whitespace",
                                   "specification_ref": CANONICAL_REF},
        "content": {"availability": "available", "covered_bytes_b64": b64(record_text.encode("utf-8"))},
        "derived_from": {"original_seal_hash": original_seal_hex, "original_seal_algorithm": "SHA-256",
                         "transformation": {"name": "re-serialisation in the canonical form",
                                            "specification_ref": CANONICAL_REF, "record_ref": "DR-2099-010"}},
        "derived_digest": derived_hex,
        "chain": {"sequence": sequence, "previous_link": previous_link},
    }


def build():
    anchoring = strict_json(ANCHORING_VECTORS.read_bytes())
    signatures = strict_json((SIGNATURES / "tests" / "vectors.json").read_bytes())
    attachment_schema = strict_json((SIGNATURES / "schemas" / "signatures-attachment.schema.json").read_bytes())
    export_schema = strict_json((HERE.parent / "schemas" / "verification-export.schema.json").read_bytes())

    # ---- records: the signatures generator's R0, R1, R2, R4; R3 and D2 made from R2
    records = {k: sg.RECORDS[k] for k in ("R0", "R1", "R2", "R4")}
    zeroed = '"seal_hash":"' + "0" * 64 + '"'
    if records["R2"].count(zeroed) != 1:
        raise ValueError("R2 does not carry one zeroed seal field")
    records["R3"] = records["R2"].replace(zeroed, '"seal_hash":""')
    d2 = json.dumps(value(records["R2"]), sort_keys=True, separators=(",", ":"))
    if d2 == records["R2"] or value(d2) != value(records["R2"]):
        raise ValueError("D2 must be R2's value in other bytes")
    records["D2"] = d2
    # R0 naming decision_id twice, another identifier first and the real one last: a reader keeping the last member
    # reads R0, one keeping the first reads another record, and a strict reader reads neither.
    marker = '"decision_id":"DR-2099-001"'
    if records["R0"].count(marker) != 1:
        raise ValueError("R0 does not name DR-2099-001 once")
    records["R0d"] = records["R0"].replace(marker, '"decision_id":"DR-2099-042",' + marker, 1)
    seal = {k: sha256(v.encode("utf-8")).hex() for k, v in records.items()}
    for k, v in sg.PORTABLE_VERIFICATION_SEALS.items():
        if seal[k] != v:
            raise ValueError(f"{k}: the record no longer matches the 0.1.0 fixture")
    if not seal["R3"].startswith("0c88eacdfdff"):
        raise ValueError("R3: the record no longer matches the 0.1.0 fixture")
    record_vectors = {k: {"text": v, "digest": seal[k], "about": about} for k, v, about in (
        ("R0", records["R0"], "DR-2099-001, as in portable verification 0.1.0's cases; its seal_hash is the digest"),
        ("R1", records["R1"], "DR-2099-002, which supersedes DR-2099-001 and omits record_type"),
        ("R2", records["R2"], "DR-2099-003, whose covered bytes carry the seal field zeroed"),
        ("R3", records["R3"], "R2 with an empty seal_hash as placeholder, which 0.1.0 and 0.2.0 do not cover"),
        ("R4", records["R4"], "DR-2099-004, as in the anchoring and signatures vectors (the extended export)"),
        ("D2", records["D2"], "a derived representation of R2: the same JSON value with its members sorted and no "
                              "whitespace; its digest is a derived_digest, never R2's seal"),
        ("R0d", records["R0d"], "R0 naming decision_id twice, DR-2099-042 first and DR-2099-001 last, sealed as "
                                "written: not read by a strict reader; a reader keeping the last member reads R0, one "
                                "keeping the first reads another record"))}

    # ---- the chain: R0, R1, R2, then D2 as a fourth entry (its derived digest)
    links, head = {}, None
    for i, k in enumerate(("R0", "R1", "R2", "D2")):
        head = link(head, seal[k])
        links[f"L{i}"] = head.hex()
    for i in range(3):
        if links[f"L{i}"] != anchoring["chain"]["links"][f"L{i}"]:
            raise ValueError(f"L{i}: the chain no longer matches the anchoring vectors")

    # ---- keys: the signatures and anchoring test keys, from their seed texts, checked against those vectors
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

    # ---- the entries' signatures
    sigs = {}

    def sig(name, about, key, record, sealed_at=None, **kw):
        ident = value(records[record])["decision_id"]
        sigs[name] = {"about": about, **entry_signature(ed, key, ident, seal[record], sealed_at or SEALED_AT[record], **kw)}
        return sigs[name]["signature"]

    for r, about in (("R0", "org-seal-1 signs the entry of DR-2099-001: its seal_hash, as the signatures vectors' "
                            "seal_record_r0"),
                     ("R1", "org-seal-1 signs the entry of DR-2099-002"),
                     ("R2", "org-seal-1 signs the entry of DR-2099-003, as the signatures vectors' seal_record_r2"),
                     ("D2", "org-seal-1 signs the derived entry of DR-2099-003: its derived_digest, never R2's seal")):
        sig(r.lower(), about, "org-seal-1", r)
    for name, vector in (("r0", "seal_record_r0"), ("r2", "seal_record_r2")):
        theirs = signatures["organisation_seals"][vector]["assertion"]
        if (sigs[name]["signature"]["value_b64"], sigs[name]["signed_bytes_hex"]) != (
                theirs["signature"]["value_b64"], signatures["organisation_seals"][vector]["signed_bytes_hex"]):
            raise ValueError(f"{name}: the signature is not the signatures vectors' {vector}")
    sigs["d2_over_original_seal"] = {"about": "the derived entry signed over R2's seal (derived_from.original_seal_hash) "
                                     "instead of its derived_digest: a signature that does not verify on the derived "
                                     "entry, whose signed digest is its derived_digest",
                                     **entry_signature(ed, "org-seal-1", "DR-2099-003", seal["R2"], SEALED_AT["D2"])}
    sigs["r2_over_derived_digest"] = {"about": "the original entry of DR-2099-003 signed over D2's derived_digest "
                                      "instead of its seal: the reverse, which does not verify on the original",
                                      **entry_signature(ed, "org-seal-1", "DR-2099-003", seal["D2"], SEALED_AT["R2"])}
    sig("r1_org0", "org-seal-0 signs the entry of DR-2099-002 before the key was superseded", "org-seal-0", "R1")
    sig("r1_org0_late", "org-seal-0, stated as signing after it was superseded (2026-10-05)", "org-seal-0", "R1",
        "2026-10-06T09:00:00Z")
    sig("r0_org_x", "org-seal-x, a key the policy does not list", "org-seal-x", "R0")
    sig("r0_person", "person-a-1, a key in role person, signs an entry", "person-a-1", "R0")
    sig("r0_witness", "witness-a-1, a key in role witness, signs an entry", "witness-a-1", "R0")
    sig("r0_feb30", "sealed_at 2026-02-30T11:30:00Z: the schema admits the form, but it is not a real UTC time",
        "org-seal-1", "R0", "2026-02-30T11:30:00Z")
    sig("r0_before_validity", "org-seal-1, stated as signing before the key's not_before", "org-seal-1", "R0",
        "2025-12-31T23:00:00Z")
    sig("r0_other_profile", "the key signed the same fields under profile dps-anchoring", "org-seal-1", "R0",
        signed_as={"profile": "dps-anchoring"})
    sig("r0_other_version", "the key signed the same fields under signatures profile_version 0.3.0", "org-seal-1",
        "R0", signed_as={"version": "0.3.0"})
    sig("r0_as_attachment", "the key signed the same fields with sealed.kind attachment", "org-seal-1", "R0",
        kind="attachment")
    sig("r0_time_changed", "signed at 11:30:00Z, the member stating an hour later", "org-seal-1", "R0",
        presented={"sealed_at": "2026-09-25T12:30:00Z"})
    sig("r0_moved_to_org0", "r0's signature presented under key reference org-seal-0", "org-seal-1", "R0",
        presented={"key_ref": "org-seal-0"})
    bad = copy.deepcopy(sigs["r0"])
    bad["about"] = "r0 with the last byte of its signature changed"
    bad["signature"]["value_b64"] = b64(sg.flip_last_byte(base64.b64decode(bad["signature"]["value_b64"])))
    sigs["r0_bad_signature"] = bad

    # ---- exports
    def with_signature(entry, name):
        entry = copy.deepcopy(entry)
        entry["signature"] = sigs[name]["signature"]
        return entry

    originals = [original_entry("R0", records["R0"], seal["R0"], 0, None),
                 original_entry("R1", records["R1"], seal["R1"], 1, links["L0"]),
                 original_entry("R2", records["R2"], seal["R2"], 2, links["L1"])]
    d2_entry = derived_entry(records["D2"], seal["R2"], seal["D2"], 3, links["L2"])
    exports = {
        "signed": {"profile": PROFILE, "profile_version": VERSION,
                   "entries": [with_signature(e, n) for e, n in zip(originals, ("r0", "r1", "r2"))]},
        "with_derived": {"profile": PROFILE, "profile_version": VERSION,
                         "entries": [with_signature(e, n) for e, n in zip(originals + [d2_entry],
                                                                          ("r0", "r1", "r2", "d2"))]},
        "unsigned": {"profile": PROFILE, "profile_version": VERSION, "entries": copy.deepcopy(originals)},
    }
    validator = Draft202012Validator(export_schema)
    for name, export in exports.items():
        found = sorted(validator.iter_errors(export), key=lambda e: list(e.absolute_path))
        if found:
            raise ValueError(f"export {name} is not valid against the export schema: {found[0].message}")
    for i, e in enumerate(exports["unsigned"]["entries"]):
        theirs = signatures["exports"]["full"]["entries"][i]
        if {k: v for k, v in e.items()} != {k: v for k, v in theirs.items()}:
            raise ValueError(f"entry {i}: the unsigned export no longer matches the signatures vectors' full export")

    # ---- beside the export: a signatures 0.2.0 attachment with the export's seal and timestamps over signature values
    export_digest = sha256(compact(exports["signed"])).hex()
    export_seal = sg.make_seal(ed, "org-seal-1", {"kind": "export", "id": EXPORT_ID, "digest": export_digest},
                               EXPORT_SEALED_AT)
    seals = {"export": {"about": "org-seal-1 seals the signed export as issued, under the issuer's reference for it",
                        **export_seal}}
    seals["export_org_x"] = {"about": "org-seal-x, a key the policy does not list, seals the signed export",
                             **sg.make_seal(ed, "org-seal-x", {"kind": "export", "id": EXPORT_ID,
                                                              "digest": export_digest}, EXPORT_SEALED_AT)}
    seals["export_with_derived"] = {"about": "org-seal-1 seals the export with the derived entry as issued",
                                    **sg.make_seal(ed, "org-seal-1", {"kind": "export", "id": EXPORT_ID + ":derived",
                                                                     "digest": sha256(compact(exports["with_derived"])).hex()},
                                                   EXPORT_SEALED_AT)}

    tsa1 = (ecc["tsa-example-1"], tsa_certs["tsa-example-1"])
    tsa2 = (ecc["tsa-example-2"], tsa_certs["tsa-example-2"])
    tokens, timestamps = {}, {}

    def of_entry(name):
        s = sigs[name]
        return {"assertion": "organisation_seal", "key_ref": s["signature"]["key_ref"], "sealed_kind": "record",
                "sealed_id": s["for"]["decision_id"]}

    def ts(name, about, value_b64, of, signer, gen_time, serial, tsa_ref="tsa-example-1", **kw):
        value = base64.b64decode(value_b64)
        token, _ = sg.make_token(signer[0], signer[1], value, when(gen_time), serial, **kw)
        tokens[name] = {"about": about, "imprint_of_hex": value.hex(), "token_b64": b64(token)}
        timestamps[name] = {"assertion": "timestamp", "subject": {"kind": "signature", "of": of, "value_b64": value_b64},
                            "hash_algorithm": "SHA-256", "tsa_ref": tsa_ref, "token_b64": b64(token)}

    ts("r0", "TSA 1 over the signature of the entry of DR-2099-001", sigs["r0"]["signature"]["value_b64"],
       of_entry("r0"), tsa1, "2026-09-25T12:00:00Z", 501)
    ts("export_seal", "TSA 1 over the export seal's value", export_seal["assertion"]["signature"]["value_b64"],
       {"assertion": "organisation_seal", "key_ref": "org-seal-1", "sealed_kind": "export", "sealed_id": EXPORT_ID},
       tsa1, "2026-09-28T09:30:00Z", 502)
    ts("r1_org0_before", "TSA 1 over r1_org0's signature, before org-seal-0 was revoked (2026-10-05)",
       sigs["r1_org0"]["signature"]["value_b64"], of_entry("r1_org0"), tsa1, "2026-09-26T11:00:00Z", 503)
    ts("r1_org0_after", "TSA 1 over r1_org0's signature, after org-seal-0 was revoked",
       sigs["r1_org0"]["signature"]["value_b64"], of_entry("r1_org0"), tsa1, "2026-10-06T11:00:00Z", 504)
    ts("d2", "TSA 1 over the signature of the derived entry of DR-2099-003, named as the signatures profile names "
       "it: kind record, the record's identifier, like the original's", sigs["d2"]["signature"]["value_b64"],
       of_entry("d2"), tsa1, "2026-09-27T17:00:00Z", 505)
    ts("r0_named_r1", "TSA 1 over the signature of the entry of DR-2099-001, its subject naming DR-2099-002",
       sigs["r0"]["signature"]["value_b64"], dict(of_entry("r0"), sealed_id="DR-2099-002"), tsa1,
       "2026-09-25T12:00:00Z", 506)
    ts("r0_tsa2", "TSA 2, which the policy does not list, over the signature of the entry of DR-2099-001",
       sigs["r0"]["signature"]["value_b64"], of_entry("r0"), tsa2, "2026-09-25T12:00:00Z", 507, tsa_ref="tsa-example-2")
    ts("r0_early", "TSA 1 over the signature of the entry of DR-2099-001, before the time the signer states",
       sigs["r0"]["signature"]["value_b64"], of_entry("r0"), tsa1, "2026-09-25T11:00:00Z", 508)

    attachments = {
        "beside": {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION,
                   "organisation_seals": [export_seal["assertion"]],
                   "timestamps": [timestamps["r0"], timestamps["export_seal"]]},
        "seal_only": {"profile": SIGNATURES_PROFILE, "profile_version": SIGNATURES_VERSION,
                      "organisation_seals": [export_seal["assertion"]]},
    }
    att_validator = Draft202012Validator(attachment_schema)
    for name, att in attachments.items():
        found = list(att_validator.iter_errors(att))
        if found:
            raise ValueError(f"attachment {name} is not valid against the signatures attachment schema: {found[0].message}")
    for name, t in timestamps.items():
        if list(Draft202012Validator({"$ref": "#/$defs/timestamp", "$defs": attachment_schema["$defs"]}).iter_errors(t)):
            raise ValueError(f"timestamp {name} is not valid against the signatures attachment schema")

    # ---- the trust policy: the signatures vectors' policy, verbatim
    policy = copy.deepcopy(signatures["trust_policy"])

    # ---- the reference report of the signed export read with the attachment beside it
    def entry_result(i, name, record, extra_statement=None, time=None):
        s = sigs[name]["signature"]
        statement = {"status": "verified", "affirmation_record_covered": True}
        if extra_statement:
            statement["findings"] = [extra_statement]
        key_state = {"status": "verified", "key_ref": s["key_ref"], "time_basis": "stated_time", "time": s["sealed_at"]}
        if time:
            key_state.update(time_basis="independent_timestamp", time=time[1], timestamp_index=time[0])
        signature = {"status": "verified", "key_ref": s["key_ref"], "algorithm": "Ed25519",
                     "holder": "Example issuer (test only)", "reference_source": "trust_policy",
                     "certificate": "verified", "key_state": key_state}  # the policy pins org-seal-1's certificate
        time_assurance = {"status": "not_checked", "basis": "issuer_assertion",
                          "findings": ["no verified independent timestamp covers the entry's signature; sealed_at "
                                       "is the issuer's statement"]}
        if time:
            time_assurance = {"status": "verified", "basis": "independent_source", "source_ref": "tsa-example-1",
                              "no_later_than": time[1], "timestamp_index": time[0],
                              "findings": [f"the entry's signature, and so the digest it names, existed no later than "
                                           f"{time[1]} (tsa-example-1); not when the decision was made or affirmed"]}
        return {"export_index": i, "decision_id": value(records[record])["decision_id"],
                "representation": "original_sealed", "structural_validity": {"status": "verified"},
                "statement_check": statement,
                "cryptographic_verification": {"seal_digest": {"status": "verified", "reference_source": "same_export"},
                                               "signature": signature},
                "content_availability": {"status": "available"}, "time_assurance": time_assurance,
                "identity_assurance": {"status": "not_checked", "basis": "issuer_assertion"}}

    base_report = {
        "profile": REPORT_PROFILE, "profile_version": VERSION,
        "export_digest": export_digest, "export_entry_count": 3,
        "trust_policy_ref": policy["policy_ref"], "trust_policy": {"status": "verified"},
        "signatures_attachment_digest": sha256(compact(attachments["beside"])).hex(),
        "structural_validity": {"status": "verified"},
        "entries": [entry_result(0, "r0", "R0", time=(0, "2026-09-25T12:00:00Z")),
                    entry_result(1, "r1", "R1", "record_type is absent from the covered bytes and read as decision "
                                                 "(Core §6.2)"),
                    entry_result(2, "r2", "R2")],
        "object_links": {"status": "verified", "sequence": {"status": "verified", "completeness": "not_established",
                                                             "findings": ["no independent checkpoint was supplied"]}},
        "export_seal": {"status": "verified", "key_ref": "org-seal-1", "holder": "Example issuer (test only)",
                        "sealed_id": EXPORT_ID, "sealed_at": EXPORT_SEALED_AT,
                        "signature": {"status": "verified", "key_ref": "org-seal-1", "algorithm": "Ed25519",
                                      "reference_source": "trust_policy", "certificate": "verified"},
                        "subject": {"status": "verified", "checked_against": "export",
                                    "findings": [f"the export states no identifier; {EXPORT_ID} is the issuer's "
                                                 "reference for it"]},
                        "key_state": {"status": "verified", "key_ref": "org-seal-1",
                                      "time_basis": "independent_timestamp", "time": "2026-09-28T09:30:00Z",
                                      "timestamp_index": 1}},
        "scope_of_conclusion": {"covers": "supplied_export_only",
                                "not_assessed": ["legal_requirements", "conformance_level", "events_not_in_export",
                                                 "truth_of_record_content"]},
    }

    return {
        "about": f"Test vectors for the portable verification extension {VERSION}, written by generate_vectors.py from "
                 "published inputs. Records R0 to R2 and R4, the chain and the test keys are those of the anchoring "
                 "and signatures vectors; R3 and D2 are made from R2. An entry's signature is the signatures 0.2.0 "
                 "organisation seal of kind record over the entry's decision_id and its seal_hash or derived_digest; "
                 "r0 and r2 are byte for byte the signatures vectors' seal_record_r0 and seal_record_r2. Test keys "
                 "only, derived from their published seed texts: never real keys. Documents are read as JSON with no "
                 "whitespace, in UTF-8, by the convention of these cases.",
        "test_keys": test_keys,
        "records": record_vectors,
        "chain": {"about": "link(i) = SHA-256(link(i-1) || digest(i)), with 32 zero bytes before the first entry; "
                           "digest(i) is the entry's seal_hash, or D2's derived_digest for the fourth entry. L0 to L2 "
                           "are the anchoring vectors' links.", "links": links},
        "exports": exports,
        "entry_signatures": sigs,
        "export_seals": seals,
        "tokens": tokens,
        "timestamps": timestamps,
        "signatures_attachments": attachments,
        "trust_policy": policy,
        "base_context": {"export": "signed", "attachment": "beside"},
        "base_report": base_report,
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
