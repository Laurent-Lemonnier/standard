# SPDX-License-Identifier: Apache-2.0
"""Checks for the anchoring extension, version 0.2.0 (a proposal).

Runs the cases in cases.json over the values in vectors.json, which generate_vectors.py writes:

  schema cases      a base document from vectors.json (attachment, checkpoint, trust policy or report), changed by a
                    patch, against the extension's schemas; and the fixture exports against portable verification's
                    export schema
  vector cases      the values in vectors.json recomputed: SHA-256 and the chain links, the length-prefixed signed
                    bytes, the test keys from their seed texts, the Ed25519 signatures, the tokens' imprints, and
                    vectors.json itself, byte for byte, as generate_vectors.py writes it
  timestamp cases   the reference check of one independent timestamp (an RFC 3161 token) against the trust policy
  checkpoint cases  the reference check of one checkpoint: where the verifier obtained it, its signature, its key's
                    state when it signed, and the export compared with it
  pairing cases     a report read with the documents it covers (JSON Schema cannot compare two documents)

The reference check gives a result for every input that is valid against the schemas, and never stops on one. A case
in which it raises an exception fails, whatever the case expects.

Dependencies: jsonschema (tools/requirements.txt), cryptography and asn1crypto (requirements.txt in this folder). This
file parses the tokens with asn1crypto and verifies every signature with cryptography; it implements no
cryptographic primitive. A document's bytes as received are, in these cases, its JSON with no whitespace, in UTF-8.

Usage:  python extensions/anchoring/tests/run_checks.py
Exit code 0 = every case behaves as expected, 1 = a case does not.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

from asn1crypto import cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCHEMAS = {
    "attachment": HERE.parent / "schemas" / "anchoring-attachment.schema.json",
    "checkpoint": HERE.parent / "schemas" / "checkpoint.schema.json",
    "trust_policy": HERE.parent / "schemas" / "trust-policy.schema.json",
    "report": HERE.parent / "schemas" / "verification-report.schema.json",
}
PV_EXPORT_SCHEMA = ROOT / "extensions" / "portable-verification" / "schemas" / "verification-export.schema.json"
PROFILE, VERSION = "dps-anchoring", "0.2.0"
MAGIC = b"DPS-SIG\x00"
MAX_COUNT = 2 ** 53 - 1  # the largest count: JSON readers agree exactly on every integer up to it (RFC 8259 6)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CHECKS = ("token", "message_imprint", "subject_bytes", "message_digest", "tsa_signature", "signer_certificate",
          "tsa_state")
CHECKPOINT_DIMENSIONS = ("status", "independence", "signature", "key_state", "comparison")
READABLE = {"application/json"}  # media types this check reads an issuer's time from


def sha256(data):
    return hashlib.sha256(data).digest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def instant(text):
    """A time read as an instant, or None when it is not a time or has no offset. A date that does not exist, such as
    2026-02-30, and a leap second (23:59:60) are not times."""
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    return t if t.tzinfo is not None else None


def json_integer(x):
    """A number written as a JSON integer. JSON Schema accepts 3.0 as an integer; json reads it as a float."""
    return isinstance(x, int) and not isinstance(x, bool)


def iso(t):
    t = t.astimezone(timezone.utc)
    out = t.strftime("%Y-%m-%dT%H:%M:%S")
    if t.microsecond:
        out += "." + f"{t.microsecond:06d}".rstrip("0")
    return out + "Z"


def strict_json(raw):
    """UTF-8 JSON with duplicate keys and non-finite numbers rejected."""
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate key {k!r}")
            out[k] = v
        return out

    def constant(name):
        raise ValueError(f"not JSON: {name}")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


# ---------------------------------------------------------------- the shared signed-bytes rule

def lp(data):
    """4-byte big-endian length, then the bytes."""
    return len(data).to_bytes(4, "big") + data


def signed_bytes(fields):
    return MAGIC + b"".join(lp(f) for f in fields)


class Unencodable(ValueError):
    """A value the signed-bytes rule cannot encode. The verifier reports it as failed."""


def text_field(name, value):
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise Unencodable(f"{name} has no UTF-8 encoding: it holds a lone surrogate") from None


def count_field(value):
    if not json_integer(value):
        raise Unencodable(f"count is written as {value!r}, not as a JSON integer")
    if not 1 <= value <= MAX_COUNT:
        raise Unencodable(f"count is {value}; a checkpoint's count is from 1 to 2^53 - 1")
    return value.to_bytes(8, "big")


def checkpoint_signed_bytes(cp):
    """profile, profile_version, "checkpoint", key_ref, chain_id, count (8-byte big-endian unsigned), head_link (32 raw
    bytes), checkpoint_time (UTF-8). The verifier takes the first three from what it checks, never from the object.
    Raises Unencodable for a value the rule cannot encode."""
    return signed_bytes([PROFILE.encode("utf-8"), VERSION.encode("utf-8"), b"checkpoint",
                         text_field("key_ref", cp["signature"]["key_ref"]), text_field("chain_id", cp["chain_id"]),
                         count_field(cp["count"]), bytes.fromhex(cp["head_link"]),
                         text_field("checkpoint_time", cp["checkpoint_time"])])


# ---------------------------------------------------------------- the verifier's trust policy

def check_policy(policy):
    """One public key has one key reference, one holder and one role; a reference names one entry. A policy that
    breaks this is refused as a whole: every dimension that relies on it is reported as failed. The same rule, the
    same result and the same wording as the signatures profile's check."""
    findings = []
    for items, ref, what in ((policy["keys"], "key_ref", "key reference"), (policy["tsas"], "tsa_ref",
                             "authority reference"), (policy["checkpoint_sources"], "source_ref", "source reference")):
        seen = set()
        for item in items:
            if item[ref] in seen:
                findings.append(f"{what} {item[ref]} is listed twice; a {what} names one "
                                + ("key" if ref == "key_ref" else "entry"))
            seen.add(item[ref])
    by_public = {}
    for k in policy["keys"]:
        by_public.setdefault((k["algorithm"], k["public_key_hex"].lower()), []).append(k)
    for group in by_public.values():
        if len(group) < 2:
            continue
        what = [w for w, f in (("references", "key_ref"), ("holders", "holder"), ("roles", "role"))
                if len({k[f] for k in group}) > 1]
        findings.append(f"{', '.join(k['key_ref'] for k in group)} are one public key listed {len(group)} times, under "
                        f"different {' and '.join(what) if what else 'entries'}; one public key has one key "
                        "reference, one holder and one role")
    return {"status": "failed", "findings": findings} if findings else {"status": "verified"}


def refused(policy_result, what):
    return {"status": "failed", "findings": [f"{what} not checked: the trust policy is refused ("
                                             + "; ".join(policy_result["findings"]) + ")"]}


# ---------------------------------------------------------------- portable verification's chain

def entry_digests(export):
    return [e["seal"]["seal_hash"] if "seal" in e else e["derived_digest"] for e in export["entries"]]


def link_at(digests, sequence):
    """link(sequence) = SHA-256(link(sequence - 1) || digest(sequence)), with 32 zero bytes before the first entry."""
    head = bytes(32)
    for d in digests[:sequence + 1]:
        head = sha256(head + bytes.fromhex(d))
    return head.hex()


def affirmation_time(entry):
    """The issuer's affirmation time, read from covered bytes that match the entry's seal, or the reason it cannot be."""
    if entry["content"]["availability"] != "available":
        return None, f"{entry['decision_id']}: the covered bytes are unavailable"
    if entry["covered_representation"]["media_type"] not in READABLE:
        return None, f"{entry['decision_id']}: this check cannot read the media type"
    raw = base64.b64decode(entry["content"]["covered_bytes_b64"], validate=True)
    if "seal" not in entry or sha256(raw).hex() != entry["seal"]["seal_hash"]:
        return None, f"{entry['decision_id']}: the covered bytes do not match the seal, so their time is not read"
    try:
        record = strict_json(raw)
    except (ValueError, RecursionError) as exc:  # RecursionError: JSON nested too deep to read
        return None, f"{entry['decision_id']}: the covered bytes cannot be read: {exc}"
    stated = ((record.get("affirmation_record") if isinstance(record, dict) else None) or {}).get("timestamp")
    if not isinstance(stated, str):
        return None, f"{entry['decision_id']}: the covered bytes state no affirmation_record.timestamp"
    if instant(stated) is None:
        return None, f"{entry['decision_id']}: the affirmation time {stated!r} cannot be read as an instant"
    return stated, None


# ---------------------------------------------------------------- an independent timestamp

def subject_value(subject):
    if subject["kind"] == "signature":
        return base64.b64decode(subject["value_b64"], validate=True)
    return bytes.fromhex(subject["value_hex"])


def shown_subject(subject):
    return {k: v for k, v in subject.items() if k not in ("value_hex", "value_b64")}


def read_token(raw):
    """The TSTInfo, its exact bytes and the one SignerInfo of a TimeStampToken, or the reason it is not one."""
    info = cms.ContentInfo.load(raw, strict=True)
    if info["content_type"].native != "signed_data":
        raise ValueError("not CMS SignedData")
    signed_data = info["content"]
    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise ValueError(f"the encapsulated content is {encap['content_type'].native}, not id-ct-TSTInfo")
    if len(signed_data["signer_infos"]) != 1:
        raise ValueError("a time-stamp token has exactly one signer")
    econtent = encap["content"].contents
    tst = tsp.TSTInfo.load(econtent, strict=True)
    if tst["version"].native != "v1":
        raise ValueError("TSTInfo version is not 1")
    signer = signed_data["signer_infos"][0]
    if not signer["signed_attrs"].dump().startswith(b"\xa0"):
        raise ValueError("the signer has no signed attributes (RFC 5652 5.3: required for a TSTInfo)")
    tst.native, signer.native  # parse every field now, so a malformed token fails here
    if not tst["gen_time"].contents.endswith(b"Z"):
        raise ValueError(f"the genTime {tst['gen_time'].contents.decode('ascii', 'replace')} is not in UTC "
                         "(RFC 3161 2.4.2: it ends in Z)")
    try:
        tst["gen_time"].native + accuracy(tst)
    except OverflowError:
        raise ValueError("the genTime plus the accuracy is past the year 9999, so it cannot be written as a time")
    return tst, econtent, signer


def accuracy(tst):
    """The token's accuracy. RFC 3161 2.4.2: millis and micros are from 1 to 999; seconds cannot be negative."""
    n = tst["accuracy"].native
    if n is None:
        return timedelta(0)
    seconds, millis, micros = n.get("seconds"), n.get("millis"), n.get("micros")
    if (seconds is not None and seconds < 0) or any(x is not None and not 1 <= x <= 999 for x in (millis, micros)):
        raise ValueError(f"the accuracy (seconds {seconds}, millis {millis}, micros {micros}) is out of range")
    return timedelta(seconds=seconds or 0, milliseconds=millis or 0, microseconds=micros or 0)


def check_timestamp(ts, policy, export, chain_id, held):
    """Reference check of one timestamp assertion. held: the checkpoints the verifier holds, for a signature subject."""
    checks = {k: "not_checked" for k in CHECKS}
    findings = []
    subject = ts["subject"]
    out = {"subject": shown_subject(subject), "tsa_ref": ts["tsa_ref"], "checks": checks, "findings": findings,
           "issuer_time": {"status": "not_checked"}}
    value = subject_value(subject)

    # The subject: are its bytes the seal, link or signature value it names?
    kind = subject["kind"]
    if kind == "seal":
        seals = {e["seal"]["seal_hash"] for e in export["entries"] if e["decision_id"] == subject["decision_id"]
                 and "seal" in e}
        if not seals:
            findings.append(f"the export holds no sealed entry for {subject['decision_id']}")
        elif seals == {subject["value_hex"]}:
            checks["subject_bytes"] = "verified"
        else:
            checks["subject_bytes"] = "failed"
            findings.append(f"the subject's value is not the seal of {subject['decision_id']} in the export")
    elif kind == "chain_link":
        digests = entry_digests(export)
        if not json_integer(subject["sequence"]):
            checks["subject_bytes"] = "failed"
            findings.append(f"the subject's sequence is written as {subject['sequence']!r}, not as a JSON integer")
        elif subject["chain_id"] != chain_id:
            findings.append(f"the subject names chain {subject['chain_id']}; the verifier checks {chain_id}")
        elif subject["sequence"] >= len(digests):
            findings.append(f"the export has {len(digests)} entries, so link({subject['sequence']}) cannot be "
                            "recomputed")
        elif link_at(digests, subject["sequence"]) == subject["value_hex"]:
            checks["subject_bytes"] = "verified"
        else:
            checks["subject_bytes"] = "failed"
            findings.append(f"the subject's value is not link({subject['sequence']}) of the export")
    elif subject["of"]["assertion"] != "checkpoint":
        findings.append(f"the subject names a {subject['of']['assertion']} of the signatures profile, which checks it; "
                        "this check holds checkpoints only")
    else:
        same = [c for c in held if "signature" in c and c["signature"]["value_b64"] == subject["value_b64"]]
        if not same:
            findings.append("the verifier holds no checkpoint with this signature value")
        else:
            c, of = same[0], subject["of"]
            if (c["signature"]["key_ref"], c["chain_id"], c["count"]) == (of["key_ref"], of["chain_id"], of["count"]):
                checks["subject_bytes"] = "verified"
            else:
                checks["subject_bytes"] = "failed"
                findings.append("the signature value is that of another checkpoint than the subject names")

    # The token itself.
    try:
        tst, econtent, signer = read_token(base64.b64decode(ts["token_b64"], validate=True))
    except Exception as exc:  # asn1crypto raises several types for bytes that are not a token
        checks["token"] = "failed"
        findings.append(f"not a valid time-stamp token: {exc}")
        out["status"] = "failed"
        return out
    checks["token"] = "verified"
    imprint = tst["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256":
        checks["message_imprint"] = "failed"
        findings.append(f"the messageImprint uses {imprint['hash_algorithm']['algorithm'].native}; the profile "
                        "requires SHA-256")
    elif imprint["hashed_message"].native != sha256(value):
        checks["message_imprint"] = "failed"
        findings.append("the token covers other bytes than the subject names")
    else:
        checks["message_imprint"] = "verified"

    attrs = signer["signed_attrs"]
    values = {}
    for a in attrs:
        values.setdefault(a["type"].native, []).append(a["values"])
    content_type, digest = values.get("content_type", []), values.get("message_digest", [])
    if len(content_type) != 1 or len(content_type[0]) != 1 or content_type[0][0].native != "tst_info":
        checks["message_digest"] = "failed"
        findings.append("the signed content-type attribute is not one id-ct-TSTInfo")
    elif len(digest) != 1 or len(digest[0]) != 1 or digest[0][0].native != sha256(econtent):
        checks["message_digest"] = "failed"
        findings.append("the signed messageDigest is not the SHA-256 of the encapsulated TSTInfo")
    else:
        checks["message_digest"] = "verified"

    policy_result = check_policy(policy)
    if policy_result["status"] != "verified":
        checks["tsa_signature"] = checks["tsa_state"] = "failed"
        findings.append(refused(policy_result, "the authority")["findings"][0])
        out["status"] = "failed"
        return out
    tsa = next((t for t in policy["tsas"] if t["tsa_ref"] == ts["tsa_ref"]), None)
    if tsa is None:
        checks["tsa_signature"] = "failed"
        findings.append(f"{ts['tsa_ref']} is not a time-stamping authority in the trust policy")
    else:
        cert_der = base64.b64decode(tsa["certificate_b64"], validate=True)
        try:
            pinned = asn1_x509.Certificate.load(cert_der, strict=True)
            pinned.native
            key = x509.load_der_x509_certificate(cert_der).public_key()
        except Exception:  # cryptography and asn1crypto raise several types for bytes that are not a certificate
            pinned = None
        algorithms = (signer["digest_algorithm"]["algorithm"].native, signer["signature_algorithm"]["algorithm"].native)
        sid = signer["sid"]
        if pinned is None:
            names_pinned = False
        elif sid.name == "issuer_and_serial_number":
            names_pinned = (sid.chosen["issuer"].dump() == pinned.issuer.dump()
                            and sid.chosen["serial_number"].native == pinned.serial_number)
        else:
            names_pinned = sid.chosen.native == pinned.key_identifier
        if pinned is None:
            checks["tsa_signature"] = "failed"
            findings.append(f"the certificate pinned for {ts['tsa_ref']} cannot be read")
        elif algorithms != ("sha256", "sha256_ecdsa") or not (
                isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"):
            checks["tsa_signature"] = "not_supported"
            findings.append(f"this check supports ECDSA P-256 with SHA-256; the token uses {algorithms[1]}")
        elif not names_pinned:
            checks["tsa_signature"] = "failed"
            findings.append(f"the token names another signer than the certificate pinned for {ts['tsa_ref']}")
        else:
            encoded = attrs.dump()  # tagged [0] in the token; signed as a SET OF (RFC 5652 5.4), as it appears
            try:
                key.verify(signer["signature"].native, b"\x31" + encoded[1:], ec.ECDSA(hashes.SHA256()))
                checks["tsa_signature"] = "verified"
            except InvalidSignature:
                checks["tsa_signature"] = "failed"
                findings.append(f"the signature does not verify with the certificate pinned for {ts['tsa_ref']}")
        v2 = values.get("signing_certificate_v2")
        if pinned is None:
            findings.append("no certificate to compare the ESSCertIDv2 with")
        elif v2 is None:
            findings.append("the token has no ESSCertIDv2 (signingCertificateV2); the signer is identified by its "
                            "sid only")
        elif len(v2) != 1 or len(v2[0]) != 1:
            checks["signer_certificate"] = "failed"
            findings.append("the signingCertificateV2 attribute is not one attribute with one value")
        elif len(v2[0][0]["certs"]) == 0:
            checks["signer_certificate"] = "failed"
            findings.append("the signingCertificateV2 attribute lists no certificate")
        else:
            first = v2[0][0]["certs"][0]
            if first["hash_algorithm"]["algorithm"].native != "sha256":
                # As if there were none: the pinned key and the signer identifier already fix who signed.
                findings.append(f"the ESSCertIDv2 is made with {first['hash_algorithm']['algorithm'].native}, and this "
                                "check reads one made with SHA-256 only; the signer is identified by its sid only")
            elif first["cert_hash"].native == sha256(cert_der):
                checks["signer_certificate"] = "verified"
            else:
                checks["signer_certificate"] = "failed"
                findings.append(f"the ESSCertIDv2 names another certificate than the one pinned for {ts['tsa_ref']}")
        gen = tst["gen_time"].native
        window = instant(tsa["not_before"]), instant(tsa["not_after"])
        if None in window or (tsa.get("revoked_at") and instant(tsa["revoked_at"]) is None):
            checks["tsa_state"] = "failed"
            findings.append(f"a time in the trust policy for {ts['tsa_ref']} cannot be read as a UTC time")
        elif not window[0] <= gen <= window[1]:
            checks["tsa_state"] = "failed"
            findings.append(f"genTime {iso(gen)} is outside the policy's window for {ts['tsa_ref']}")
        elif tsa.get("revocation_reason") == "compromised":
            checks["tsa_state"] = "failed"
            findings.append(f"{ts['tsa_ref']} is revoked as compromised: none of its tokens can show its own time")
        elif tsa.get("revoked_at") and gen >= instant(tsa["revoked_at"]):
            checks["tsa_state"] = "failed"
            findings.append(f"genTime {iso(gen)} is not before {ts['tsa_ref']} was superseded")
        else:
            checks["tsa_state"] = "verified"

    statuses = set(checks.values())
    required = [checks[k] for k in CHECKS if k != "signer_certificate"]
    if "failed" in statuses:
        out["status"] = "failed"
    elif "not_supported" in statuses:
        out["status"] = "not_supported"
    elif all(s == "verified" for s in required) and checks["signer_certificate"] in ("verified", "not_checked"):
        out["status"] = "verified"
    else:
        out["status"] = "not_checked"
    if out["status"] != "verified":
        return out

    gen = tst["gen_time"].native
    upper = gen + accuracy(tst)
    out.update(reference_source="trust_policy", gen_time=iso(gen), existed_no_later_than=iso(upper))
    out["_upper"], out["_value"] = upper, value

    # The issuer's own time for the subject, compared with T. It never changes the timestamp's own status.
    if kind == "signature":
        stated, stated_in = same[0]["checkpoint_time"], "checkpoint_time"
        why = None if instant(stated) else f"the checkpoint_time {stated} is not a real UTC time: not compared"
    else:
        entries = export["entries"]
        upto = ([e for e in entries if e["decision_id"] == subject["decision_id"]][:1] if kind == "seal"
                else entries[:subject["sequence"] + 1])
        read = [affirmation_time(e) for e in upto]
        why = next((w for _, w in read if w), None)
        stated = max((s for s, _ in read if s), key=instant, default=None)
        stated_in = "affirmation_record.timestamp"
    if why or stated is None:
        out["issuer_time"] = {"status": "not_checked", "findings": [why or "no issuer's time to compare"]}
    else:
        late = instant(stated) > upper
        out["issuer_time"] = {"status": "failed" if late else "verified", "stated": stated, "stated_in": stated_in,
                              "consistency": "inconsistent" if late else "consistent"}
        if late:
            out["issuer_time"]["findings"] = [f"the issuer's time {stated} is later than the timestamp "
                                              f"({iso(upper)})"]
    return out


# ---------------------------------------------------------------- an independent checkpoint

def combine(*statuses):
    s = set(statuses)
    for worst in ("failed", "unavailable", "not_supported", "not_checked"):
        if worst in s:
            return worst
    return "verified"


def key_state(key, cp, covering):
    """The key's state when the checkpoint was signed. covering: (index, verified timestamp result) over its signature.
    The lower bound (not_before) rests on the stated time; the upper bounds rest on the earliest independent
    timestamp when there is one, and otherwise on the stated time."""
    stated = instant(cp["checkpoint_time"])
    best = min(covering, key=lambda c: c[1]["_upper"], default=None)
    upper = best[1]["_upper"] if best else stated
    basis = "independent_timestamp" if best else "stated_time"
    out = {"key_ref": key["key_ref"]}
    if key.get("revocation_reason"):
        out["revocation_reason"] = key["revocation_reason"]
    findings = []
    status = "verified"
    bounds = [instant(key[k]) for k in ("not_before", "not_after")] + (
        [instant(key["revoked_at"])] if key.get("revoked_at") else [])
    if stated is None or None in bounds:
        status = "failed"
        findings.append(("checkpoint_time" if stated is None else f"a time in the trust policy for {key['key_ref']}")
                        + " cannot be read as a UTC time (a date that does not exist, or a leap second), so the "
                        "key's state when it signed cannot be read")
    elif stated < instant(key["not_before"]):
        status = "failed"
        findings.append(f"stated as made at {cp['checkpoint_time']}, before {key['key_ref']}'s not_before")
    elif upper > instant(key["not_after"]):
        status = "failed"
        findings.append(f"made after {key['key_ref']}'s not_after, by its {basis.replace('_', ' ')}")
    elif key.get("revocation_reason") == "superseded":
        if upper < instant(key["revoked_at"]):
            findings.append(f"{key['key_ref']} was superseded at {key['revoked_at']}; the signature is earlier by its "
                            f"{basis.replace('_', ' ')}")
        else:
            status = "failed"
            findings.append(f"not made before {key['key_ref']} was superseded at {key['revoked_at']}, by its "
                            f"{basis.replace('_', ' ')}")
    elif key.get("revocation_reason") == "compromised":
        if best is None:
            status = "unavailable"
            findings.append(f"{key['key_ref']} was revoked as compromised at {key['revoked_at']} and no independent "
                            "timestamp covers the signature: the time cannot be established")
        elif upper >= instant(key["revoked_at"]):
            status = "failed"
            findings.append(f"the earliest independent timestamp over the signature ({iso(upper)}) is not earlier "
                            f"than the compromise at {key['revoked_at']}")
    out["status"] = status
    if status == "verified":
        out.update(time_basis=basis, time=iso(upper))
        if best:
            out["timestamp_index"] = best[0]
    if findings:
        out["findings"] = findings
    return out


def compare(export, cp):
    digests = entry_digests(export)
    n, count = len(digests), cp["count"]
    if n < count:
        return {"status": "failed", "findings": [f"the export has {n} entries; the checkpoint fixes {count}"]}
    if link_at(digests, count - 1) != cp["head_link"]:
        return {"status": "failed", "findings": [f"the export's first {count} entries do not give the checkpoint's "
                                                 "head link: an entry was dropped, reordered or rewritten"]}
    out = {"status": "verified", "covered_count": count, "not_covered_indexes": list(range(count, n))}
    if n == count + 1:
        out["findings"] = [f"entry {count} comes after the checkpoint and is not covered"]
    elif n > count:
        out["findings"] = [f"entries {count} to {n - 1} come after the checkpoint and are not covered"]
    return out


def check_checkpoint(obtained, policy, export, chain_id, ts_results):
    """Reference check of one checkpoint, as the verifier obtained it (or could not)."""
    cp, where = obtained.get("checkpoint"), obtained["obtained_from"]
    out = {"obtained_from": where}
    if obtained.get("source_ref"):
        out["source_ref"] = obtained["source_ref"]
    if cp is not None:
        out["checkpoint"] = {k: cp[k] for k in ("chain_id", "count", "head_link", "checkpoint_time") if k in cp}
    policy_result = check_policy(policy)
    is_refused = policy_result["status"] != "verified"
    source = next((s for s in policy["checkpoint_sources"] if s["source_ref"] == obtained.get("source_ref")), None)
    if where == "same_export":
        independence = {"status": "failed", "findings": ["found in the export: a checkpoint from the same export is "
                                                         "never independent"]}
    elif is_refused:
        independence = refused(policy_result, "the source")
    elif source is None:
        independence = {"status": "failed", "findings": [f"{obtained.get('source_ref')} is not a checkpoint source "
                                                         "in the trust policy"]}
    elif cp is not None and cp.get("chain_id") not in source["chain_ids"]:
        independence = {"status": "failed", "findings": [f"the trust policy does not configure "
                                                         f"{source['source_ref']} for {cp.get('chain_id')}"]}
    else:
        independence = {"status": "verified"}
    out["independence"] = independence
    if cp is None:
        out.update(status="failed" if is_refused else "unavailable", signature={"status": "not_checked"},
                   key_state={"status": "not_checked"},
                   comparison={"status": "not_checked"},
                   findings=[f"{obtained.get('source_ref')} gave no checkpoint for {chain_id}"])
        return out

    keys = {k["key_ref"]: k for k in policy["keys"]}
    key = None
    if "signature" not in cp:
        signature = {"status": "not_checked", "findings": ["the checkpoint carries no signature"]}
    elif is_refused:
        signature = {"key_ref": cp["signature"]["key_ref"], **refused(policy_result, "the signature")}
    elif source is not None and source["kind"] != "witness":
        signature = {"status": "not_supported", "findings": [f"{source['source_ref']} is a {source['kind']}; this "
                                                             "version defines no format for it"]}
    else:
        s = cp["signature"]
        signature = {"key_ref": s["key_ref"]}
        key = keys.get(s["key_ref"])
        if key is None:
            signature.update(status="failed", findings=[f"{s['key_ref']} is not a key in the trust policy"])
        elif source is not None and s["key_ref"] not in source.get("key_refs", []):
            signature.update(status="failed", findings=[f"the trust policy does not list {s['key_ref']} for "
                                                        f"{source['source_ref']}"])
        elif key["role"] != "witness":
            signature.update(status="failed", findings=[f"{s['key_ref']} is a key in role {key['role']}; only a "
                                                        "witness key signs a checkpoint"])
        elif s["algorithm"] != "Ed25519" or key["algorithm"] != "Ed25519":
            signature.update(status="not_supported", findings=[f"this check supports Ed25519; the checkpoint uses "
                                                               f"{s['algorithm']}"])
        else:
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key_hex"]))
            try:
                public.verify(base64.b64decode(s["value_b64"], validate=True), checkpoint_signed_bytes(cp))
                signature.update(status="verified", reference_source="trust_policy")
            except Unencodable as exc:
                signature.update(status="failed", findings=[f"the signed bytes cannot be built: {exc}"])
            except InvalidSignature:
                signature.update(status="failed", findings=["the signature does not verify over the checkpoint's "
                                                            "signed bytes"])
    out["signature"] = signature

    if is_refused:
        out["key_state"] = refused(policy_result, "the key state")
    elif signature["status"] == "verified":
        value = base64.b64decode(cp["signature"]["value_b64"])
        covering = [(i, r) for i, r in enumerate(ts_results) if r["status"] == "verified" and r["_value"] == value]
        out["key_state"] = key_state(key, cp, covering)
    else:
        out["key_state"] = {"status": "not_checked"}

    out["status"] = combine(independence["status"], signature["status"], out["key_state"]["status"])
    if out["status"] != "verified":
        out["comparison"] = {"status": "not_checked", "findings": ["compared only with a verified independent "
                                                                   "checkpoint"]}
    elif cp["chain_id"] != chain_id:
        out["comparison"] = {"status": "not_checked", "findings": [f"the checkpoint is for {cp['chain_id']}; the "
                                                                   f"verifier checks {chain_id}"]}
    else:
        out["comparison"] = compare(export, cp)
    return out


# ---------------------------------------------------------------- a report read with its documents

def run_context(ctx):
    held = [o["checkpoint"] for o in ctx["obtained"] if o.get("checkpoint") and "signature" in o["checkpoint"]]
    ts = (ctx["attachment"] or {}).get("timestamps", [])
    ts_results = [check_timestamp(t, ctx["policy"], ctx["export"], ctx["chain_id"], held) for t in ts]
    cp_results = [check_checkpoint(o, ctx["policy"], ctx["export"], ctx["chain_id"], ts_results)
                  for o in ctx["obtained"]]
    return ts_results, cp_results


def not_integers(doc, path=""):
    """The paths of the numbers in a document that are not written as JSON integers, such as 0.0."""
    if isinstance(doc, float):
        return [path]
    if isinstance(doc, dict):
        return [p for k, x in doc.items() for p in not_integers(x, f"{path}/{k}")]
    if isinstance(doc, list):
        return [p for i, x in enumerate(doc) for p in not_integers(x, f"{path}/{i}")]
    return []


def read_with_documents(report, ctx):
    """What a reader holding a report and the documents it covers checks; JSON Schema cannot compare documents."""
    problems = [f"{p} is not written as a JSON integer; every number in a report is one" for p in not_integers(report)]
    ts_ref, cp_ref = run_context(ctx)
    attachment, export = ctx["attachment"], ctx["export"]
    if report["trust_policy_ref"] != ctx["policy"]["policy_ref"]:
        problems.append("trust_policy_ref is not the policy the documents are read with")
    policy_ref = check_policy(ctx["policy"])
    if report["trust_policy"]["status"] != policy_ref["status"]:
        problems.append(f"the trust policy reported {report['trust_policy']['status']}; the reference check finds "
                        f"{policy_ref['status']}")
    if attachment is not None and report.get("attachment_digest") != sha256(compact(attachment)).hex():
        problems.append("attachment_digest is not the digest of the attachment read with it")
    if report["export_digest"] != sha256(compact(export)).hex():
        problems.append("export_digest is not the digest of the export read with it")
    if report["export_entry_count"] != len(export["entries"]):
        problems.append(f"export_entry_count is {report['export_entry_count']}; the export has "
                        f"{len(export['entries'])} entries")
    if report["chain_id"] != ctx["chain_id"]:
        problems.append("chain_id is not the chain the documents are read for")

    stated = (attachment or {}).get("timestamps", [])
    for label, count_key, results, n, key in (("timestamp", "timestamp_count", report["timestamps"], len(stated),
                                               "timestamp_index"),
                                              ("checkpoint", "checkpoint_count", report["checkpoints"],
                                               len(ctx["obtained"]), "checkpoint_index")):
        if report[count_key] != n:
            problems.append(f"{count_key} is {report[count_key]}; there are {n}")
        indexes = sorted(r[key] for r in results)
        if indexes != list(range(n)):
            problems.append(f"{label} results name {indexes}; each of 0 to {n - 1} must appear once")

    for r in report["timestamps"]:
        i = r["timestamp_index"]
        if not json_integer(i) or i >= len(stated):
            continue
        ref = ts_ref[i]
        if r["subject"] != shown_subject(stated[i]["subject"]) or r["tsa_ref"] != stated[i]["tsa_ref"]:
            problems.append(f"timestamp {i}: subject or tsa_ref not as the attachment states them")
        if r["status"] == "verified" and ref["status"] != "verified":
            problems.append(f"timestamp {i}: reported verified, but the reference check finds {ref['status']}")
        for k in CHECKS:
            if r["checks"][k] == "verified" and ref["checks"][k] != "verified":
                problems.append(f"timestamp {i}: {k} reported verified, but it is {ref['checks'][k]}")
        if r["status"] == ref["status"] == "verified":
            if (r["gen_time"], r["existed_no_later_than"]) != (ref["gen_time"], ref["existed_no_later_than"]):
                problems.append(f"timestamp {i}: gen_time or existed_no_later_than not as the token gives them")
        it, ri = r["issuer_time"], ref["issuer_time"]
        if it["status"] == "verified" and ri["status"] != "verified":
            problems.append(f"timestamp {i}: the issuer's time reported consistent, but it is {ri['status']}")
        if ri.get("consistency") == "inconsistent" and it.get("consistency") != "inconsistent":
            problems.append(f"timestamp {i}: an issuer's time later than the timestamp not reported as inconsistent")
        if "stated" in it and "stated" in ri and (it["stated"], it["stated_in"]) != (ri["stated"], ri["stated_in"]):
            problems.append(f"timestamp {i}: the issuer's time not carried through as stated")

    for r in report["checkpoints"]:
        i = r["checkpoint_index"]
        if not json_integer(i) or i >= len(ctx["obtained"]):
            continue
        ref = cp_ref[i]
        if (r["obtained_from"], r.get("source_ref")) != (ref["obtained_from"], ref.get("source_ref")):
            problems.append(f"checkpoint {i}: not reported as obtained from where it was")
        if ref.get("checkpoint") is not None and r.get("checkpoint") != ref["checkpoint"]:
            problems.append(f"checkpoint {i}: values not as the source gave them")
        for dim in CHECKPOINT_DIMENSIONS:
            got = r[dim] if dim == "status" else r[dim]["status"]
            want = ref[dim] if dim == "status" else ref[dim]["status"]
            if got == "verified" and want != "verified":
                problems.append(f"checkpoint {i}: {dim} reported verified, but the reference check finds {want}")
        ks, rks = r["key_state"], ref["key_state"]
        if ks["status"] == rks["status"] == "verified" and any(
                ks.get(k) != rks.get(k) for k in ("time_basis", "time", "timestamp_index", "revocation_reason")):
            problems.append(f"checkpoint {i}: the key state's time and its basis not reported as found")
        rc, refc = r["comparison"], ref["comparison"]
        if refc["status"] == "failed" and rc["status"] != "failed":
            problems.append(f"checkpoint {i}: a comparison that fails not reported as failed")
        if rc["status"] == refc["status"] == "verified" and (rc["covered_count"], rc["not_covered_indexes"]) != (
                refc["covered_count"], refc["not_covered_indexes"]):
            problems.append(f"checkpoint {i}: entries covered and not covered not reported as found")
    return problems


# ---------------------------------------------------------------- the cases

def pointer_get(doc, pointer):
    for p in [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]:
        doc = doc[int(p)] if isinstance(doc, list) else doc[p]
    return doc


def locate(doc, pointer):
    *parents, last = [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]
    for p in parents:
        doc = doc[int(p)] if isinstance(doc, list) else doc[p]
    return doc, (int(last) if isinstance(doc, list) else last)


def apply_patch(doc, patch, vectors, digests=None):
    """Each operation sets (a value, a value from vectors.json, or a document's digest), removes, copies, inserts or
    moves the member at a JSON Pointer."""
    doc = copy.deepcopy(doc)
    for op in patch:
        if "remove" in op:
            parent, key = locate(doc, op["remove"])
            del parent[key]
            continue
        if "insert" in op:
            parent, key = locate(doc, op["insert"])
            parent.insert(key, copy.deepcopy(source_value(op, vectors, digests)))
            continue
        if "move" in op:
            parent, key = locate(doc, op["move"])
            value = parent.pop(key)
            parent, key = locate(doc, op["to"])
            parent.insert(key, value)
            continue
        if "copy" in op:
            parent, key = locate(doc, op["copy"])
            value, pointer = parent[key], op["to"]
        else:
            value, pointer = source_value(op, vectors, digests), op["set"]
        parent, key = locate(doc, pointer)
        parent[key] = copy.deepcopy(value)
    return doc


def source_value(op, vectors, digests):
    if "vector" in op:
        return copy.deepcopy(pointer_get(vectors, op["vector"]))
    if "digest_of" in op:
        return digests[op["digest_of"]]
    return op["value"]


def resolve(spec, vectors):
    """A document named by a pointer into vectors.json, or {"from": pointer, "patch": [...]}."""
    if isinstance(spec, str):
        return copy.deepcopy(pointer_get(vectors, spec))
    return apply_patch(pointer_get(vectors, spec["from"]), spec.get("patch", []), vectors)


def errors(validator, doc):
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message[:100]}" for e in validator.iter_errors(doc)]


def schema_case(c, v, validators):
    doc = apply_patch(pointer_get(v, c["base"]), c["patch"], v)
    found = errors(validators[c["schema"]], doc)
    return ("pass" if not found else "fail"), found


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_vectors", HERE / "generate_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def vector_case(c, v):
    kind = c["check"]
    bad = []
    if kind == "known_vector":
        return ("match" if sha256(c["text"].encode()).hex() == c["digest"] else "mismatch"), ""
    if kind == "length_prefix":
        bad = [t for t, h in c["vectors"] if lp(t.encode("utf-8")).hex() != h]
    elif kind == "record_seals":
        bad = [k for k, r in v["records"].items() if sha256(r["text"].encode("utf-8")).hex() != r["seal_hash"]]
    elif kind == "chain_links":
        seal = {k: r["seal_hash"] for k, r in v["records"].items()}
        for name, order in c["chains"].items():
            for i, link_name in enumerate(order["links"]):
                if link_at([seal[k] for k in order["records"]], i) != v["chain"]["links"][link_name]:
                    bad.append(f"{name}: {link_name}")
    elif kind == "exports":
        for name, export in v["exports"].items():
            for i, e in enumerate(export["entries"]):
                raw = base64.b64decode(e["content"]["covered_bytes_b64"], validate=True)
                if sha256(raw).hex() != e["seal"]["seal_hash"]:
                    bad.append(f"{name} entry {i}")
            digests = entry_digests(export)
            for i, e in enumerate(export["entries"][1:], 1):
                if name in c["chained"] and e["chain"]["previous_link"] != link_at(digests, i - 1):
                    bad.append(f"{name} entry {i}: previous_link")
    elif kind == "test_keys":
        for name, k in v["test_keys"].items():
            seed = sha256(k["seed_text"].encode("utf-8"))
            if k["algorithm"] == "Ed25519":
                public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            else:
                private = ec.derive_private_key(int.from_bytes(seed, "big") % (P256_N - 1) + 1, ec.SECP256R1())
                public = private.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint)
            if public.hex() != k["public_key_hex"]:
                bad.append(name)
    elif kind == "signed_bytes":
        bad = [n for n, x in v["checkpoints"].items() if checkpoint_signed_bytes(x["checkpoint"]).hex() !=
               x["signed_bytes_hex"]]
    elif kind == "signed_bytes_fields":
        cp = v["checkpoints"][c["checkpoint"]]["checkpoint"]
        built = MAGIC.hex() + "".join(lp(bytes.fromhex(f)).hex() for f in c["fields_hex"])
        if built != checkpoint_signed_bytes(cp).hex() or built != v["checkpoints"][c["checkpoint"]]["signed_bytes_hex"]:
            bad.append(c["checkpoint"])
    elif kind == "signatures":
        for n, x in v["checkpoints"].items():
            if n in c["altered_after_signing"]:
                continue
            seed_text = v["test_keys"][x["signed_with"]]["seed_text"]
            key = Ed25519PrivateKey.from_private_bytes(sha256(seed_text.encode("utf-8")))
            made_over = bytes.fromhex(x.get("signature_made_over_hex", x["signed_bytes_hex"]))
            if base64.b64encode(key.sign(made_over)).decode() != x["checkpoint"]["signature"]["value_b64"]:
                bad.append(n)
    elif kind == "domain_separation":
        cp = v["checkpoints"][c["checkpoint"]]["checkpoint"]
        base = checkpoint_signed_bytes(cp)
        f = [PROFILE, VERSION, "checkpoint", cp["signature"]["key_ref"]]
        for i, other in enumerate(c["others"]):
            g = list(f)
            g[i] = other
            variant = signed_bytes([x.encode("utf-8") for x in g] + [cp["chain_id"].encode("utf-8"),
                                   cp["count"].to_bytes(8, "big"), bytes.fromhex(cp["head_link"]),
                                   cp["checkpoint_time"].encode("utf-8")])
            if variant == base:
                bad.append(f"field {i + 1}")
    elif kind == "counting_characters":
        # The bytes of a mistaken encoder, whose text prefixes count characters, beside the shared rule's.
        x = v["checkpoints"][c["checkpoint"]]
        cp = x["checkpoint"]

        def build(counting_characters):
            def text(t):
                n = len(t) if counting_characters else len(t.encode("utf-8"))
                return n.to_bytes(4, "big") + t.encode("utf-8")
            return (MAGIC + b"".join(text(t) for t in (PROFILE, VERSION, "checkpoint", cp["signature"]["key_ref"],
                                                      cp["chain_id"]))
                    + lp(cp["count"].to_bytes(8, "big")) + lp(bytes.fromhex(cp["head_link"]))
                    + text(cp["checkpoint_time"]))

        right, wrong = build(False), build(True)
        if right != checkpoint_signed_bytes(cp) or right.hex() != x["signed_bytes_hex"]:
            bad.append("the shared rule's bytes")
        if (lp(cp["chain_id"].encode("utf-8"))[:4].hex(), len(cp["chain_id"]).to_bytes(4, "big").hex()) != (
                c["chain_id_prefix"], c["chain_id_prefix_counting_characters"]) or wrong == right:
            bad.append("the chain_id prefixes")
        public = Ed25519PrivateKey.from_private_bytes(sha256(v["test_keys"][x["signed_with"]]["seed_text"].encode(
            "utf-8"))).public_key()
        value = base64.b64decode(cp["signature"]["value_b64"])
        for name, over, verifies in (("the shared rule's bytes", right, True), ("the bytes counted in characters",
                                                                                wrong, False)):
            try:
                public.verify(value, over)
                ok = True
            except InvalidSignature:
                ok = False
            if ok != verifies:
                bad.append(f"the signature {'does not verify' if verifies else 'verifies'} over {name}")
    elif kind == "token_imprints":
        for n, t in v["tokens"].items():
            if n in c["not_tokens"]:
                continue
            # Read the TSTInfo even where the token is invalid on purpose (wrong content type, two signers).
            encap = cms.ContentInfo.load(base64.b64decode(t["token_b64"]))["content"]["encap_content_info"]
            mi = tsp.TSTInfo.load(encap["content"].contents)["message_imprint"]
            alg = c["true_algorithm"].get(n, mi["hash_algorithm"]["algorithm"].native)
            if mi["hashed_message"].native != hashlib.new(alg, bytes.fromhex(t["imprint_of_hex"])).digest():
                bad.append(n)
    elif kind == "tsa_certificates":
        for n, cert in v["tsa_certificates"].items():
            der = base64.b64decode(cert["certificate_b64"])
            point = x509.load_der_x509_certificate(der).public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            if sha256(der).hex() != cert["sha256"] or point.hex() != v["test_keys"][n]["public_key_hex"]:
                bad.append(n)
    elif kind == "reproduction":
        if load_generator().render() != (HERE / "vectors.json").read_bytes():
            bad.append("vectors.json")
    else:
        raise ValueError(f"unknown check {kind!r}")
    return ("mismatch" if bad else "match"), ", ".join(bad)


def chain_of(c, v):
    return c.get("chain_id", v["base_context"]["chain_id"])


def timestamp_input(spec, v, validators):
    ts = resolve(spec, v)
    holder = {"profile": PROFILE, "profile_version": VERSION, "timestamps": [ts]}
    found = errors(validators["attachment"], holder)
    if found:
        raise ValueError(f"the timestamp must be schema-valid for this case: {found[0]}")
    return ts


def schema_valid(validator, doc, what):
    found = errors(validator, doc)
    if found:
        raise ValueError(f"the {what} must be schema-valid for this case: {found[0]}")
    return doc


class Raised(Exception):
    """The reference check raised an exception on input valid against the schemas: never an expected outcome."""


def reference(check, *args):
    try:
        return check(*args)
    except Exception as exc:
        raise Raised(f"the reference check raised {type(exc).__name__} on schema-valid input: {exc}") from exc


def timestamp_case(c, v, validators):
    ts = timestamp_input(c["timestamp"], v, validators)
    export = schema_valid(validators["pv_export"], apply_patch(v["exports"][c.get("export", "full")],
                                                               c.get("export_patch", []), v), "export")
    policy = schema_valid(validators["trust_policy"], apply_patch(v["trust_policy"], c.get("policy_patch", []), v),
                          "trust policy")
    held = [schema_valid(validators["checkpoint"], v["checkpoints"][n]["checkpoint"], "held checkpoint")
            for n in c.get("held_checkpoints", [])]
    r = reference(check_timestamp, ts, policy, export, chain_of(c, v), held)
    summary = {"status": r["status"], **r["checks"], "issuer_time": r["issuer_time"]["status"]}
    for k in ("existed_no_later_than", "gen_time"):
        if k in c["expected"]:
            summary[k] = r.get(k)
    if "consistency" in c["expected"]:
        summary["consistency"] = r["issuer_time"].get("consistency")
    detail = r["findings"] + r["issuer_time"].get("findings", [])
    return summary, "; ".join(detail)


def expected_timestamp(c):
    """Every check, the timestamp and the issuer's time are expected verified unless the case says otherwise."""
    full = {"status": "verified", **{k: "verified" for k in CHECKS}, "issuer_time": "verified"}
    full.update(c["expected"])
    return full


def checkpoint_case(c, v, validators):
    """checkpoint: a name in vectors.json, {"from", "patch"}, issuer_checkpoint, or null. schema_valid: false marks a
    checkpoint that is deliberately not valid against the schema, which the check must still report."""
    export = schema_valid(validators["pv_export"], v["exports"][c.get("export", "full")], "export")
    policy = schema_valid(validators["trust_policy"], apply_patch(v["trust_policy"], c.get("policy_patch", []), v),
                          "trust policy")
    name = c["checkpoint"]
    if name is None:
        cp = None
    elif name == "issuer_checkpoint":
        cp = copy.deepcopy(export["issuer_checkpoint"])
    else:
        cp = resolve(name if isinstance(name, dict) else f"/checkpoints/{name}/checkpoint", v)
        found = errors(validators["checkpoint"], cp)
        if c.get("schema_valid", True) and found:
            raise ValueError(f"the checkpoint must be schema-valid for this case: {found[0]}")
        if not c.get("schema_valid", True) and not found:
            raise ValueError("the case says the checkpoint is not schema-valid, but it is")
    timestamps = [timestamp_input(t, v, validators) for t in c.get("timestamps", [])]
    held = [cp] if cp and "signature" in cp else []
    chain_id = chain_of(c, v)
    ts_results = [reference(check_timestamp, t, policy, export, chain_id, held) for t in timestamps]
    obtained = {"checkpoint": cp, "obtained_from": c.get("obtained_from", "configured_source")}
    if c.get("source_ref"):
        obtained["source_ref"] = c["source_ref"]
    r = reference(check_checkpoint, obtained, policy, export, chain_id, ts_results)
    summary = {d: (r[d] if d == "status" else r[d]["status"]) for d in CHECKPOINT_DIMENSIONS}
    if r["key_state"]["status"] == "verified":
        summary["time_basis"] = r["key_state"]["time_basis"]
    for k in ("covered_count", "not_covered_indexes"):
        if k in c["expected"]:
            summary[k] = r["comparison"].get(k)
    detail = [f"{d}: {f}" for d in CHECKPOINT_DIMENSIONS[1:] for f in r[d].get("findings", [])] + r.get("findings", [])
    return summary, "; ".join(detail)


def expected_checkpoint(c):
    """Every dimension is expected verified, on the stated time, unless the case says otherwise."""
    full = {d: "verified" for d in CHECKPOINT_DIMENSIONS}
    full["time_basis"] = "stated_time"
    full.update(c["expected"])
    if full["key_state"] != "verified":
        full.pop("time_basis", None)
    return full


def pairing_case(c, v, validators):
    base = v["base_context"]
    attachment = apply_patch(v["base_attachment"], c.get("attachment_patch", []), v)
    export = apply_patch(v["exports"][c.get("export", base["export"])], c.get("export_patch", []), v)
    policy = apply_patch(v["trust_policy"], c.get("policy_patch", []), v)
    obtained = []
    for o in c.get("checkpoints", base["checkpoints"]):
        o = dict(o)
        name = o.pop("checkpoint")
        if name == "issuer_checkpoint":
            o["checkpoint"] = copy.deepcopy(export["issuer_checkpoint"])
        else:
            o["checkpoint"] = copy.deepcopy(v["checkpoints"][name]["checkpoint"]) if name else None
        obtained.append(o)
    digests = {"attachment": sha256(compact(attachment)).hex(), "export": sha256(compact(export)).hex()}
    report = apply_patch(v["base_report"], c["report_patch"], v, digests)
    if any(errors(validators[k], d) for k, d in (("report", report), ("attachment", attachment),
                                                 ("pv_export", export), ("trust_policy", policy))):
        return "error", "every document must be schema-valid for this case"
    ctx = {"attachment": attachment, "export": export, "policy": policy, "chain_id": base["chain_id"],
           "obtained": obtained}
    problems = reference(read_with_documents, report, ctx)
    return ("inconsistent" if problems else "consistent"), "; ".join(problems)


def main():
    sys.stdout.reconfigure(errors="backslashreplace")  # some cases hold text with no UTF-8 encoding, on purpose
    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))
    v = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
    validators = {}
    for name, p in SCHEMAS.items():
        schema = json.loads(p.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)
        print(f"[ok  ] schemas/{p.name}: valid JSON Schema 2020-12")
    validators["pv_export"] = Draft202012Validator(json.loads(PV_EXPORT_SCHEMA.read_text(encoding="utf-8")))

    same = lambda c: c["expected"]  # noqa: E731
    groups = [
        ("schema", cases["schema_cases"], lambda c: schema_case(c, v, validators), same),
        ("vector", cases["vector_cases"], lambda c: vector_case(c, v), same),
        ("timestamp", cases["timestamp_cases"], lambda c: timestamp_case(c, v, validators), expected_timestamp),
        ("checkpoint", cases["checkpoint_cases"], lambda c: checkpoint_case(c, v, validators), expected_checkpoint),
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
            ok = got == want and want not in ("error", "raised")  # a crash is never an expected outcome
            label = c.get("schema", group)
            print(f"[{'ok' if ok else 'FAIL':4}] {c['id']:4} {label:12} {c['description']}")
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
