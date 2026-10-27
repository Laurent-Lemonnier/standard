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
import binascii
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
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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
# The token signature algorithms this check supports (digest algorithm, signature algorithm): each with SHA-256.
TOKEN_ALGORITHMS = {("sha256", "sha256_ecdsa"): "ECDSA P-256", ("sha256", "sha256_rsa"): "RSA PKCS#1 v1.5"}
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

def strict_hex(text):
    """The bytes of a key written as lowercase hex pairs and nothing else, or None for any other writing: a final
    newline, which the schema's $ lets through in some engines and bytes.fromhex would skip, an uppercase digit, a
    space. Used where a signature is verified; the policy's duplicate check keeps the lenient read on purpose."""
    if not isinstance(text, str) or not text or len(text) % 2 or any(c not in "0123456789abcdef" for c in text):
        return None
    return bytes.fromhex(text)


def public_key_identity(entry):
    """The public key an entry lists, from its bytes alone: the entry's algorithm label plays no part, so that one key
    labelled Ed25519 in one entry and EdDSA or ed25519 in another is one key. An Ed25519 key is its 32 raw bytes. A
    P-256 key is its point, written compressed (33 bytes) or uncompressed (65 bytes). An RSA key is its modulus and
    exponent, written in DER as an RSAPublicKey (RFC 8017) or a SubjectPublicKeyInfo (RFC 5280); a P-256 or Ed25519
    key in a SubjectPublicKeyInfo is the same key as its raw bytes. Bytes that are none of these are compared as
    they are."""
    raw = bytes.fromhex(entry["public_key_hex"])
    key = None
    if len(raw) in (33, 65) and raw[0] in (2, 3, 4):
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except ValueError:  # not a point on the curve
            pass
    elif raw[:1] == b"\x30":
        try:
            key = serialization.load_der_public_key(raw)
        except Exception:  # cryptography raises several types for bytes that are not a public key it reads
            pass
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        return "RSA", numbers.n, numbers.e
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.curve.name, key.public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
    if isinstance(key, Ed25519PublicKey):
        return "bytes", key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "bytes", raw


def check_policy(policy):
    """One public key has one key reference, one holder and one role; a reference names one entry. A policy that
    breaks this is refused as a whole: every dimension that relies on it is reported as failed. Keys are compared by
    their bytes (public_key_identity), whatever their entries label the algorithm. The same rule, the same result and
    the same wording as the signatures profile's check."""
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
        by_public.setdefault(public_key_identity(k), []).append(k)
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


def key_kind(key):
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"an ECDSA key on {key.curve.name}"
    if isinstance(key, rsa.RSAPublicKey):
        return f"an RSA key of {key.key_size} bits"
    return "a key of another kind"


def key_fits(algorithm, key):
    """Whether the pinned certificate's key is of the kind the token's signature algorithm names."""
    if algorithm == "ECDSA P-256":
        return isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"
    return isinstance(key, rsa.RSAPublicKey)


def verify_token_signature(key, signature, data):
    """ECDSA P-256 or RSA PKCS#1 v1.5 (RSASSA-PKCS1-v1_5), with SHA-256, as the pinned key decides; InvalidSignature
    when it does not verify. RSASSA-PSS is not supported."""
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    else:
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))


def accuracy(tst):
    """The token's accuracy. RFC 3161 2.4.2: millis and micros are from 1 to 999; seconds cannot be negative."""
    n = tst["accuracy"].native
    if n is None:
        return timedelta(0)
    seconds, millis, micros = n.get("seconds"), n.get("millis"), n.get("micros")
    if (seconds is not None and seconds < 0) or any(x is not None and not 1 <= x <= 999 for x in (millis, micros)):
        raise ValueError(f"the accuracy (seconds {seconds}, millis {millis}, micros {micros}) is out of range")
    return timedelta(seconds=seconds or 0, milliseconds=millis or 0, microseconds=micros or 0)


def signature_verifies(cp, policy):
    """Whether a held checkpoint's signature verifies over its own fields, with the policy's witness key for its
    key_ref: what a timestamp over that signature value may take the witness's time from. Says nothing about whether
    the key is listed for a source or a chain, which check_checkpoint says."""
    key = next((k for k in policy.get("keys", []) if k.get("key_ref") == cp["signature"].get("key_ref")), None)
    if key is None or key.get("role") != "witness" or key.get("algorithm") != "Ed25519" or \
            cp["signature"].get("algorithm") != "Ed25519" or strict_hex(key.get("public_key_hex")) is None:
        return False
    try:
        made_over = cp["_to_be_signed"] if "_to_be_signed" in cp else checkpoint_signed_bytes(cp)  # a statement's
        Ed25519PublicKey.from_public_bytes(strict_hex(key["public_key_hex"])).verify(
            base64.b64decode(cp["signature"]["value_b64"], validate=True), made_over)
        return True
    except (Unencodable, InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        # A held checkpoint with a field missing or not text (one from a source reaches this check without a schema
        # check) gives no time, and the check goes on: it never stops on a document.
        return False


def check_timestamp(ts, policy, export, chain_id, held, headers=None):
    """Reference check of one timestamp assertion. held: the checkpoints the verifier holds, for a signature subject.
    headers: the Bitcoin block headers the verifier holds from its own source ({"source_ref", "headers": {height:
    hex}}), for an OpenTimestamps proof."""
    checks = {k: "not_checked" for k in CHECKS}
    findings = []
    subject = ts["subject"]
    out = {"subject": shown_subject(subject), "checks": checks, "findings": findings,
           "issuer_time": {"status": "not_checked"}}
    if "tsa_ref" in ts:
        out["tsa_ref"] = ts["tsa_ref"]
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
        # Only a checkpoint whose signature verifies over its own fields says what the witness signed: a copy presented
        # with another checkpoint_time carries the same value, and its time is not the witness's.
        with_value = [c for c in held if "signature" in c and c["signature"]["value_b64"] == subject["value_b64"]]
        same = [c for c in with_value if signature_verifies(c, policy)]
        if not with_value:
            findings.append("the verifier holds no checkpoint with this signature value")
        elif not same:
            findings.append("the verifier holds a checkpoint with this signature value, but the signature does not "
                            "verify over that checkpoint's fields: not the checkpoint the witness signed")
        else:
            c, of = same[0], subject["of"]
            if (c["signature"]["key_ref"], c["chain_id"], c["count"]) == (of["key_ref"], of["chain_id"], of["count"]):
                checks["subject_bytes"] = "verified"
            else:
                checks["subject_bytes"] = "failed"
                findings.append("the signature value is that of another checkpoint than the subject names")

    if ts.get("format") == "opentimestamps":
        return check_ots(ts, policy, out, checks["subject_bytes"], value, headers)

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
        elif algorithms not in TOKEN_ALGORITHMS:
            checks["tsa_signature"] = "not_supported"
            findings.append("this check supports ECDSA P-256 and RSA PKCS#1 v1.5, each with SHA-256; the token uses "
                            f"{algorithms[1]} with {algorithms[0]}")
        elif not key_fits(TOKEN_ALGORITHMS[algorithms], key):
            checks["tsa_signature"] = "failed"
            findings.append(f"the token's signature algorithm ({algorithms[1]}) does not fit the key of the "
                            f"certificate pinned for {ts['tsa_ref']}, which is {key_kind(key)}")
        elif not names_pinned:
            checks["tsa_signature"] = "failed"
            findings.append(f"the token names another signer than the certificate pinned for {ts['tsa_ref']}")
        else:
            encoded = attrs.dump()  # tagged [0] in the token; signed as a SET OF (RFC 5652 5.4), as it appears
            try:
                verify_token_signature(key, signer["signature"].native, b"\x31" + encoded[1:])
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


# ---------------------------------------------------------------- a SCITT transparency service as a source

COSE_SIGN1_TAG = 18                                        # RFC 9052: a tagged COSE_Sign1
ALG_ED25519 = -19                                          # RFC 9864: Ed25519; -8 (EdDSA) is deprecated there
ALG_EDDSA_DEPRECATED = -8                                  # EdDSA; read in a receipt with a finding, never in a statement
HDR_ALG, HDR_CRIT, HDR_KID, HDR_CWT_CLAIMS = 1, 2, 4, 15    # RFC 9052 header labels; 15 is RFC 9597's CWT claims
CWT_ISS, CWT_SUB = 1, 2                                    # RFC 8392 claim keys
HDR_VDS, HDR_VDP = 395, 396                                # RFC 9942: the verifiable data structure, and its proofs
VDS_RFC9162_SHA256 = 1                                     # RFC 9942: the RFC 9162 SHA-256 Merkle tree
VDP_INCLUSION_PROOFS = -1                                  # RFC 9942: inclusion proofs, [tree-size, leaf-index, path]
KNOWN_STATEMENT_LABELS = {HDR_ALG, HDR_KID, HDR_CWT_CLAIMS}
MAX_CBOR_NESTING = 16  # far more than a statement, a receipt or a proof needs
LOG_CONSISTENCY_NOT_CHECKED = ("one inclusion proof shows nothing about the log being append-only or shown to everyone "
                               "alike (RFC 9942 gives consistency proofs for the first; RFC 9943 leaves the second to "
                               "the service and to auditors); a consistency proof against a root the verifier holds "
                               "is not in this version")


class NotCbor(ValueError):
    """Bytes this check does not read as CBOR, with the reason."""


class Tagged:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def cbor_strict(raw):
    """A strict reader for the CBOR a statement, a receipt and a proof use: definite lengths only; integers and lengths
    in their shortest form; no map key named twice; map keys integers or text; tag 18 only; false, true and null the
    only simple values; no floats; nothing after the item. Anything else raises NotCbor with the reason, as this
    extension refuses a JSON member named twice."""
    pos = 0

    def take(n, what):
        nonlocal pos
        if pos + n > len(raw):
            raise NotCbor(f"the item ends before {what}")
        data = raw[pos:pos + n]
        pos += n
        return data

    def head():
        first = take(1, "the next item")[0]
        major, info = first >> 5, first & 31
        if major == 7:
            if info in (20, 21, 22):
                return major, info
            raise NotCbor("a simple value or a float; none is used here")
        if info < 24:
            return major, info
        if info > 27:
            raise NotCbor("an indefinite length" if info == 31 else "reserved additional information")
        size = 1 << (info - 24)
        value = int.from_bytes(take(size, "an argument"), "big")
        if value < (24, 256, 65536, 2 ** 32)[info - 24]:
            raise NotCbor("an integer or a length not in its shortest form")
        return major, value

    def item(depth=0):
        # Arrays, maps and tags nest; a statement, a receipt and a proof need a few levels, so deeper nesting is
        # refused with the reason before it can exhaust the reader.
        if depth > MAX_CBOR_NESTING:
            raise NotCbor(f"items nested deeper than {MAX_CBOR_NESTING} levels")
        major, arg = head()
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major in (2, 3):
            data = take(arg, "the end of a string")
            if major == 2:
                return data
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                raise NotCbor("a text string that is not UTF-8") from None
        if major == 4:
            return [item(depth + 1) for _ in range(arg)]
        if major == 5:
            out = {}
            for _ in range(arg):
                k = item(depth + 1)
                if not isinstance(k, (int, str)) or isinstance(k, bool):
                    raise NotCbor("a map key that is not an integer or text")
                if k in out:
                    raise NotCbor(f"the map key {k!r} named twice")
                out[k] = item(depth + 1)
            return out
        if major == 6:
            if arg != COSE_SIGN1_TAG:
                raise NotCbor(f"tag {arg}; this check reads tag 18 (COSE_Sign1) only")
            return Tagged(arg, item(depth + 1))
        return {20: False, 21: True, 22: None}[arg]

    value = item()
    if pos != len(raw):
        raise NotCbor("bytes after the item")
    return value


def plain(value):
    """A read item as plain Python, for comparison with another reader: a tag as ("tag", n, value)."""
    if isinstance(value, Tagged):
        return ("tag", value.tag, plain(value.value))
    if hasattr(value, "tag") and hasattr(value, "value"):  # cbor2.CBORTag
        return ("tag", value.tag, plain(value.value))
    if isinstance(value, (list, tuple)):  # cbor2 reads an array inside a tag as a tuple
        return [plain(x) for x in value]
    if hasattr(value, "items"):  # a dict, or cbor2's immutable map
        return {k: plain(x) for k, x in value.items()}
    return value


def cbor_head(major, n):
    """The head of a CBOR item by the full rule (RFC 8949 section 3): the argument in the shortest of 0, 1, 2, 4 or 8
    bytes."""
    if n < 24:
        return bytes([major << 5 | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError("a length beyond 2^64 - 1")


def sig_structure(protected, payload):
    """RFC 9052 section 4.4 for COSE_Sign1: ["Signature1", protected header bytes, external_aad (empty), payload],
    written in the shortest definite form, whatever the lengths. These bytes start 84 6a "Signature1"; the shared
    rule's bytes start "DPS-SIG" 00: no bytes are both, so the two formats cannot be confused (a witness still signs
    its statements with a key of their own: RFC 9943 section 9.4)."""
    def bstr(data):
        return cbor_head(2, len(data)) + data
    return b"\x84" + b"\x6aSignature1" + bstr(protected) + b"\x40" + bstr(payload)


def cose_sign1(raw):
    """A tagged COSE_Sign1 read strictly: (protected bytes, protected map, unprotected map, payload or None,
    signature). Raises NotCbor with the reason."""
    item = cbor_strict(raw)
    if not isinstance(item, Tagged):
        raise NotCbor("not tagged 18 (COSE_Sign1)")
    arr = item.value
    if not (isinstance(arr, list) and len(arr) == 4):
        raise NotCbor("COSE_Sign1 is an array of four items")
    protected, unprotected, payload, signature = arr
    if not isinstance(protected, bytes) or not isinstance(unprotected, dict) or not isinstance(signature, bytes) \
            or not (payload is None or isinstance(payload, bytes)):
        raise NotCbor("COSE_Sign1's items are not of their types")
    pmap = cbor_strict(protected) if protected else {}
    if not isinstance(pmap, dict):
        raise NotCbor("the protected header is not a map")
    return protected, pmap, unprotected, payload, signature


def read_checkpoint_bytes(payload):
    """The shared rule read back for a checkpoint: the prefix, then exactly eight length-prefixed fields: profile
    (dps-anchoring), profile_version (0.2.0), the assertion type (checkpoint), key_ref, chain_id, count (8 bytes),
    head_link (32 bytes) and checkpoint_time. Raises ValueError with the reason."""
    if not payload.startswith(MAGIC):
        raise ValueError("the payload does not start with the shared rule's prefix DPS-SIG 00")
    pos, fields = len(MAGIC), []
    while pos < len(payload):
        if pos + 4 > len(payload):
            raise ValueError("a length prefix is cut")
        n = int.from_bytes(payload[pos:pos + 4], "big")
        pos += 4
        if pos + n > len(payload):
            raise ValueError("a field is longer than the bytes left")
        fields.append(payload[pos:pos + n])
        pos += n
    if len(fields) != 8:
        raise ValueError(f"{len(fields)} fields; a checkpoint's signed bytes have eight")
    profile, version, assertion, key_ref, chain, count, head, time = fields
    if (profile, version, assertion) != (PROFILE.encode("utf-8"), VERSION.encode("utf-8"), b"checkpoint"):
        raise ValueError("the first three fields are not dps-anchoring, 0.2.0 and checkpoint")
    if len(count) != 8 or len(head) != 32:
        raise ValueError("count is not 8 bytes, or head_link not 32")
    n = int.from_bytes(count, "big")
    if not 1 <= n <= MAX_COUNT:
        raise ValueError(f"count is {n}; a checkpoint's count is from 1 to 2^53 - 1")
    try:
        return {"key_ref": key_ref.decode("utf-8"), "chain_id": chain.decode("utf-8"), "count": n,
                "head_link": head.hex(), "checkpoint_time": time.decode("utf-8")}
    except UnicodeDecodeError:
        raise ValueError("a text field is not UTF-8") from None


def read_statement(obtained):
    """A SCITT carrier (statement_b64, and receipt_b64 where held) read into obtained: checkpoint, the checkpoint the
    payload states, with the COSE signature as its signature and the Sig_structure kept for verifying; _scitt, what
    the check needs besides. A statement that cannot be read leaves checkpoint None, with the reason."""
    info = {"raw": None, "receipt_raw": None, "header": None, "error": None}
    obtained["_scitt"], obtained["checkpoint"] = info, None
    try:
        info["raw"] = base64.b64decode(obtained["statement_b64"], validate=True)
        if obtained.get("receipt_b64") is not None:
            info["receipt_raw"] = base64.b64decode(obtained["receipt_b64"], validate=True)
    except (binascii.Error, ValueError, TypeError):
        info["error"] = "the statement or the receipt is not base64"
        return obtained
    try:
        protected, pmap, unprotected, payload, signature = cose_sign1(info["raw"])
        if payload is None:
            raise NotCbor("the statement's payload is detached; a signed statement carries it")
        fields = read_checkpoint_bytes(payload)
        to_be_signed = sig_structure(protected, payload)
    except (NotCbor, ValueError) as exc:
        info["error"] = f"the statement cannot be read: {exc}"
        return obtained
    # The fields the payload states are held to the checkpoint schema's rules, as a checkpoint under the shared rule
    # is: a chain_id of 1 to 256 characters, a time in exactly the signed form, and the rest. A payload outside them
    # fails the signature with the reason, since its result could not be written in a valid report.
    stated = {"profile": PROFILE, "profile_version": VERSION, "assertion": "checkpoint",
              **{k: fields[k] for k in ("chain_id", "count", "head_link", "checkpoint_time")},
              "signature": {"algorithm": "Ed25519", "key_ref": fields["key_ref"],
                            "value_b64": base64.b64encode(signature).decode("ascii")}}
    refused_by_schema = errors(checkpoint_validator(), stated)
    if refused_by_schema:
        info["payload_refused"] = f"the payload states a checkpoint the checkpoint schema refuses: {refused_by_schema[0]}"
        rules = strict_json(SCHEMAS["checkpoint"].read_bytes())["properties"]
        info["refused_fields"] = sorted(k for k in ("chain_id", "count", "head_link", "checkpoint_time")
                                        if list(Draft202012Validator(rules[k]).iter_errors(stated[k])))
    kid, claims = pmap.get(HDR_KID), pmap.get(HDR_CWT_CLAIMS)
    info["header"] = {"alg": pmap.get(HDR_ALG), "crit": pmap.get(HDR_CRIT),
                      "kid": kid.decode("utf-8", "replace") if isinstance(kid, bytes) else None,
                      "iss": claims.get(CWT_ISS) if isinstance(claims, dict) else None,
                      "sub": claims.get(CWT_SUB) if isinstance(claims, dict) else None,
                      "unknown_labels": sorted(str(k) for k in pmap if k not in KNOWN_STATEMENT_LABELS)}
    obtained["checkpoint"] = {
        "profile": PROFILE, "profile_version": VERSION, "assertion": "checkpoint", "format": "scitt",
        **{k: fields[k] for k in ("chain_id", "count", "head_link", "checkpoint_time")},
        "signature": {"algorithm": "Ed25519", "key_ref": info["header"]["kid"] or fields["key_ref"],
                      "value_b64": base64.b64encode(signature).decode("ascii")},
        "_payload_key_ref": fields["key_ref"], "_to_be_signed": to_be_signed}
    return obtained


_CHECKPOINT_VALIDATOR = []


def checkpoint_validator():
    """The checkpoint schema's validator, read once."""
    if not _CHECKPOINT_VALIDATOR:
        _CHECKPOINT_VALIDATOR.append(Draft202012Validator(strict_json(SCHEMAS["checkpoint"].read_bytes())))
    return _CHECKPOINT_VALIDATOR[0]


def checkpoint_result_validator():
    """The report schema's checkpoint result, as a validator of one result."""
    report = strict_json(SCHEMAS["report"].read_bytes())
    return Draft202012Validator({"$schema": report["$schema"], "$defs": report["$defs"],
                                 "$ref": "#/$defs/checkpoint_result"})


def statement_header_findings(cp, info, key):
    """What the pinned header must say, checked before the signature: alg -19; no critical header this check does
    not know; kid the payload's key_ref; iss the key's holder; sub the payload's chain. Returns (status, findings)."""
    h = info["header"]
    if h["alg"] != ALG_ED25519:
        return "not_supported", [f"alg {h['alg']!r}; this check takes -19 (Ed25519, RFC 9864), under which -8 (EdDSA) "
                                 "is deprecated"]
    findings = []
    if info.get("payload_refused"):
        findings.append(info["payload_refused"])
    if h["crit"] is not None:
        findings.append(f"a critical header this check does not know: {h['crit']!r}")
    if h["kid"] is None:
        findings.append("the protected header names no kid")
    elif h["kid"] != cp["_payload_key_ref"]:
        findings.append(f"kid {h['kid']!r} is not the payload's key_ref {cp['_payload_key_ref']!r}")
    if h["iss"] is None:
        findings.append("the CWT claims name no iss (RFC 9943 requires it)")
    elif h["iss"] != key["holder"]:
        findings.append(f"iss {h['iss']!r} is not the holder of {key['key_ref']} in the trust policy")
    if h["sub"] != cp["chain_id"]:
        findings.append(f"sub {h['sub']!r} is not the payload's chain_id {cp['chain_id']!r}")
    return ("failed" if findings else "verified"), findings


def root_from_path(leaf, index, size, path):
    """RFC 9162 section 2.1.3.2: the root an inclusion path leads to from a leaf hash, or None when the path does not
    fit the tree size and index."""
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = sha256(b"\x01" + p + r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = sha256(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def check_receipt(info, policy, allowed, where):
    """The service's receipt (RFC 9942) for a statement: verified means exactly that the service signed that this
    statement is in its log at the tree size named. allowed: the service keys the policy lists for the source (or,
    beside the export, for a SCITT source of the chain). No time: a receipt states none."""
    if info["receipt_raw"] is None:
        return {"status": "unavailable", "findings": ["no receipt held: the service's registration of this statement "
                                                      "is not shown"]}

    def failed(why):
        return {"status": "failed", "findings": [why]}
    try:
        protected, pmap, unprotected, payload, signature = cose_sign1(info["receipt_raw"])
    except NotCbor as exc:
        return failed(f"the receipt cannot be read: {exc}")
    if payload is not None:
        return failed("the receipt carries a payload; a receipt's payload is detached, the root the verifier computes")
    # A receipt is the service's own, and a service is not bound by this extension: a receipt labelled -8 (EdDSA, which
    # RFC 9864 deprecates in favour of -19) is verified exactly as one labelled -19, with a finding. The key comes from
    # the policy, never from the receipt, so the verifier fixes the curve; the label is inside the signed bytes, so a
    # signature made under one label does not verify under the other. A statement stays pinned to -19 (header_problems).
    alg = pmap.get(HDR_ALG)
    if alg not in (ALG_ED25519, ALG_EDDSA_DEPRECATED):
        return {"status": "not_supported", "findings": [f"alg {alg!r}; this check takes -19 (Ed25519) or -8 (EdDSA)"]}
    deprecated = ["alg -8 (EdDSA), deprecated by RFC 9864 in favour of -19 (Ed25519)"] if alg == ALG_EDDSA_DEPRECATED else []
    if pmap.get(HDR_VDS) != VDS_RFC9162_SHA256:
        return {"status": "not_supported", "findings": [f"verifiable data structure {pmap.get(HDR_VDS)!r}; this check "
                                                        "knows the RFC 9162 SHA-256 tree (1)"]}
    kid = pmap.get(HDR_KID)
    kid = kid.decode("utf-8", "replace") if isinstance(kid, bytes) else None
    key = next((k for k in policy["keys"] if k["key_ref"] == kid), None)
    if key is None:
        return failed(f"the receipt's kid {kid!r} is not a key in the trust policy")
    if key["role"] != "transparency_service":
        return failed(f"{kid} is a key in role {key['role']}; only a transparency service's key signs a receipt")
    if kid not in allowed:
        return failed(f"the trust policy does not list {kid} as a service key " +
                      ("for this source" if where == "configured_source" else "of a SCITT source for this chain"))
    if key.get("algorithm") != "Ed25519":  # the policy may list a service key under another algorithm; this check
        return {"status": "not_supported", "findings": [f"{kid} is listed as {key.get('algorithm')!r}; this check "
                                                        "verifies a receipt with a service key listed as Ed25519"]}
    proofs = unprotected.get(HDR_VDP, {}).get(VDP_INCLUSION_PROOFS) if isinstance(unprotected.get(HDR_VDP), dict) \
        else None
    if not isinstance(proofs, list) or not proofs or not isinstance(proofs[0], bytes):
        return failed("the receipt carries no inclusion proof (label 396, key -1)")
    try:
        proof = cbor_strict(proofs[0])
    except NotCbor as exc:
        return failed(f"the inclusion proof cannot be read: {exc}")
    if not (isinstance(proof, list) and len(proof) == 3 and all(json_integer(x) for x in proof[:2])
            and isinstance(proof[2], list) and all(isinstance(p, bytes) and len(p) == 32 for p in proof[2])):
        return failed("the inclusion proof is not [tree-size, leaf-index, path of 32-byte hashes]")
    size, index, path = proof
    if size < 1 or not 0 <= index < size:
        return failed(f"tree size {size} does not hold leaf {index}")
    root = root_from_path(sha256(b"\x00" + info["raw"]), index, size, path)
    if root is None:
        return failed(f"a path of {len(path)} hashes does not fit leaf {index} of {size}")
    if strict_hex(key["public_key_hex"]) is None:
        return failed(f"the policy's public key for {kid} is not written as lowercase hex pairs and nothing else")
    try:
        Ed25519PublicKey.from_public_bytes(strict_hex(key["public_key_hex"])).verify(signature,
                                                                                     sig_structure(protected, root))
    except InvalidSignature:
        return failed("the receipt's signature does not verify over the root the proof leads to from this statement: "
                      "the proof is for another leaf, or the receipt is not the service's")
    out = {"service_key_ref": kid, "tree_size": size, "leaf_index": index}
    if key.get("revoked_at"):
        out.update(status="unavailable", findings=deprecated + [f"{kid} is revoked as {key.get('revocation_reason')}; "
                                                                "a receipt states no time, so it cannot be shown made "
                                                                "before that"])
        return out
    out.update(status="verified", findings=deprecated + [f"{kid} signed that this statement is in its log at tree size {size} "
                                            f"(leaf {index}); not that the log is append-only, nor that it showed "
                                            "everyone the same log; a receipt states no registration time, and the "
                                            "log's order need not be the order of issuance"])
    return out


# ---------------------------------------------------------------- an OpenTimestamps proof as a timestamp

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_VERSION = 1
OTS_SHA256, OTS_APPEND, OTS_PREPEND = 0x08, 0xf0, 0xf1
OTS_KNOWN_UNSUPPORTED = {0x02: "sha1", 0x03: "ripemd160", 0x67: "keccak256", 0xf2: "reverse", 0xf3: "hexlify"}
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")   # a Bitcoin block header attestation: the payload is the height
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")   # a calendar's promise, not yet in a block
OTS_MAX_DEPTH = 256        # nested timestamps (each operation opens one level); the real proof in the vectors has 79
OTS_MAX_VARUINT_BYTES = 9  # a varint of at most 63 bits; the reference library accepts far longer ones
OTS_MAX_ARG = 4096         # an append or prepend argument
OTS_MAX_PAYLOAD = 8192     # an attestation's payload
OTS_MAX_RESULT = 4096      # an operation's result, as the reference library's MAX_RESULT_LENGTH
OTS_MAX_HEIGHT = MAX_COUNT  # a height a report can carry as a JSON integer


class NotOts(ValueError):
    """Bytes this check does not read as an OpenTimestamps proof, with the reason."""


class OtsNotSupported(ValueError):
    """A proof this check reads but cannot replay: an operation other than sha256, append and prepend."""


def ots_read(raw):
    """A strict reader: the magic, version 1, the file hash sha256 and its 32 bytes, then the timestamp tree; varints in
    their shortest form and within OTS_MAX_VARUINT_BYTES; arguments, payloads and depth within their limits; the same
    operation or attestation twice at one point refused (the reference library keeps the last); nothing after the proof.
    Returns (digest, tree); a node is {"ops": {(tag, arg): node}, "atts": [(tag8, payload)]}. Raises NotOts or
    OtsNotSupported with the reason."""
    pos = 0

    def take(n, what):
        nonlocal pos
        if pos + n > len(raw):
            raise NotOts(f"the proof ends before {what}")
        data = raw[pos:pos + n]
        pos += n
        return data

    def varuint(what):
        n = shift = 0
        for count in range(1, OTS_MAX_VARUINT_BYTES + 1):
            b = take(1, what)[0]
            n |= (b & 0x7f) << shift
            shift += 7
            if not b & 0x80:
                if count > 1 and b == 0:
                    raise NotOts(f"{what} is not in its shortest form")
                return n
        raise NotOts(f"{what} is longer than {OTS_MAX_VARUINT_BYTES} bytes")

    def varbytes(limit, what):
        n = varuint(f"the length of {what}")
        if n > limit:
            raise NotOts(f"{what} is {n} bytes, over the limit of {limit}")
        return take(n, what)

    def node(depth, length):
        """length: the size of the message at this point, followed through the operations so that no result over
        OTS_MAX_RESULT is ever built; a sha256 gives 32 bytes, an append or prepend adds its argument."""
        if depth > OTS_MAX_DEPTH:
            raise NotOts(f"timestamps nested deeper than {OTS_MAX_DEPTH} levels")
        out = {"ops": {}, "atts": []}
        seen = set()

        def item(tag):
            if tag == 0x00:
                att = (take(8, "an attestation's tag"), varbytes(OTS_MAX_PAYLOAD, "an attestation's payload"))
                if att in seen:
                    raise NotOts("the same attestation twice at one point")
                seen.add(att)
                out["atts"].append(att)
                return
            if tag in OTS_KNOWN_UNSUPPORTED:
                raise OtsNotSupported(f"the operation {OTS_KNOWN_UNSUPPORTED[tag]}; this check replays sha256, append "
                                      "and prepend only")
            if tag not in (OTS_SHA256, OTS_APPEND, OTS_PREPEND):
                raise NotOts(f"an unknown operation tag {tag:#04x}")
            arg = varbytes(OTS_MAX_ARG, "an argument") if tag != OTS_SHA256 else b""
            if (tag, arg) in out["ops"]:
                raise NotOts("the same operation twice at one point")
            result = 32 if tag == OTS_SHA256 else length + len(arg)
            if result > OTS_MAX_RESULT:
                raise NotOts(f"an operation's result would be {result} bytes, over the limit of {OTS_MAX_RESULT}")
            out["ops"][(tag, arg)] = node(depth + 1, result)

        tag = take(1, "an operation")[0]
        while tag == 0xff:
            item(take(1, "an operation")[0])
            tag = take(1, "an operation")[0]
        item(tag)
        return out

    if take(len(OTS_MAGIC), "its magic") != OTS_MAGIC:
        raise NotOts("not an OpenTimestamps proof: the magic differs")
    version = varuint("the version")
    if version != OTS_VERSION:
        raise NotOts(f"version {version}; this check reads version {OTS_VERSION}")
    file_hash = take(1, "the file hash operation")[0]
    if file_hash != OTS_SHA256:
        raise OtsNotSupported(f"a file hash other than sha256 ({OTS_KNOWN_UNSUPPORTED.get(file_hash, hex(file_hash))})")
    digest = take(32, "the digest")
    tree = node(1, 32)
    if pos != len(raw):
        raise NotOts("bytes after the proof")
    return digest, tree


def ots_attestations(tree, digest):
    """Replay the tree from the digest: [(kind, value, message)] for each attestation, kind bitcoin (value the height),
    pending (value the calendar's text) or unknown (skipped, by its length, as read). The message is kept only where
    it can match a header's Merkle root: for a Bitcoin attestation whose result is 32 bytes; otherwise None, so that a
    proof whose every leaf ends in an attestation does not hold every leaf's message at once."""
    out, stack = [], [(tree, None, b"", digest)]
    while stack:
        node, tag, arg, parent = stack.pop()
        # The message at this point, computed only now that this branch is replayed: holding every branch's
        # message at once would cost the chain's length times the number of leaves.
        msg = parent if tag is None else (sha256(parent) if tag == OTS_SHA256 else
                                          (parent + arg if tag == OTS_APPEND else arg + parent))
        for tag8, payload in node["atts"]:
            if tag8 == OTS_BITCOIN:
                # The height: one varint filling the payload, of at most OTS_MAX_VARUINT_BYTES bytes, in its shortest
                # form, and at most OTS_MAX_HEIGHT. Each rule gives its own reason.
                if len(payload) > OTS_MAX_VARUINT_BYTES:
                    out.append(("bitcoin_refused", f"a Bitcoin attestation's height is a varint of {len(payload)} "
                                f"bytes, over the limit of {OTS_MAX_VARUINT_BYTES}", None))
                    continue
                ends = [p for p, b in enumerate(payload) if not b & 0x80]
                if not payload or ends != [len(payload) - 1]:
                    out.append(("bitcoin_refused", "a Bitcoin attestation's payload is not exactly one varint", None))
                    continue
                if len(payload) > 1 and payload[-1] == 0:
                    out.append(("bitcoin_refused", "a Bitcoin attestation's height is not in its shortest form", None))
                    continue
                height = sum((b & 0x7f) << (7 * p) for p, b in enumerate(payload))
                if height > OTS_MAX_HEIGHT:
                    out.append(("bitcoin_refused", f"a Bitcoin attestation's height {height} is beyond what a report "
                                "can carry (2^53 - 1)", None))
                    continue
                out.append(("bitcoin", height, msg if len(msg) == 32 else None))
            elif tag8 == OTS_PENDING:
                out.append(("pending", payload, None))
            else:
                out.append(("unknown", tag8.hex(), None))
        for (tag, arg), child in node["ops"].items():
            stack.append((child, tag, arg, msg))
    return out


def check_ots(ts, policy, out, subject_check, value, headers):
    """An OpenTimestamps proof, checked against a header from the verifier's own source. What it shows: the subject's
    bytes existed before the block it names was mined. The header's time is the miner's statement, never a bound."""
    checks = {"proof": "not_checked", "subject_bytes": subject_check, "operations": "not_checked",
              "attestation": "not_checked", "header": "not_checked"}
    findings = out["findings"]
    out.update(format="opentimestamps", checks=checks,
               issuer_time={"status": "not_checked", "findings": [
                   "an OpenTimestamps proof gives no time that holds, so no issuer's time is compared with it"]})
    out.pop("tsa_ref", None)
    try:
        digest, tree = ots_read(base64.b64decode(ts["proof_b64"], validate=True))
        checks["proof"] = "verified"
    except OtsNotSupported as exc:
        checks["proof"], checks["operations"] = "verified", "not_supported"
        findings.append(str(exc))
        out["status"] = "not_supported"
        return out
    except (NotOts, binascii.Error, ValueError) as exc:
        checks["proof"] = "failed"
        findings.append(f"the proof is not read: {exc}")
        out["status"] = "failed"
        return out
    if digest != sha256(value):
        checks["subject_bytes"] = "failed"
        findings.append("the proof starts from the SHA-256 of other bytes than the subject names")
    checks["operations"] = "verified"
    atts = ots_attestations(tree, digest)
    for kind, val, _ in atts:
        if kind == "unknown":
            findings.append(f"an attestation of an unknown kind ({val}) is skipped")
    bitcoin = [(h, msg) for kind, h, msg in atts if kind == "bitcoin"]
    refused = [why for kind, why, _ in atts if kind == "bitcoin_refused"]
    if refused:
        checks["attestation"] = "failed"
        findings.extend(refused)
    elif not bitcoin:
        pending = any(kind == "pending" for kind, _, _ in atts)
        checks["attestation"] = "unavailable" if pending else "failed"
        findings.append("only pending attestations: not yet in a block, so the proof shows nothing yet" if pending else
                        "no attestation this check can use")
    else:
        checks["attestation"] = "verified"
        sources = {s["source_ref"]: s for s in policy.get("bitcoin_header_sources", []) if s.get("network") == "mainnet"}
        held = headers or {}
        if not sources:
            findings.append("the trust policy names no Bitcoin header source, so no header is checked")
        elif held.get("source_ref") not in sources:
            checks["header"] = "unavailable"
            findings.append("no header is held from a source the trust policy names")
        else:
            results = []
            for height, msg in sorted(bitcoin, key=lambda b: b[0]):
                hdr_hex = held.get("headers", {}).get(str(height))
                if hdr_hex is None:
                    results.append((height, "unavailable", msg, None))
                    continue
                hdr = bytes.fromhex(hdr_hex) if isinstance(hdr_hex, str) and len(hdr_hex) == 160 else None
                if hdr is None:
                    results.append((height, "failed", msg, None))
                elif msg is not None and hdr[36:68] == msg:
                    results.append((height, "verified", msg, hdr))
                else:
                    results.append((height, "failed", msg, hdr))
            good = [r for r in results if r[1] == "verified"]
            if good:
                # Several Bitcoin attestations: the lowest block the verifier holds a matching header for is reported.
                height, _, _, hdr = good[0]
                checks["header"] = "verified"
                out["block"] = {"height": height, "hash_hex": sha256(sha256(hdr))[::-1].hex(),
                                "header_source_ref": held["source_ref"]}
                out["miner_stated_time"] = iso(datetime.fromtimestamp(int.from_bytes(hdr[68:72], "little"),
                                                                      tz=timezone.utc))
                findings.append(f"the subject's bytes existed before block {height} was mined; its header's time is "
                                "the miner's statement, not a time they existed by; the header is only as good as "
                                f"{held['source_ref']}, and this check does not test proof of work")
            elif any(r[1] == "failed" for r in results):
                checks["header"] = "failed"
                for height, status, msg, hdr in results:
                    if status == "failed":
                        hint = (" (it matches only in the reverse byte order, as explorers show the root)"
                                if hdr is not None and msg is not None and hdr[36:68] == msg[::-1] else "")
                        findings.append(f"the header held for block {height} does not hold the proof's result as "
                                        f"its Merkle root{hint}")
            else:
                checks["header"] = "unavailable"
                findings.append("no header is held for the block" + ("s " if len(results) > 1 else " ") +
                                ", ".join(str(r[0]) for r in results))
    statuses = set(checks.values())
    for worst in ("failed", "unavailable", "not_supported", "not_checked"):
        if worst in statuses:
            out["status"] = worst
            break
    else:
        out["status"] = "verified"
    return out


def check_checkpoint(obtained, policy, export, chain_id, ts_results):
    """Reference check of one checkpoint, as the verifier obtained it (or could not)."""
    cp, where = obtained.get("checkpoint"), obtained["obtained_from"]
    out = {"obtained_from": where}
    if obtained.get("source_ref"):
        out["source_ref"] = obtained["source_ref"]
    if where == "beside_export" and "attachment_index" in obtained:  # its place in the attachment's checkpoints
        out["attachment_index"] = obtained["attachment_index"]
    scitt = obtained.get("_scitt")  # a SCITT signed statement, read by read_statement; None for a plain checkpoint
    if scitt:
        out["format"] = "scitt"
    if cp is not None:
        # A statement's payload field that the checkpoint schema refuses is left out: the result reports only values a
        # report can carry (its reason is under signature).
        left_out = scitt.get("refused_fields", ()) if scitt else ()
        out["checkpoint"] = {k: cp[k] for k in ("chain_id", "count", "head_link", "checkpoint_time")
                             if k in cp and k not in left_out}
    policy_result = check_policy(policy)
    is_refused = policy_result["status"] != "verified"
    source = next((s for s in policy["checkpoint_sources"] if s["source_ref"] == obtained.get("source_ref")), None)
    beside = where == "beside_export"
    if where == "same_export":
        independence = {"status": "failed", "findings": ["found in the export: a checkpoint from the same export is "
                                                         "never independent"]}
    elif beside:
        independence = {"status": "failed", "findings": ["carried beside the export: the issuer chose which "
                                                         "checkpoint to carry, so it is never independent"]}
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
    if cp is None and scitt and scitt["error"]:
        # A statement this check does not read: nothing in it is checked, and the reason is given.
        out.update(status="failed", signature={"status": "failed", "findings": [scitt["error"]]},
                   key_state={"status": "not_checked"}, comparison={"status": "not_checked"},
                   receipt={"status": "not_checked", "findings": ["the statement is not read"]},
                   log_consistency={"status": "not_checked", "findings": [LOG_CONSISTENCY_NOT_CHECKED]})
        if beside:
            out.update(prefix={"status": "not_checked", "findings": ["the statement is not read"]},
                       freshness="not_established")
        return out
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
    elif source is not None and not scitt and source.get("format") == "scitt":
        signature = {"key_ref": cp["signature"]["key_ref"], "status": "failed",
                     "findings": [f"{source['source_ref']} gives SCITT signed statements (format scitt); a checkpoint "
                                  "signed under the shared rule is not what it gives"]}
    elif source is not None and not scitt and source["kind"] != "witness":
        signature = {"status": "not_supported", "findings": [f"{source['source_ref']} is a {source['kind']} that "
                                                             "names no format; this check reads nothing from it"]}
    elif source is not None and scitt and source["kind"] == "transparency_log" and source.get("format") != "scitt":
        signature = {"status": "not_supported", "findings": [f"{source['source_ref']} is a transparency_log that "
                                                             "names no format; this check reads nothing from it"]}
    elif source is not None and scitt and source.get("format") != "scitt":
        signature = {"key_ref": cp["signature"]["key_ref"], "status": "failed",
                     "findings": [f"{source['source_ref']} is a {source['kind']}; a SCITT signed statement is not "
                                  "what it gives"]}
    else:
        s = cp["signature"]
        signature = {"key_ref": s["key_ref"]}
        key = keys.get(s["key_ref"])
        # Beside the export, the key must be a witness key listed for a source the policy configures for the chain
        # the verifier checks: taken from its own configuration, never from the checkpoint's chain_id.
        listed_for_chain = {r for src in policy["checkpoint_sources"]
                            if (src["kind"] == "witness" or src.get("format") == "scitt")
                            and chain_id in src["chain_ids"] for r in src.get("key_refs", [])}
        shared_rule_keys = {r for src in policy["checkpoint_sources"] if src["kind"] == "witness"
                            for r in src.get("key_refs", [])}
        statement_keys = {r for src in policy["checkpoint_sources"] if src.get("format") == "scitt"
                          for r in src.get("key_refs", [])}
        if key is None:
            signature.update(status="failed", findings=[f"{s['key_ref']} is not a key in the trust policy"])
        elif beside and s["key_ref"] not in listed_for_chain:
            signature.update(status="failed", findings=[f"the trust policy lists {s['key_ref']} for no witness source "
                                                        f"it configures for {chain_id}"])
        elif source is not None and s["key_ref"] not in source.get("key_refs", []):
            signature.update(status="failed", findings=[f"the trust policy does not list {s['key_ref']} for "
                                                        f"{source['source_ref']}"])
        elif key["role"] != "witness":
            signature.update(status="failed", findings=[f"{s['key_ref']} is a key in role {key['role']}; only a "
                                                        "witness key signs a checkpoint"])
        elif s["key_ref"] in (shared_rule_keys if scitt else statement_keys):
            # One key, one purpose (RFC 9943 section 9.4): a key the policy lists for the other format is refused for
            # this one. From a source the key is also listed for that source, so it is listed both ways; beside the
            # export it may be listed for the other format only, and the reason says which.
            listed_both = s["key_ref"] in shared_rule_keys and s["key_ref"] in statement_keys
            reason = (f"the trust policy lists {s['key_ref']} both for checkpoints under the shared rule and for SCITT "
                      "statements" if listed_both else
                      f"the trust policy lists {s['key_ref']} for checkpoints under the shared rule only, so it signs "
                      "no SCITT statement" if scitt else
                      f"the trust policy lists {s['key_ref']} for SCITT statements only, so it signs no checkpoint "
                      "under the shared rule")
            signature.update(status="failed", findings=[
                reason + "; a witness signs its statements with a key of their own (RFC 9943 section 9.4)"])
        elif s["algorithm"] != "Ed25519" or key["algorithm"] != "Ed25519":
            signature.update(status="not_supported", findings=[f"this check supports Ed25519; the checkpoint uses "
                                                               f"{s['algorithm']}"])
        elif strict_hex(key["public_key_hex"]) is None:
            signature.update(status="failed", findings=[f"the policy's public key for {s['key_ref']} is not written "
                                                        "as lowercase hex pairs and nothing else"])
        else:
            # A statement's pinned header is checked before its signature; a plain checkpoint has none.
            header_status, header_findings = statement_header_findings(cp, scitt, key) if scitt else ("verified", [])
            public = Ed25519PublicKey.from_public_bytes(strict_hex(key["public_key_hex"]))
            if header_status != "verified":
                signature.update(status=header_status, findings=header_findings)
            else:
                try:
                    made_over = cp["_to_be_signed"] if scitt else checkpoint_signed_bytes(cp)
                    public.verify(base64.b64decode(s["value_b64"], validate=True), made_over)
                    signature.update(status="verified", reference_source="trust_policy")
                except Unencodable as exc:
                    signature.update(status="failed", findings=[f"the signed bytes cannot be built: {exc}"])
                except InvalidSignature:
                    signature.update(status="failed", findings=[
                        "the signature does not verify over the statement's Sig_structure" if scitt else
                        "the signature does not verify over the checkpoint's signed bytes"])
    # A statement's kid that a report cannot carry as a key reference (empty, or over 256 characters) is left out of the
    # result; the header check has already given the reason.
    if scitt and "key_ref" in signature and not (isinstance(signature["key_ref"], str)
                                                 and 1 <= len(signature["key_ref"]) <= 256):
        signature.pop("key_ref")
        if signature.get("status") == "verified":  # cannot happen: such a kid names no key in a valid policy
            signature["status"] = "failed"
    out["signature"] = signature

    if is_refused:
        out["key_state"] = refused(policy_result, "the key state")
    elif signature["status"] == "verified":
        value = base64.b64decode(cp["signature"]["value_b64"])
        # An OpenTimestamps proof gives no time that holds, so it carries no _value and never counts here.
        covering = [(i, r) for i, r in enumerate(ts_results) if r["status"] == "verified" and r.get("_value") == value]
        out["key_state"] = key_state(key, cp, covering)
    else:
        out["key_state"] = {"status": "not_checked"}

    if scitt:
        # The service's receipt, its own dimension: checked whatever the witness's signature says, since it is the
        # service's statement about these bytes. The log's consistency is not checked in this version.
        if is_refused:
            out["receipt"] = refused(policy_result, "the receipt")
        elif source is not None and not beside and source.get("format") != "scitt":
            out["receipt"] = {"status": "not_checked", "findings": [f"{source['source_ref']} is not a SCITT source; "
                                                                    "its receipts are not read"]}
        else:
            allowed = (source.get("service_key_refs", []) if source is not None and not beside else
                       sorted({r for src in policy["checkpoint_sources"] if src.get("format") == "scitt"
                               and chain_id in src["chain_ids"] for r in src.get("service_key_refs", [])}))
            out["receipt"] = check_receipt(scitt, policy, allowed, where)
        out["log_consistency"] = {"status": "not_checked", "findings": [LOG_CONSISTENCY_NOT_CHECKED]}
        out["status"] = combine(independence["status"], signature["status"], out["key_state"]["status"],
                                out["receipt"]["status"])
    else:
        out["status"] = combine(independence["status"], signature["status"], out["key_state"]["status"])
    if beside:
        out["comparison"] = {"status": "not_checked", "findings": ["compared only with a verified independent "
                                                                   "checkpoint; the prefix is reported apart"]}
        ks = out["key_state"]
        if signature["status"] != "verified" or ks["status"] != "verified":
            out["prefix"] = {"status": "not_checked", "findings": ["the checkpoint's signature or the key's state "
                                                                   "when it signed is not verified"]}
        elif cp["chain_id"] != chain_id:
            out["prefix"] = {"status": "not_checked", "findings": [f"the checkpoint is for {cp['chain_id']}; the "
                                                                   f"verifier checks {chain_id}"]}
        else:
            prefix = compare(export, cp)
            if prefix["status"] == "verified":
                prefix.update(time_basis=ks["time_basis"], time=ks["time"])
                if "timestamp_index" in ks:
                    prefix["timestamp_index"] = ks["timestamp_index"]
            out["prefix"] = prefix
        out["freshness"] = "not_established"
    elif out["status"] != "verified":
        out["comparison"] = {"status": "not_checked", "findings": ["compared only with a verified independent "
                                                                   "checkpoint"]}
    elif cp["chain_id"] != chain_id:
        out["comparison"] = {"status": "not_checked", "findings": [f"the checkpoint is for {cp['chain_id']}; the "
                                                                   f"verifier checks {chain_id}"]}
    else:
        out["comparison"] = compare(export, cp)
    return out


# ---------------------------------------------------------------- a report read with its documents

def all_obtained(ctx):
    """The checkpoints the verifier obtained from its sources, then those carried beside the export, in that order."""
    beside = []
    for i, item in enumerate((ctx["attachment"] or {}).get("checkpoints", [])):
        o = {"obtained_from": "beside_export", "attachment_index": i}
        if isinstance(item, dict) and item.get("format") == "scitt":  # a statement with its receipt, carried
            o.update(statement_b64=item.get("statement_b64"), receipt_b64=item.get("receipt_b64"))
            read_statement(o)
        else:
            o["checkpoint"] = item
        beside.append(o)
    sources = [read_statement(dict(o)) if "statement_b64" in o else o for o in ctx["obtained"]]
    return sources + beside


def with_conflicts(obtained, results):
    """Two checkpoints of one chain and count, each with its signature and key state verified, that fix different last
    links cannot both hold: a witness signed two histories, or the chain was forked. Each is reported as it is, with a
    finding that names both and their keys. Wherever they came from."""
    good = [(i, o["checkpoint"]) for i, (o, r) in enumerate(zip(obtained, results))
            if o.get("checkpoint") and r["signature"]["status"] == "verified" and r["key_state"]["status"] == "verified"]
    for a, (i, x) in enumerate(good):
        for j, y in good[a + 1:]:
            if (x["chain_id"], x["count"]) == (y["chain_id"], y["count"]) and x["head_link"] != y["head_link"]:
                finding = (f"checkpoints {i} ({x['signature']['key_ref']}) and {j} ({y['signature']['key_ref']}) fix "
                           f"{x['count']} entries of {x['chain_id']} with different last links: they cannot both hold; "
                           "a witness signed two histories, or the chain was forked")
                for k in (i, j):
                    results[k].setdefault("findings", []).append(finding)
    return results


def run_context(ctx):
    obtained = all_obtained(ctx)
    held = [o["checkpoint"] for o in obtained if o.get("checkpoint") and "signature" in o["checkpoint"]]
    ts = (ctx["attachment"] or {}).get("timestamps", [])
    ts_results = [check_timestamp(t, ctx["policy"], ctx["export"], ctx["chain_id"], held, ctx.get("headers"))
                  for t in ts]
    cp_results = [check_checkpoint(o, ctx["policy"], ctx["export"], ctx["chain_id"], ts_results) for o in obtained]
    return ts_results, with_conflicts(obtained, cp_results)


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
    obtained = all_obtained(ctx)
    for label, count_key, results, n, key in (("timestamp", "timestamp_count", report["timestamps"], len(stated),
                                               "timestamp_index"),
                                              ("checkpoint", "checkpoint_count", report["checkpoints"],
                                               len(obtained), "checkpoint_index")):
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
        if (r.get("format") == "opentimestamps") != (ref.get("format") == "opentimestamps"):
            problems.append(f"timestamp {i}: not reported in the format the attachment states it")
            continue
        if ref.get("format") == "opentimestamps":
            # An OpenTimestamps proof: the block and the miner's time as found, never more than the check finds.
            if r["subject"] != shown_subject(stated[i]["subject"]):
                problems.append(f"timestamp {i}: subject not as the attachment states it")
            if r["status"] == "verified" and ref["status"] != "verified":
                problems.append(f"timestamp {i}: reported verified, but the reference check finds {ref['status']}")
            for k, got in r["checks"].items():
                if got == "verified" and ref["checks"].get(k) != "verified":
                    problems.append(f"timestamp {i}: {k} reported verified, but it is {ref['checks'].get(k)}")
            if r["status"] == ref["status"] == "verified" and (r.get("block"), r.get("miner_stated_time")) != (
                    ref.get("block"), ref.get("miner_stated_time")):
                problems.append(f"timestamp {i}: the block or the miner's stated time not reported as found")
            continue
        # Read with .get: a result or a timestamp of the other format names no authority, and the reader goes on.
        if r["subject"] != shown_subject(stated[i]["subject"]) or r.get("tsa_ref") != stated[i].get("tsa_ref"):
            problems.append(f"timestamp {i}: subject or tsa_ref not as the attachment states them")
        if r["status"] == "verified" and ref["status"] != "verified":
            problems.append(f"timestamp {i}: reported verified, but the reference check finds {ref['status']}")
        for k in CHECKS:
            if r["checks"].get(k) == "verified" and ref["checks"].get(k) != "verified":
                problems.append(f"timestamp {i}: {k} reported verified, but it is {ref['checks'].get(k)}")
        if r["status"] == ref["status"] == "verified":
            if (r.get("gen_time"), r.get("existed_no_later_than")) != (ref.get("gen_time"),
                                                                       ref.get("existed_no_later_than")):
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
        if not json_integer(i) or i >= len(obtained):
            continue
        ref = cp_ref[i]
        if (r["obtained_from"], r.get("source_ref")) != (ref["obtained_from"], ref.get("source_ref")):
            problems.append(f"checkpoint {i}: not reported as obtained from where it was")
        if "attachment_index" in r and r["attachment_index"] != ref.get("attachment_index"):
            problems.append(f"checkpoint {i}: attachment_index is not the checkpoint's place in the attachment")
        if r.get("format") != ref.get("format"):
            problems.append(f"checkpoint {i}: format not reported as the checkpoint was obtained")
        rr, refr = r.get("receipt", {}), ref.get("receipt", {})
        if rr.get("status") == "verified" and refr.get("status") != "verified":
            problems.append(f"checkpoint {i}: receipt reported verified, but the reference check finds "
                            f"{refr.get('status', 'none')}")
        if rr.get("status") == refr.get("status") == "verified" and any(
                rr.get(k) != refr.get(k) for k in ("service_key_ref", "tree_size", "leaf_index")):
            problems.append(f"checkpoint {i}: the receipt's service key, tree size or leaf index not reported as found")
        if r.get("log_consistency", {}).get("status") == "verified":
            problems.append(f"checkpoint {i}: log_consistency reported verified; this version checks none")
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
        rp, refp = r.get("prefix"), ref.get("prefix")
        if rp is not None and refp is not None:
            verified_prefix = rp["status"] == "verified"
            if verified_prefix and refp["status"] != "verified":
                problems.append(f"checkpoint {i}: prefix reported verified, but the reference check finds "
                                f"{refp['status']}")
            elif refp["status"] == "failed" and rp["status"] != "failed":
                problems.append(f"checkpoint {i}: a prefix that fails not reported as failed")
            elif verified_prefix and any(rp.get(k) != refp.get(k) for k in (
                    "covered_count", "not_covered_indexes", "time_basis", "time", "timestamp_index")):
                problems.append(f"checkpoint {i}: the prefix's entries or its time not reported as found")
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
            if k["algorithm"] == "RSA-2048":
                # Not seed-derived: the key RFC 9500 publishes, held as its public modulus and exponent (V16 checks
                # them against the RFC's text).
                if (int(k["modulus_hex"], 16).bit_length() != 2048 or k["public_exponent_hex"] != "010001"
                        or k["name"] != name or "RFC 9500" not in k["published_in"]):
                    bad.append(name)
                continue
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
            public, k = x509.load_der_x509_certificate(der).public_key(), v["test_keys"][n]
            if isinstance(public, rsa.RSAPublicKey):
                numbers = public.public_numbers()
                same = (f"{numbers.n:x}", f"{numbers.e:x}") == (k["modulus_hex"].lstrip("0"),
                                                               k["public_exponent_hex"].lstrip("0"))
            else:
                point = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                same = point.hex() == k["public_key_hex"]
            if sha256(der).hex() != cert["sha256"] or not same:
                bad.append(n)
    elif kind == "published_rsa_key":
        # The RSA test key against RFC 9500's text: the first and last bytes of the modulus as the RFC prints them, the
        # modulus's SHA-256, the exponent, and the size. The private parameters are in generate_vectors.py.
        k = v["test_keys"][c["key"]]
        n = k["modulus_hex"]
        if not (n.startswith(c["modulus_starts_with"]) and n.endswith(c["modulus_ends_with"])
                and sha256(bytes.fromhex(n)).hex() == c["modulus_sha256"] and len(n) == c["bits"] // 4
                and k["public_exponent_hex"] == c["public_exponent_hex"] and k["published_in"] == c["published_in"]):
            bad.append(c["key"])
    elif kind == "scitt_cbor":
        # The strict reader against cbor2, pinned: on every statement, receipt and proof it reads, the two agree and
        # cbor2 writes the same bytes back; on the ones it refuses, it says why, where cbor2 reads some of them.
        import cbor2
        refused = {}
        for name, st in v["scitt"]["statements"].items():
            for member in ("statement_b64", "receipt_b64"):
                if member not in st:
                    continue
                raw = base64.b64decode(st[member])
                try:
                    protected = cose_sign1(raw)[0]  # reads the item and its protected header, strictly
                    mine = cbor_strict(raw)
                except NotCbor as exc:
                    refused[f"{name}/{member}"] = str(exc)
                    continue
                theirs = cbor2.loads(raw)
                if plain(mine) != plain(theirs) or cbor2.dumps(theirs) != raw:
                    bad.append(f"{name}/{member}: the strict reader and cbor2 disagree, or cbor2 writes other bytes")
                if protected and (plain(cbor_strict(protected)) != plain(cbor2.loads(protected))
                                  or cbor2.dumps(cbor2.loads(protected)) != protected):
                    bad.append(f"{name}/{member}: the protected header read differently")
                if member == "receipt_b64" and HDR_VDP in mine.value[1]:
                    proof = mine.value[1][HDR_VDP][VDP_INCLUSION_PROOFS][0]
                    if plain(cbor_strict(proof)) != plain(cbor2.loads(proof)):
                        bad.append(f"{name}: the proof read differently")
        for name, why in c["refused"].items():
            if name not in refused:
                bad.append(f"{name}: read, where the strict reader must refuse it")
            elif why not in refused[name]:
                bad.append(f"{name}: refused for {refused[name]!r}, not for {why!r}")
        for name in refused:
            if name not in c["refused"]:
                bad.append(f"{name}: refused ({refused[name]}), where it must be read")
    elif kind == "scitt_payload":
        # Each statement's payload is the checkpoint's signed bytes under the shared rule, its key_ref field the kid,
        # rebuilt from the values the vector states; and to_be_signed_hex is the Sig_structure over it.
        for name, st in v["scitt"]["statements"].items():
            cp = {**st["checkpoint"], "signature": {"key_ref": st["key_ref"]}}
            if name in c.get("other_payload", []):
                continue
            if checkpoint_signed_bytes(cp).hex() != st["payload_hex"]:
                bad.append(f"{name}: the payload is not the checkpoint's signed bytes")
            protected = cbor_strict(base64.b64decode(st["statement_b64"])).value[0] \
                if name not in c["refused"] else None
            if protected is not None and sig_structure(protected, bytes.fromhex(st["payload_hex"])).hex() \
                    != st["to_be_signed_hex"]:
                bad.append(f"{name}: to_be_signed_hex is not the Sig_structure")
    elif kind == "scitt_log":
        # The log's leaf hashes from the statements' bytes, the root from the leaf hashes (RFC 9162), and each
        # receipt's inclusion path leading from its statement's leaf to that root.
        log = v["scitt"]["log"]
        leaves = [sha256(b"\x00" + base64.b64decode(v["scitt"]["statements"][n]["statement_b64"])) for n in log["leaves"]]
        if [h.hex() for h in leaves] != log["leaf_hashes_hex"]:
            bad.append("the leaf hashes")

        def root_of(hashes_):
            if len(hashes_) == 1:
                return hashes_[0]
            k = 1 << (len(hashes_) - 1).bit_length() - 1
            return sha256(b"\x01" + root_of(hashes_[:k]) + root_of(hashes_[k:]))
        if root_of(leaves).hex() != log["root_hex"]:
            bad.append("the root")
        for name in c["reaching"]:
            st = v["scitt"]["statements"][name]
            receipt = cbor_strict(base64.b64decode(st["receipt_b64"]))
            size, index, path = cbor_strict(receipt.value[1][HDR_VDP][VDP_INCLUSION_PROOFS][0])
            root = root_from_path(sha256(b"\x00" + base64.b64decode(st["statement_b64"])), index, size, path)
            if root is None or root.hex() != st["root_hex"] or (size, index) != (st["tree_size"], st["leaf_index"]):
                bad.append(f"{name}: the path does not lead to the root")
    elif kind == "format_prefixes":
        # The two formats cannot be confused: a Sig_structure starts with 84 6a "Signature1", the
        # shared rule's bytes with "DPS-SIG" 00.
        st = v["scitt"]["statements"][c["statement"]]
        tbs, payload = bytes.fromhex(st["to_be_signed_hex"]), bytes.fromhex(st["payload_hex"])
        if not tbs.startswith(b"\x84\x6aSignature1") or not payload.startswith(MAGIC) or tbs[:8] == MAGIC[:8]:
            bad.append("the prefixes")
    elif kind == "statement_signatures":
        # Every statement's witness signature verifies over its Sig_structure with the test key named, but those the
        # case lists; every receipt's over the root with the service key named.
        for name, st in v["scitt"]["statements"].items():
            if name in c["refused"]:
                continue
            raw = cbor_strict(base64.b64decode(st["statement_b64"])).value
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["test_keys"][st["signed_with"]]["public_key_hex"]))
            try:
                key.verify(raw[3], bytes.fromhex(st["to_be_signed_hex"]))
                if name in c["not_verifying"]:
                    bad.append(f"{name}: verifies, where it must not")
            except InvalidSignature:
                if name not in c["not_verifying"]:
                    bad.append(f"{name}: the statement's signature")
            if "receipt_b64" in st:
                rc = cbor_strict(base64.b64decode(st["receipt_b64"])).value
                skey = Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(v["test_keys"][st["receipt_signed_with"]]["public_key_hex"]))
                try:
                    skey.verify(rc[3], bytes.fromhex(st["receipt_to_be_signed_hex"]))
                except InvalidSignature:
                    bad.append(f"{name}: the receipt's signature")
    elif kind == "ots_real":
        # The real proof, read strictly, replays from the SHA-256 of R0's seal to both mainnet headers, the result being
        # each header's Merkle root as stored in its bytes (the reverse of the hex explorers show); each header hashes
        # to its block's hash.
        ots = v["opentimestamps"]
        ts = ots["timestamps"][c["proof"]]["timestamp"]
        digest, tree = ots_read(base64.b64decode(ts["proof_b64"]))
        if digest != sha256(subject_value(ts["subject"])):
            bad.append("the proof's digest is not the SHA-256 of its subject's bytes")
        found = sorted((h, msg) for kind_, h, msg in ots_attestations(tree, digest) if kind_ == "bitcoin")
        if [h for h, _ in found] != c["heights"]:
            bad.append(f"the proof's Bitcoin heights are {[h for h, _ in found]}")
        for h, msg in found:
            x = ots["headers"]["mainnet"].get(str(h))
            hdr = bytes.fromhex(x["header_hex"]) if x else b""
            if hdr[36:68] != msg or hdr[36:68][::-1] == msg:
                bad.append(f"block {h}: the result is not the Merkle root as stored in the header")
            if x and sha256(sha256(hdr))[::-1].hex() != x["block_hash"]:
                bad.append(f"block {h}: the header does not hash to the block's hash")
    elif kind == "ots_refusals":
        # The strict reader refuses each malformed proof, for the reason named; it reads every other proof.
        for name, x in v["opentimestamps"]["timestamps"].items():
            try:
                ots_read(base64.b64decode(x["timestamp"]["proof_b64"]))
                got = None
            except (NotOts, OtsNotSupported) as exc:
                got = str(exc)
            want = c["refused"].get(name)
            if want is None and got is not None:
                bad.append(f"{name}: refused ({got}), where it must be read")
            elif want is not None and (got is None or want not in got):
                bad.append(f"{name}: {'read' if got is None else repr(got)}, where it must be refused for {want!r}")
    elif kind == "reproduction":
        if load_generator().render() != (HERE / "vectors.json").read_bytes():
            bad.append("vectors.json")
    elif kind == "inline_checkpoint":
        # The attachment schema carries the checkpoint object inline: it must be the checkpoint schema's, member for
        # member, so that a checkpoint beside the export is the same object as one from a source.
        att = strict_json(SCHEMAS["attachment"].read_bytes())["$defs"]["checkpoint"]
        cp = strict_json(SCHEMAS["checkpoint"].read_bytes())
        if att != {k: cp[k] for k in ("description", "type", "additionalProperties", "required", "properties")}:
            bad.append("the attachment's checkpoint is not the checkpoint schema's")
    elif kind == "duplicate_member":
        # An attachment whose carried checkpoint names a member twice, held as text: not read. A reader keeping the
        # last member reads a checkpoint whose signature verifies; one keeping the first reads another checkpoint.
        t = v["texts"][c["text"]]
        raw = t["attachment_text"].encode("utf-8")
        try:
            strict_json(raw)
            bad.append("read a document that names a member twice")
        except ValueError:
            pass
        last = json.loads(raw)  # json.loads keeps the last member
        first = json.loads(raw, object_pairs_hook=lambda items: dict(reversed(items)))  # keeps the first member
        if (pointer_get(last, t["differs_at"]), pointer_get(first, t["differs_at"])) != (t["last_member"],
                                                                                        t["first_member"]):
            bad.append("the last-member and first-member readings")
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["test_keys"][c["key"]]["public_key_hex"]))
        for reading, should_verify in ((last, True), (first, False)):
            cp = reading["checkpoints"][0]
            try:
                public.verify(base64.b64decode(cp["signature"]["value_b64"]), checkpoint_signed_bytes(cp))
                ok = True
            except InvalidSignature:
                ok = False
            if ok != should_verify:
                bad.append(f"the {'last' if should_verify else 'first'}-member reading's signature")
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
    # A held checkpoint is a name in vectors.json, or {"from", "patch", "schema_valid": false}: a checkpoint obtained
    # from a source reaches this check without a schema check, so a case may hold one that is not schema-valid.
    held = []
    for h in c.get("held_checkpoints", []):
        if isinstance(h, str):
            held.append(schema_valid(validators["checkpoint"], v["checkpoints"][h]["checkpoint"], "held checkpoint"))
            continue
        cp = resolve({"from": h["from"], "patch": h.get("patch", [])}, v)
        found = errors(validators["checkpoint"], cp)
        if h.get("schema_valid", True) != (not found):
            raise ValueError("a held checkpoint's schema validity is not what the case says")
        held.append(cp)
    r = reference(check_timestamp, ts, policy, export, chain_of(c, v), held, held_headers(c, v))
    summary = {"status": r["status"], **r["checks"], "issuer_time": r["issuer_time"]["status"]}
    for k in ("existed_no_later_than", "gen_time"):
        if k in c["expected"]:
            summary[k] = r.get(k)
    if r.get("format") == "opentimestamps":
        for k, got in (("height", (r.get("block") or {}).get("height")), ("hash_hex", (r.get("block") or {}).get(
                "hash_hex")), ("miner_stated_time", r.get("miner_stated_time"))):
            if k in c["expected"]:
                summary[k] = got
        if "result_schema_valid" in c["expected"]:
            written = {"timestamp_index": 0, **{k: x for k, x in r.items() if not k.startswith("_")}}
            summary["result_schema_valid"] = not errors(ots_result_validator(), written)
    if "finding" in c["expected"]:  # a phrase the findings must hold: the reason, where several rules could refuse
        summary["finding"] = c["expected"]["finding"] if c["expected"]["finding"] in " ".join(r["findings"]) else None
    if "consistency" in c["expected"]:
        summary["consistency"] = r["issuer_time"].get("consistency")
    detail = r["findings"] + r["issuer_time"].get("findings", [])
    return summary, "; ".join(detail)


def expected_timestamp(c):
    """Every check, the timestamp and the issuer's time are expected verified unless the case says otherwise. For an
    OpenTimestamps proof (headers named), its five checks are expected verified and the issuer's time not checked."""
    if "headers" in c or c.get("format") == "opentimestamps":
        full = {"status": "verified", **{k: "verified" for k in OTS_CHECKS}, "issuer_time": "not_checked"}
    else:
        full = {"status": "verified", **{k: "verified" for k in CHECKS}, "issuer_time": "verified"}
    full.update(c["expected"])
    return full


OTS_CHECKS = ("proof", "subject_bytes", "operations", "attestation", "header")


def held_headers(c, v):
    """The Bitcoin headers a case's verifier holds: headers {"source_ref", "set": a set in vectors.json, "only":
    [heights]} or {"source_ref", "headers": {height: hex}}; none when the case names none."""
    spec = c.get("headers")
    if spec is None:
        return None
    if "headers" in spec:
        return {"source_ref": spec["source_ref"], "headers": dict(spec["headers"])}
    full = v["opentimestamps"]["headers"][spec["set"]]
    only = spec.get("only")
    return {"source_ref": spec["source_ref"],
            "headers": {h: x["header_hex"] for h, x in full.items() if only is None or int(h) in only}}


def ots_result_validator():
    """The report schema's OpenTimestamps result, as a validator of one result."""
    report = strict_json(SCHEMAS["report"].read_bytes())
    return Draft202012Validator({"$schema": report["$schema"], "$defs": report["$defs"],
                                 "$ref": "#/$defs/ots_timestamp_result"})


def checkpoint_case(c, v, validators):
    """checkpoint: a name in vectors.json, {"from", "patch"}, issuer_checkpoint, or null. schema_valid: false marks a
    checkpoint that is deliberately not valid against the schema, which the check must still report."""
    export = schema_valid(validators["pv_export"], v["exports"][c.get("export", "full")], "export")
    policy = schema_valid(validators["trust_policy"], apply_patch(v["trust_policy"], c.get("policy_patch", []), v),
                          "trust policy")
    name = c.get("checkpoint")
    carrier = None  # statement: a name under /scitt/statements, or {"from", "patch"}: a SCITT statement with its receipt
    if "statement" in c:
        carrier = resolve(c["statement"] if isinstance(c["statement"], dict)
                          else f"/scitt/statements/{c['statement']}/carrier", v)
        cp = None
    elif name is None:
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
    chain_id = chain_of(c, v)
    obtained = {"checkpoint": cp, "obtained_from": c.get("obtained_from", "configured_source")}
    if c.get("source_ref"):
        obtained["source_ref"] = c["source_ref"]
    if carrier is not None:
        obtained.update(copy.deepcopy(carrier))
        read_statement(obtained)
    # Other checkpoints read at the same time (others): from a source or beside the export, by name in vectors.json.
    others = []
    for o in c.get("others", []):
        o = dict(o)
        if "statement" in o:
            o.update(copy.deepcopy(v["scitt"]["statements"][o.pop("statement")]["carrier"]))
            read_statement(o)
        else:
            o["checkpoint"] = copy.deepcopy(v["checkpoints"][o.pop("checkpoint")]["checkpoint"])
        others.append(o)
    all_cps = [obtained] + others
    held = [o["checkpoint"] for o in all_cps if o["checkpoint"] and "signature" in o["checkpoint"]]
    ts_results = [reference(check_timestamp, t, policy, export, chain_id, held, held_headers(c, v))
                  for t in timestamps]
    results = [reference(check_checkpoint, o, policy, export, chain_id, ts_results) for o in all_cps]
    r = with_conflicts(all_cps, results)[0]
    summary = {d: (r[d] if d == "status" else r[d]["status"]) for d in CHECKPOINT_DIMENSIONS}
    if r["key_state"]["status"] == "verified":
        summary["time_basis"] = r["key_state"]["time_basis"]
    for k in ("covered_count", "not_covered_indexes"):
        if k in c["expected"]:
            summary[k] = r["comparison"].get(k)
    if "prefix" in r:
        summary["prefix"], summary["freshness"] = r["prefix"]["status"], r["freshness"]
        for k in ("covered_count", "not_covered_indexes", "time_basis", "time"):
            if f"prefix_{k}" in c["expected"]:
                summary[f"prefix_{k}"] = r["prefix"].get(k)
    if "conflict" in c["expected"]:
        summary["conflict"] = any("cannot both hold" in f for f in r.get("findings", []))
    if "finding" in c["expected"]:  # a phrase the reason must hold
        summary["finding"] = c["expected"]["finding"] if c["expected"]["finding"] in " ".join(
            r.get("signature", {}).get("findings", [])) else None
    if "result_schema_valid" in c["expected"]:
        # The result as a report carries it: valid against the report schema's checkpoint result.
        written = {"checkpoint_index": 0, **{k: x for k, x in r.items() if not k.startswith("_")}}
        summary["result_schema_valid"] = not errors(checkpoint_result_validator(), written)
    if "receipt" in r:
        summary["receipt"], summary["log_consistency"] = r["receipt"]["status"], r["log_consistency"]["status"]
        for k in ("service_key_ref", "tree_size", "leaf_index"):
            if k in c["expected"]:
                summary[k] = r["receipt"].get(k)
        if "receipt_finding" in c["expected"]:  # a phrase the receipt's findings must hold
            summary["receipt_finding"] = c["expected"]["receipt_finding"] if c["expected"]["receipt_finding"] in " ".join(
                r["receipt"].get("findings", [])) else None
    detail = [f"{d}: {f}" for d in CHECKPOINT_DIMENSIONS[1:] for f in r[d].get("findings", [])] + r.get("findings", [])
    if "receipt" in r:
        detail += [f"receipt: {f}" for f in r["receipt"].get("findings", [])]
    if "prefix" in r:
        detail += [f"prefix: {f}" for f in r["prefix"].get("findings", [])]
    return summary, "; ".join(detail)


def expected_checkpoint(c):
    """Every dimension is expected verified, on the stated time, unless the case says otherwise. A checkpoint beside
    the export is expected failed as an independent checkpoint (independence failed, comparison not checked), its
    prefix verified and its freshness not established, unless the case says otherwise."""
    full = {d: "verified" for d in CHECKPOINT_DIMENSIONS}
    full["time_basis"] = "stated_time"
    if c.get("obtained_from") == "beside_export":
        full.update(status="failed", independence="failed", comparison="not_checked", prefix="verified",
                    freshness="not_established")
    if "statement" in c:  # a SCITT statement: its receipt verified, the log's consistency not checked
        full.update(receipt="verified", log_consistency="not_checked")
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
        if "statement" in o:  # a SCITT statement with its receipt, from a source: read by all_obtained
            o.update(copy.deepcopy(v["scitt"]["statements"][o.pop("statement")]["carrier"]))
            obtained.append(o)
            continue
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
           "obtained": obtained, "headers": held_headers(c, v)}
    problems = reference(read_with_documents, report, ctx)
    return ("inconsistent" if problems else "consistent"), "; ".join(problems)


def main():
    sys.stdout.reconfigure(errors="backslashreplace")  # some cases hold text with no UTF-8 encoding, on purpose
    # Every document this check reads, its fixtures and schemas included, is read with duplicate members rejected.
    cases = strict_json((HERE / "cases.json").read_bytes())
    v = strict_json((HERE / "vectors.json").read_bytes())
    validators = {}
    for name, p in SCHEMAS.items():
        schema = strict_json(p.read_bytes())
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)
        print(f"[ok  ] schemas/{p.name}: valid JSON Schema 2020-12")
    validators["pv_export"] = Draft202012Validator(strict_json(PV_EXPORT_SCHEMA.read_bytes()))

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
