# SPDX-License-Identifier: Apache-2.0
"""Checks for the signatures extension, version 0.1.0 (a proposal).

Runs the cases in cases.json over the values in vectors.json, which generate_vectors.py writes:

  schema cases      a base document from vectors.json (the attachment, one assertion, the trust policy or the
                    report), changed by a patch, against the extension's schemas (the trust policy against anchoring
                    0.2.0's, which is the one trust policy); and the fixture export, the fixture action-binding
                    attachments and the fixture records against the schemas they claim
  vector cases      the values in vectors.json recomputed: SHA-256, the length prefix (bytes, not characters), the
                    test keys from their seed texts and the RSA key against RFC 9500's text, each assertion's signed
                    bytes, every Ed25519 and ECDSA signature, the WebAuthn client data and authenticator data, the
                    certificates, the tokens' imprints, and vectors.json itself, byte for byte, as
                    generate_vectors.py writes it
  person cases      the reference check of one person's signature against the trust policy and the documents
  seal cases        the reference check of one organisation's seal
  timestamp cases   the reference check of one independent timestamp over a signature value (anchoring's assertion)
  pairing cases     a report read with the documents it covers (JSON Schema cannot compare two documents)

The reference check gives a result for every input that is valid against the schemas, and never stops on one. A case
in which it raises an exception fails, whatever the case expects.

Dependencies: jsonschema (tools/requirements.txt), cryptography and asn1crypto (requirements.txt in this folder). This
file verifies every signature with cryptography and parses the tokens with asn1crypto; it implements no
cryptographic primitive. It imports nothing from the other extensions' runners: the small pieces of anchoring it
needs (the shared rule, the key states, the trust policy's refusal, the token check) are written again here, from
the anchoring 0.2.0 text, with the same results and the same wording. A document's bytes as received are, in these
cases, its JSON with no whitespace, in UTF-8.

Usage:  python extensions/signatures/tests/run_checks.py
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
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCHEMAS = {
    "attachment": HERE.parent / "schemas" / "signatures-attachment.schema.json",
    "report": HERE.parent / "schemas" / "verification-report.schema.json",
}
OTHER_SCHEMAS = {
    # The trust policy is anchoring 0.2.0's: one policy document holds the keys of every role and the authorities.
    "trust_policy": ROOT / "extensions" / "anchoring" / "schemas" / "trust-policy.schema.json",
    "pv_export": ROOT / "extensions" / "portable-verification" / "schemas" / "verification-export.schema.json",
    "ab_attachment": ROOT / "extensions" / "action-binding" / "schemas" / "execution-evidence.schema.json",
    "core_record": ROOT / "standard" / "v5.0" / "schemas" / "decision-record.schema.json",
}
ANCHORING_VECTORS = ROOT / "extensions" / "anchoring" / "tests" / "vectors.json"
PROFILE, VERSION = "dps-signatures", "0.1.0"
MAGIC = b"DPS-SIG\x00"
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
PERSON_TYPES = ("person_approval", "person_review", "person_affirmation")
PERSON_SUITES, SEAL_SUITES = ("Ed25519", "WebAuthn-ES256"), ("Ed25519",)
TS_CHECKS = ("token", "message_imprint", "subject_bytes", "message_digest", "tsa_signature", "signer_certificate",
             "tsa_state")
# The token signature algorithms this check supports (digest algorithm, signature algorithm), each with SHA-256: the
# ones anchoring 0.2.0's reference check supports.
TOKEN_ALGORITHMS = {("sha256", "sha256_ecdsa"): "ECDSA P-256", ("sha256", "sha256_rsa"): "RSA PKCS#1 v1.5"}
PERSON_DIMENSIONS = ("status", "signature", "subject", "key_state", "identity")
SEAL_DIMENSIONS = ("status", "signature", "subject", "key_state")
READABLE = {"application/json"}  # media types this check reads a record from
UP, UV = 0x01, 0x04  # authenticatorData flags: user present, user verified
SEAL_SIGNED_BYTES_REF = f"{PROFILE} {VERSION} organisation_seal"  # what a copy of a seal names as its signed_bytes_ref


def sha256(data):
    return hashlib.sha256(data).digest()


def compact(doc):
    """A document's bytes as received, by the convention of these cases: its JSON with no whitespace, in UTF-8. A
    document holding a lone surrogate has no UTF-8 encoding, so no bytes: the check that needs them fails."""
    try:
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except UnicodeEncodeError:
        raise Unencodable("the document has no UTF-8 encoding: it holds a lone surrogate") from None


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


def b64decode(text):
    return base64.b64decode(text, validate=True)


def b64url_decode(text):
    if not isinstance(text, str) or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                                        for c in text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def combine(*statuses):
    s = set(statuses)
    for worst in ("failed", "unavailable", "not_supported", "not_checked"):
        if worst in s:
            return worst
    return "verified"


# ---------------------------------------------------------------- the shared signed-bytes rule (anchoring)

def lp(data):
    """4-byte big-endian length, then the bytes."""
    return len(data).to_bytes(4, "big") + data


def signed_bytes(fields):
    return MAGIC + b"".join(lp(f) for f in fields)


class Unencodable(ValueError):
    """A value the signed-bytes rule cannot encode. The verifier reports it as failed."""


def text(value):
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise Unencodable(f"{value!r} has no UTF-8 encoding: it holds a lone surrogate") from None


def digest(value):
    """32 raw bytes, or the empty byte string for a digest the source does not state (the shared rule)."""
    return b"" if value is None else bytes.fromhex(value)


def person_signed_bytes(ps, profile=PROFILE, version=VERSION, assertion=None, key_ref=None):
    """The person's assertions, each with one fixed field order (README, "Signed bytes"). The verifier takes the
    profile, the version and the assertion type from what it checks, never from bytes supplied with the signature."""
    kind = assertion or ps["assertion"]
    fields = [text(profile), text(version), text(kind), text(key_ref or ps["signature"]["key_ref"]),
              text(ps["decision_id"])]
    if kind == "person_affirmation":
        fields.append(digest(ps["affirmed_digest"]))
    else:
        fields += [text(ps["stage_id"]), text(ps["outcome"]), digest(ps["shown_spec_digest"]),
                   digest(ps.get("shown_view_digest"))]
        if kind == "person_approval":
            fields.append(digest(ps["approved_spec_digest"]))
    fields.append(text(ps["signed_at"]))
    return signed_bytes(fields)


def seal_signed_bytes(seal, profile=PROFILE, version=VERSION, assertion="organisation_seal", key_ref=None):
    s = seal["sealed"]
    return signed_bytes([text(profile), text(version), text(assertion), text(key_ref or seal["signature"]["key_ref"]),
                         text(s["kind"]), text(s["id"]), digest(s["digest"]), text(seal["sealed_at"])])


def assertion_signed_bytes(a):
    return seal_signed_bytes(a) if a["assertion"] == "organisation_seal" else person_signed_bytes(a)


def identify(a):
    """What a timestamp's subject names about an assertion, as anchoring 0.2.0 names it: its type, key reference and
    identifiers. The subject may also name the profile (dps-signatures), which says nothing more."""
    of = {"assertion": a["assertion"], "key_ref": a["signature"]["key_ref"]}
    if a["assertion"] == "organisation_seal":
        of.update(sealed_kind=a["sealed"]["kind"], sealed_id=a["sealed"]["id"])
    else:
        of["decision_id"] = a["decision_id"]
        if "stage_id" in a:
            of["stage_id"] = a["stage_id"]
    return of


def names(of):
    return {k: v for k, v in of.items() if k != "profile"}


def stated_time_of(a):
    return ("sealed_at", a["sealed_at"]) if a["assertion"] == "organisation_seal" else ("signed_at", a["signed_at"])


# ---------------------------------------------------------------- the trust policy

def public_key_identity(key):
    """The public key of a policy entry, decoded, so that one key written two ways or labelled two ways is one key:
    a P-256 point written compressed (33 bytes) or uncompressed (65 bytes) is its curve and coordinates; an RSA key,
    given as a DER SubjectPublicKeyInfo or PKCS#1 RSAPublicKey, is its modulus and exponent; a key of another kind in
    a SubjectPublicKeyInfo is its raw bytes; anything else (an Ed25519 key's 32 raw bytes) is its bytes as written.
    The algorithm label plays no part here: it is read where a signature is verified."""
    try:
        raw = bytes.fromhex(key["public_key_hex"])
    except ValueError:
        return ("text", key["public_key_hex"].lower())
    if len(raw) in (33, 65) and raw[:1] in (b"\x02", b"\x03", b"\x04"):
        try:
            point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw).public_numbers()
            return ("ec", point.curve.name, point.x, point.y)
        except ValueError:
            pass  # not a point of P-256: the bytes themselves are the key
    try:
        loaded = serialization.load_der_public_key(raw)
    except Exception:  # not a DER public key: the bytes themselves are the key
        return ("bytes", raw)
    if isinstance(loaded, rsa.RSAPublicKey):
        numbers = loaded.public_numbers()
        return ("rsa", numbers.n, numbers.e)
    if isinstance(loaded, ec.EllipticCurvePublicKey):
        numbers = loaded.public_numbers()
        return ("ec", numbers.curve.name, numbers.x, numbers.y)
    try:
        return ("bytes", loaded.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    except Exception:  # a key with no raw form (DSA): its DER is the key
        return ("bytes", raw)


def check_policy(policy):
    """One public key has one key reference, one holder and one role; a reference names one entry. A policy that
    breaks this is refused as a whole: every dimension that relies on it is reported as failed. The same rule, the
    same result and the same wording as anchoring 0.2.0's check, since the policy is anchoring's; except that the
    keys are compared decoded (public_key_identity), whatever their algorithm labels and encodings, as anchoring
    0.2.0's check compares them too. When the entries of one key differ in label or in encoding, this check's finding
    says so; anchoring's does not."""
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
        written = []
        if len({k["algorithm"] for k in group}) > 1:
            written.append("labelled " + " and ".join(k["algorithm"] for k in group))
        if len({k["public_key_hex"].lower() for k in group}) > 1:
            written.append("written in " + " and ".join(str(len(k["public_key_hex"]) // 2) for k in group) + " bytes")
        findings.append(f"{', '.join(k['key_ref'] for k in group)} are one public key listed {len(group)} times, under "
                        f"different {' and '.join(what) if what else 'entries'}"
                        + (f" ({', '.join(written)})" if written else "")
                        + "; one public key has one key reference, one holder and one role")
    return {"status": "failed", "findings": findings} if findings else {"status": "verified"}


def refused(policy_result, what):
    return {"status": "failed", "findings": [f"{what} not checked: the trust policy is refused ("
                                             + "; ".join(policy_result["findings"]) + ")"]}


# ---------------------------------------------------------------- key states (anchoring)

def key_state(key, stated_in, stated_text, covering):
    """The key's state when the signature was made. covering: (index, verified timestamp result) over its value.
    The lower bound (not_before) rests on the stated time; the upper bounds rest on the earliest independent
    timestamp when there is one, and otherwise on the stated time."""
    out = {"key_ref": key["key_ref"]}
    if key.get("revocation_reason"):
        out["revocation_reason"] = key["revocation_reason"]
    stated = instant(stated_text)
    bounds = [instant(key[k]) for k in ("not_before", "not_after")] + (
        [instant(key["revoked_at"])] if key.get("revoked_at") else [])
    if stated is None or any(b is None for b in bounds):
        which = stated_in if stated is None else "a time in the trust policy for " + key["key_ref"]
        out.update(status="failed", findings=[f"{which} cannot be read as a UTC time (a date that does not exist, or "
                                              "a leap second), so the key's state when it signed cannot be read"])
        return out
    best = min(covering, key=lambda c: c[1]["_upper"], default=None)
    upper = best[1]["_upper"] if best else stated
    basis = "independent_timestamp" if best else "stated_time"
    shown = basis.replace("_", " ")
    findings, status = [], "verified"
    if stated < instant(key["not_before"]):
        status = "failed"
        findings.append(f"stated as made at {stated_text}, before {key['key_ref']}'s not_before")
    elif upper > instant(key["not_after"]):
        status = "failed"
        findings.append(f"made after {key['key_ref']}'s not_after, by its {shown}")
    elif key.get("revocation_reason") == "superseded":
        if upper < instant(key["revoked_at"]):
            findings.append(f"{key['key_ref']} was superseded at {key['revoked_at']}; the signature is earlier by its "
                            f"{shown}")
        else:
            status = "failed"
            findings.append(f"not made before {key['key_ref']} was superseded at {key['revoked_at']}, by its {shown}")
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


def covering_timestamps(value, ts_results):
    return [(i, r) for i, r in enumerate(ts_results) if r["status"] == "verified" and r.get("_value") == value]


# ---------------------------------------------------------------- the signature itself

def strict_hex(text):
    """The bytes of a key written as lowercase hex pairs and nothing else, or None for any other writing: a final
    newline, which the schema's $ lets through and bytes.fromhex would skip, an uppercase digit, a space."""
    if not isinstance(text, str) or not text or len(text) % 2 or any(c not in "0123456789abcdef" for c in text):
        return None
    return bytes.fromhex(text)


def ed25519_verify(key, sig, made_over):
    raw = strict_hex(key["public_key_hex"])
    if raw is None:
        return [f"the policy's public key for {key['key_ref']} is not written as lowercase hex pairs and nothing else"]
    try:
        public = Ed25519PublicKey.from_public_bytes(raw)
        public.verify(b64decode(sig["value_b64"]), made_over)
        return []
    except InvalidSignature:
        return ["the signature does not verify over the signed bytes"]
    except (ValueError, TypeError) as exc:
        return [f"the signature or the key cannot be read: {exc}"]


def webauthn_verify(key, sig, made_over):
    """The passkey check: client data (type, challenge, origin), relying party, user presence, signature. Returns the
    findings and the authenticator's flags as facts."""
    findings, flags = [], None
    try:
        client_raw = b64decode(sig["client_data_json_b64"])
        auth = b64decode(sig["authenticator_data_b64"])
        client = strict_json(client_raw)
        if not isinstance(client, dict):
            raise ValueError("clientDataJSON is not a JSON object")
    except (ValueError, TypeError) as exc:
        return [f"the client data or the authenticator data cannot be read: {exc}"], None
    if client.get("type") != "webauthn.get":
        findings.append(f"the client data type is {client.get('type')!r}, not webauthn.get")
    try:
        if b64url_decode(client.get("challenge")) != sha256(made_over):
            findings.append("the challenge is not the SHA-256 of the signed bytes")
    except (ValueError, TypeError):
        findings.append("the challenge cannot be read as base64url")
    origins = key["webauthn"]["origins"]
    origin = client.get("origin")
    if not isinstance(origin, str) or origin not in origins:
        findings.append(f"the origin {origin!r} is not one the policy allows for {key['key_ref']}")
    if len(auth) < 37:
        findings.append("the authenticator data is shorter than 37 bytes")
    else:
        try:
            rp_hash = sha256(text(key["webauthn"]["rp_id"]))
        except Unencodable:
            rp_hash = None
        if auth[:32] != rp_hash:
            findings.append(f"the relying party hash is not that of {key['webauthn']['rp_id']!r}")
        flags = {"user_present": bool(auth[32] & UP), "user_verified": bool(auth[32] & UV)}
        if not flags["user_present"]:
            findings.append("the UP flag is absent: the authenticator does not state user presence")
    if flags is not None:  # the client data's cross-origin statements, carried through as facts when it makes them
        if isinstance(client.get("crossOrigin"), bool):
            flags["cross_origin"] = client["crossOrigin"]
        if isinstance(client.get("topOrigin"), str) and client["topOrigin"]:
            flags["top_origin"] = client["topOrigin"]
    if client.get("crossOrigin") is True or "topOrigin" in client:
        # WebAuthn Level 3, 13.4.9: a relying party validates that a topOrigin is expected. The verifier plays that
        # part through its policy, whose entry cannot yet name expected outside pages, so a framed signature fails.
        findings.append(f"the client data states an outside page (crossOrigin {client.get('crossOrigin')!r}, topOrigin "
                        f"{client.get('topOrigin')!r}); the policy's entry for {key['key_ref']} names no expected "
                        "outside page, so a signature made from one fails")
    raw = strict_hex(key["public_key_hex"])
    if raw is None:
        findings.append(f"the policy's public key for {key['key_ref']} is not written as lowercase hex pairs and "
                        "nothing else")
    elif len(raw) != 65 or raw[:1] != b"\x04":
        # The text says which form a passkey's entry gives. A point written compressed is another writing of the same
        # key, and the policy check decodes it as such; the entry this profile reads gives the uncompressed point.
        findings.append(f"the policy's public key for {key['key_ref']} is not the 65-byte uncompressed point "
                        f"(0x04, x, y) a passkey's entry gives: it is written in {len(raw)} bytes")
    else:
        try:
            public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
            public.verify(b64decode(sig["value_b64"]), auth + sha256(client_raw), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            findings.append("the signature does not verify over authenticatorData || SHA-256(clientDataJSON)")
        except (ValueError, TypeError) as exc:
            findings.append(f"the signature or the key cannot be read: {exc}")
    return findings, flags


def check_signature(a, policy, policy_result, role, suites, made_over):
    """The signature dimension: the key the policy gives for key_ref, in the role the assertion needs, verifies over
    the signed bytes the verifier built. Returns the dimension, the key (if any) and the authenticator flags."""
    sig = a["signature"]
    out = {"key_ref": sig["key_ref"], "algorithm": sig["algorithm"]}
    if policy_result["status"] != "verified":
        out.update(refused(policy_result, "the signature"))
        return out, None, None
    keys = {k["key_ref"]: k for k in policy["keys"]}
    key = keys.get(sig["key_ref"])
    flags = None
    if key is None:
        out.update(status="failed", findings=[f"{sig['key_ref']} is not a key in the trust policy"])
    elif key["role"] != role:
        out.update(status="failed", findings=[f"{sig['key_ref']} is a key in role {key['role']}; only a key in role "
                                              f"{role} makes this assertion"])
    elif sig["algorithm"] not in suites:
        out.update(status="not_supported", findings=[f"this check supports {' and '.join(suites)} for this "
                                                     f"assertion; the signature uses {sig['algorithm']}"])
    elif key["algorithm"] != sig["algorithm"]:
        out.update(status="failed", findings=[f"the signature says {sig['algorithm']}; the policy's key "
                                              f"{sig['key_ref']} is {key['algorithm']}"])
    elif sig["algorithm"] == "WebAuthn-ES256" and not isinstance(key.get("webauthn"), dict):
        # The shared trust-policy schema does not require it; this profile does, for a passkey.
        out.update(status="failed", findings=[f"the trust policy gives no relying party identifier and origins "
                                              f"(webauthn) for the passkey {sig['key_ref']}; a WebAuthn-ES256 key "
                                              "names them"])
    else:
        if sig["algorithm"] == "Ed25519":
            findings = ed25519_verify(key, sig, made_over)
        else:
            findings, flags = webauthn_verify(key, sig, made_over)
        if role == "organisation" and key.get("certificate_b64"):
            try:
                cert = x509.load_der_x509_certificate(b64decode(key["certificate_b64"]))
                held = cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                if held.hex() != key["public_key_hex"]:
                    findings.append(f"the certificate pinned for {key['key_ref']} does not hold its public key")
                    out["certificate"] = "failed"
                else:
                    out["certificate"] = "verified"
            except Exception:  # cryptography raises several types for bytes that are not an Ed25519 certificate
                findings.append(f"the certificate pinned for {key['key_ref']} cannot be read as a certificate holding "
                                "an Ed25519 key")
                out["certificate"] = "failed"
        elif role == "organisation":
            out["certificate"] = "not_checked"
        if findings:
            out.update(status="failed", findings=findings)
        else:
            out.update(status="verified", reference_source="trust_policy")
    return out, key, flags


# ---------------------------------------------------------------- the documents an assertion names

def record_entry(export, decision_id):
    if export is None:
        return None
    return next((e for e in export["entries"] if e["decision_id"] == decision_id and "seal" in e), None)


def entry_actor(entry):
    """affirmation_record.actor_identity from covered bytes that match the entry's seal, or None."""
    if entry["content"]["availability"] != "available":
        return None
    if entry["covered_representation"]["media_type"] not in READABLE:
        return None
    try:
        raw = b64decode(entry["content"]["covered_bytes_b64"])
        if sha256(raw).hex() != entry["seal"]["seal_hash"]:
            return None
        record = strict_json(raw)
    except (ValueError, TypeError):
        return None
    actor = ((record.get("affirmation_record") if isinstance(record, dict) else None) or {}).get("actor_identity")
    return actor if isinstance(actor, str) and actor else None


def digest_against_entry(value_hex, entry, what):
    """A digest said to be a record's seal, against the export entry: the entry's seal, and the covered bytes."""
    findings = []
    if value_hex != entry["seal"]["seal_hash"]:
        return "failed", [f"{what} is not the seal of {entry['decision_id']} in the export"]
    if entry["content"]["availability"] != "available":
        return "unavailable", [f"{what} is the seal the export states for {entry['decision_id']}, but the covered "
                               "bytes are unavailable, so it cannot be recomputed"]
    try:
        raw = b64decode(entry["content"]["covered_bytes_b64"])
    except (ValueError, TypeError) as exc:
        return "failed", [f"the covered bytes of {entry['decision_id']} cannot be read: {exc}"]
    if sha256(raw).hex() != entry["seal"]["seal_hash"]:
        return "failed", [f"the covered bytes of {entry['decision_id']} do not match its seal"]
    return "verified", findings


def check_person_subject(ps, ctx):
    """The signed fields against the document they name. Returns the dimension and the actor the issuer names."""
    kind = ps["assertion"]
    if kind == "person_affirmation":
        entry = record_entry(ctx.get("export"), ps["decision_id"])
        if entry is None:
            return {"status": "not_checked", "findings": [f"the export holds no sealed entry for {ps['decision_id']}"]}, None
        status, findings = digest_against_entry(ps["affirmed_digest"], entry, "the affirmed digest")
        out = {"status": status, "checked_against": "export_entry",
               "covers_affirmation_record": entry["seal"]["affirmation_record_covered"]}
        if findings:
            out["findings"] = findings
        return out, entry_actor(entry)
    att = (ctx.get("action_binding") or {}).get(ps["decision_id"])
    if att is None:
        return {"status": "not_checked", "findings": [f"the verifier holds no action-binding attachment for "
                                                     f"{ps['decision_id']}"]}, None
    out = {"checked_against": "action_binding_attachment"}
    by_id = {}
    for s in att["stages"]:
        by_id.setdefault(s["stage_id"], s)
    stage = by_id.get(ps["stage_id"])
    bad = []
    if stage is None or stage["kind"] != "outcome":
        bad.append(f"{ps['stage_id']} is not an outcome stage of the attachment of {ps['decision_id']}")
        out.update(status="failed", findings=bad)
        return out, None
    if stage["outcome"] != ps["outcome"]:
        bad.append(f"the attachment records outcome {stage['outcome']} for {ps['stage_id']}; the signature says "
                   f"{ps['outcome']}")
    review = by_id.get(stage["review_ref"])
    if review is None or review["kind"] != "review":
        bad.append(f"{ps['stage_id']} answers no review stage")
    else:
        if review["shown_spec_digest"] != ps["shown_spec_digest"]:
            bad.append("the shown specification digest differs from the review's")
        signed_view, stated_view = ps.get("shown_view_digest"), review.get("shown_view_digest")
        if signed_view != stated_view:
            bad.append("signed with no view digest; the review states one" if signed_view is None else
                       "signed with a view digest; the review states none" if stated_view is None else
                       "the shown view digest differs from the review's")
    if kind == "person_approval" and stage.get("approved_spec_digest") != ps["approved_spec_digest"]:
        bad.append("the approved specification digest differs from the outcome's")
    out.update(status="failed" if bad else "verified")
    if bad:
        out["findings"] = bad
    return out, stage.get("actor_ref")


def check_identity(key, policy_result, signature, key_state, issuer_named):
    """The identity dimension: the key's binding to a person, from the policy and the source it names, compared with
    the actor the issuer names. Apart from the signature check; never from the signature itself. Verified only when
    the signature and the key's state are: a key outside its validity, superseded, or compromised with no timestamp
    may have been anyone's by the time it signed, so the signature then shows nothing about its holder."""
    if policy_result["status"] != "verified":
        return refused(policy_result, "the identity")
    if key is None:
        return {"status": "not_checked", "findings": ["the key is not in the trust policy, so it binds no one"]}
    if key["role"] != "person":
        return {"status": "failed", "findings": [f"{key['key_ref']} is a key in role {key['role']}; it binds no "
                                                 "person"]}
    if signature["status"] != "verified":
        return {"status": "not_checked", "findings": ["the signature is not verified, so no one signed these bytes "
                                                      "with this key"]}
    if not key.get("identity_source_ref"):
        # The shared trust-policy schema does not require it; this profile does, for a person's key.
        return {"status": "failed", "basis": "trust_policy", "holder": key["holder"],
                "findings": [f"the trust policy names no identity source (identity_source_ref) for {key['key_ref']}; "
                             "a person's key names the source its binding rests on"]}
    out = {"basis": "trust_policy", "source_ref": key["identity_source_ref"], "holder": key["holder"]}
    if issuer_named is None:
        out.update(status="not_checked", findings=["the issuer names no actor to compare with the key's holder"])
        return out
    out["issuer_named"] = issuer_named
    if issuer_named != key["holder"]:
        out.update(status="failed", consistency="inconsistent",
                   findings=[f"the issuer names {issuer_named}; the trust policy binds {key['key_ref']} to "
                             f"{key['holder']}"])
    elif key_state["status"] != "verified":
        out.update(status="not_checked", consistency="consistent",
                   findings=[f"the key's state when it signed is {key_state['status']}, so the signature does not show "
                             f"that {key['key_ref']}'s holder signed; the actor the issuer names is the holder the "
                             "policy gives"])
    else:
        out.update(status="verified", consistency="consistent")
    return out


def checked_signature(a, build, policy, policy_result, role, suites):
    """The signature dimension over the bytes the verifier builds. A value the shared rule cannot encode (a text
    field with no UTF-8 encoding) fails the signature with the reason; it never stops the check."""
    try:
        made_over = build(a)
    except Unencodable as exc:
        return ({"key_ref": a["signature"]["key_ref"], "algorithm": a["signature"]["algorithm"], "status": "failed",
                 "findings": [f"the signed bytes cannot be built: {exc}"]}, None, None)
    return check_signature(a, policy, policy_result, role, suites, made_over)


def check_person(ps, policy, policy_result, ctx, ts_results):
    """Reference check of one person's signature. Every dimension is reported on its own."""
    out = {"assertion": ps["assertion"], "decision_id": ps["decision_id"]}
    if "stage_id" in ps:
        out["stage_id"] = ps["stage_id"]
    out["key_ref"] = ps["signature"]["key_ref"]
    signature, key, flags = checked_signature(ps, person_signed_bytes, policy, policy_result, "person", PERSON_SUITES)
    out["signature"] = signature
    if flags is not None:
        out["authenticator"] = flags
    out["subject"], issuer_named = check_person_subject(ps, ctx)
    if signature["status"] == "verified":
        value = b64decode(ps["signature"]["value_b64"])
        out["key_state"] = key_state(key, "signed_at", ps["signed_at"], covering_timestamps(value, ts_results))
    elif policy_result["status"] != "verified":
        out["key_state"] = refused(policy_result, "the key state")
    else:
        out["key_state"] = {"status": "not_checked"}
    out["identity"] = check_identity(key, policy_result, signature, out["key_state"], issuer_named)
    out["status"] = combine(signature["status"], out["subject"]["status"], out["key_state"]["status"])
    return out


def attachment_bytes_for_seal(att):
    """The attachment's bytes as issued, with every character of issuer_signature.value_b64 replaced by A, which
    keeps the length: the seal can then be copied into that member after signing."""
    if "issuer_signature" in att:
        att = copy.deepcopy(att)
        att["issuer_signature"]["value_b64"] = "A" * len(att["issuer_signature"]["value_b64"])
    return compact(att)


def check_seal_subject(seal, ctx):
    s = seal["sealed"]
    if s["kind"] == "record":
        entry = record_entry(ctx.get("export"), s["id"])
        if entry is None:
            return {"status": "not_checked", "findings": [f"the export holds no sealed entry for {s['id']}"]}
        status, findings = digest_against_entry(s["digest"], entry, "the sealed digest")
        out = {"status": status, "checked_against": "export_entry"}
        if findings:
            out["findings"] = findings
        return out
    if s["kind"] == "attachment":
        att = (ctx.get("action_binding") or {}).get(s["id"])
        if att is None:
            return {"status": "not_checked", "findings": [f"the verifier holds no action-binding attachment for "
                                                         f"{s['id']}"]}
        out = {"checked_against": "action_binding_attachment"}
        findings = []
        try:
            as_issued = sha256(attachment_bytes_for_seal(att)).hex()
        except Unencodable as exc:
            as_issued = None
            findings.append(f"the attachment of {s['id']} has no bytes as issued: {exc}")
        if as_issued != s["digest"]:
            findings.append(f"the sealed digest is not the digest of the attachment of {s['id']} as issued (with an "
                            "embedded copy of the seal replaced by A)")
        if "issuer_signature" in att:
            # A copy agrees when every member does: a copy labelled otherwise, or naming other signed bytes, is not a
            # copy of this seal, even where the issuer sealed the attachment so.
            copy_ = att["issuer_signature"]
            expected = {"algorithm": seal["signature"]["algorithm"], "key_ref": seal["signature"]["key_ref"],
                        "signed_bytes_ref": SEAL_SIGNED_BYTES_REF, "value_b64": seal["signature"]["value_b64"]}
            differs = [k for k in expected if copy_.get(k) != expected[k]]
            if not differs:
                out["embedded_copy"] = "verified"
            else:
                out["embedded_copy"] = "failed"
                findings.append("the attachment's issuer_signature is not a copy of this seal: " + "; ".join(
                    "its value is not the seal's" if k == "value_b64" else f"its {k} is {copy_.get(k)!r}, the seal's "
                    f"{expected[k]!r}" for k in differs))
        else:
            out["embedded_copy"] = "not_checked"
        out["status"] = "failed" if findings else "verified"
        if findings:
            out["findings"] = findings
        return out
    export = ctx.get("export")
    if export is None:
        return {"status": "not_checked", "findings": ["the verifier holds no export"]}
    out = {"checked_against": "export", "findings": [f"the export states no identifier; {s['id']} is the issuer's "
                                                    "reference for it"]}
    try:
        as_issued = sha256(compact(export)).hex()
    except Unencodable as exc:
        as_issued = None
        out["findings"].append(f"the export has no bytes as issued: {exc}")
    if as_issued != s["digest"]:
        out["status"] = "failed"
        out["findings"].append("the sealed digest is not the digest of the export as issued")
    else:
        out["status"] = "verified"
    return out


def check_seal(seal, policy, policy_result, ctx, ts_results):
    """Reference check of one organisation's seal."""
    out = {"sealed": {"kind": seal["sealed"]["kind"], "id": seal["sealed"]["id"]}, "key_ref": seal["signature"]["key_ref"]}
    signature, key, _ = checked_signature(seal, seal_signed_bytes, policy, policy_result, "organisation", SEAL_SUITES)
    out["signature"] = signature
    out["subject"] = check_seal_subject(seal, ctx)
    if signature["status"] == "verified":
        value = b64decode(seal["signature"]["value_b64"])
        out["key_state"] = key_state(key, "sealed_at", seal["sealed_at"], covering_timestamps(value, ts_results))
    elif policy_result["status"] != "verified":
        out["key_state"] = refused(policy_result, "the key state")
    else:
        out["key_state"] = {"status": "not_checked"}
    out["status"] = combine(signature["status"], out["subject"]["status"], out["key_state"]["status"])
    return out


# ---------------------------------------------------------------- an independent timestamp (anchoring, by reference)

def read_token(raw):
    """The TSTInfo, its exact bytes and the one SignerInfo of a TimeStampToken, or the reason it is not one. The
    guards are anchoring 0.2.0's: genTime in UTC, accuracy within RFC 3161's ranges, T before the year 10000."""
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


def check_timestamp(ts, policy, policy_result, held):
    """Reference check of one timestamp over a signature value, as anchoring 0.2.0 defines the checks, with the same
    results and the same wording. held: the assertions of the attachment, where the signature value is looked for."""
    checks = {k: "not_checked" for k in TS_CHECKS}
    findings = []
    subject = ts["subject"]
    out = {"subject": {k: v for k, v in subject.items() if k != "value_b64"}, "tsa_ref": ts["tsa_ref"],
           "checks": checks, "findings": findings, "signer_time": {"status": "not_checked"}}
    value = b64decode(subject["value_b64"])

    # The subject: are its bytes the signature value of the assertion it names?
    same = [a for a in held if a["signature"]["value_b64"] == subject["value_b64"]]
    if not same:
        findings.append("the attachment holds no assertion with this signature value")
    elif identify(same[0]) == names(subject["of"]):
        checks["subject_bytes"] = "verified"
    else:
        checks["subject_bytes"] = "failed"
        findings.append("the signature value is that of another assertion than the subject names")

    # The token itself.
    try:
        tst, econtent, signer = read_token(b64decode(ts["token_b64"]))
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
    content_type, md = values.get("content_type", []), values.get("message_digest", [])
    if len(content_type) != 1 or len(content_type[0]) != 1 or content_type[0][0].native != "tst_info":
        checks["message_digest"] = "failed"
        findings.append("the signed content-type attribute is not one id-ct-TSTInfo")
    elif len(md) != 1 or len(md[0]) != 1 or md[0][0].native != sha256(econtent):
        checks["message_digest"] = "failed"
        findings.append("the signed messageDigest is not the SHA-256 of the encapsulated TSTInfo")
    else:
        checks["message_digest"] = "verified"

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
        cert_der = b64decode(tsa["certificate_b64"])
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
    required = [checks[k] for k in TS_CHECKS if k != "signer_certificate"]
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

    # The signer's own stated time, compared with T. It never changes the timestamp's own status.
    stated_in, stated = stated_time_of(same[0])
    if instant(stated) is None:
        out["signer_time"] = {"status": "not_checked", "findings": [f"the {stated_in} {stated} is not a real UTC time: "
                                                                    "not compared"]}
    else:
        late = instant(stated) > upper
        out["signer_time"] = {"status": "failed" if late else "verified", "stated": stated, "stated_in": stated_in,
                              "consistency": "inconsistent" if late else "consistent"}
        if late:
            out["signer_time"]["findings"] = [f"the signer's stated time {stated} is later than the timestamp "
                                              f"({iso(upper)})"]
    return out


# ---------------------------------------------------------------- the whole attachment

def run_context(ctx):
    """Every result of one attachment read with its documents and the policy. Nothing here catches an exception: the
    reference check gives a result for every schema-valid input, and the runner fails a case in which it raises."""
    policy, att = ctx["policy"], ctx["attachment"]
    policy_result = check_policy(policy)
    persons, seals = att.get("person_signatures", []), att.get("organisation_seals", [])
    held = persons + seals
    ts_results = [check_timestamp(t, policy, policy_result, held) for t in att.get("timestamps", [])]
    person_results = [check_person(ps, policy, policy_result, ctx, ts_results) for ps in persons]
    seal_results = [check_seal(seal, policy, policy_result, ctx, ts_results) for seal in seals]
    return policy_result, person_results, seal_results, ts_results


# ---------------------------------------------------------------- a report read with its documents

def not_integers(doc, path=""):
    """The paths of the numbers in a document that are not written as JSON integers, such as 0.0."""
    if isinstance(doc, float):
        return [path]
    if isinstance(doc, dict):
        return [p for k, x in doc.items() for p in not_integers(x, f"{path}/{k}")]
    if isinstance(doc, list):
        return [p for i, x in enumerate(doc) for p in not_integers(x, f"{path}/{i}")]
    return []

def digest_or_none(doc):
    try:
        return sha256(compact(doc)).hex()
    except Unencodable:
        return None  # no bytes as received, so no digest a report could state


def expected_documents(ctx):
    docs = []
    if ctx.get("export") is not None:
        docs.append(("export", None, digest_or_none(ctx["export"])))
    for d, att in (ctx.get("action_binding") or {}).items():
        docs.append(("action_binding_attachment", d, digest_or_none(att)))
    return sorted(docs, key=str)


def verified_but_not(label, got, want, problems, what):
    if got == "verified" and want != "verified":
        problems.append(f"{label}: {what} reported verified, but the reference check finds {want}")


def read_with_documents(report, ctx):
    """What a reader holding a report and the documents it covers checks; JSON Schema cannot compare documents."""
    problems = [f"{p} is not written as a JSON integer; every number in a report is one" for p in not_integers(report)]
    policy_ref, persons_ref, seals_ref, ts_ref = run_context(ctx)
    att = ctx["attachment"]
    if report["trust_policy_ref"] != ctx["policy"]["policy_ref"]:
        problems.append("trust_policy_ref is not the policy the documents are read with")
    if report["attachment_digest"] != digest_or_none(att):
        problems.append("attachment_digest is not the digest of the attachment read with it")
    listed = sorted(((d["kind"], d.get("decision_id"), d["digest"]) for d in report["documents"]), key=str)
    if listed != expected_documents(ctx):
        problems.append("documents are not the documents read with the report, with their digests")
    if report["trust_policy"]["status"] != policy_ref["status"]:
        problems.append(f"the trust policy reported {report['trust_policy']['status']}; the reference check finds "
                        f"{policy_ref['status']}")

    for label, count_key, results, n, key in (
            ("person signature", "person_signature_count", report["person_signatures"],
             len(att.get("person_signatures", [])), "signature_index"),
            ("seal", "organisation_seal_count", report["organisation_seals"],
             len(att.get("organisation_seals", [])), "seal_index"),
            ("timestamp", "timestamp_count", report["timestamps"], len(att.get("timestamps", [])), "timestamp_index")):
        if report[count_key] != n:
            problems.append(f"{count_key} is {report[count_key]}; there are {n}")
        indexes = sorted(r[key] for r in results)
        if indexes != list(range(n)):
            problems.append(f"{label} results name {indexes}; each of 0 to {n - 1} must appear once")

    for r in report["person_signatures"]:
        i = r["signature_index"]
        if not json_integer(i) or i >= len(att.get("person_signatures", [])):
            continue
        ref, stated = persons_ref[i], att["person_signatures"][i]
        if (r["assertion"], r["decision_id"], r.get("stage_id"), r["key_ref"]) != (
                stated["assertion"], stated["decision_id"], stated.get("stage_id"), stated["signature"]["key_ref"]):
            problems.append(f"person signature {i}: not reported as the attachment states it")
        for dim in PERSON_DIMENSIONS:
            got = r[dim] if dim == "status" else r[dim]["status"]
            want = ref[dim] if dim == "status" else ref[dim]["status"]
            verified_but_not(f"person signature {i}", got, want, problems, dim)
        if r.get("authenticator") != ref.get("authenticator"):
            problems.append(f"person signature {i}: the authenticator's flags not reported as found")
        ks, rks = r["key_state"], ref["key_state"]
        if ks["status"] == rks["status"] == "verified" and any(
                ks.get(k) != rks.get(k) for k in ("time_basis", "time", "timestamp_index", "revocation_reason")):
            problems.append(f"person signature {i}: the key state's time and its basis not reported as found")
        if r["subject"].get("covers_affirmation_record") != ref["subject"].get("covers_affirmation_record"):
            problems.append(f"person signature {i}: covers_affirmation_record not carried through")
        idn, ridn = r["identity"], ref["identity"]
        if idn["status"] == ridn["status"] == "verified" and (idn.get("source_ref"), idn.get("holder"), idn.get(
                "issuer_named")) != (ridn.get("source_ref"), ridn.get("holder"), ridn.get("issuer_named")):
            problems.append(f"person signature {i}: the identity's source, holder or named actor not as found")
        if ridn.get("consistency") == "inconsistent" and idn.get("consistency") != "inconsistent":
            problems.append(f"person signature {i}: an actor other than the key's holder not reported as inconsistent")

    for r in report["organisation_seals"]:
        i = r["seal_index"]
        if not json_integer(i) or i >= len(att.get("organisation_seals", [])):
            continue
        ref, stated = seals_ref[i], att["organisation_seals"][i]
        if (r["sealed"], r["key_ref"]) != ({"kind": stated["sealed"]["kind"], "id": stated["sealed"]["id"]},
                                           stated["signature"]["key_ref"]):
            problems.append(f"seal {i}: not reported as the attachment states it")
        for dim in SEAL_DIMENSIONS:
            got = r[dim] if dim == "status" else r[dim]["status"]
            want = ref[dim] if dim == "status" else ref[dim]["status"]
            verified_but_not(f"seal {i}", got, want, problems, dim)
        verified_but_not(f"seal {i}", r["signature"].get("certificate"), ref["signature"].get("certificate", "failed"),
                         problems, "the certificate")
        verified_but_not(f"seal {i}", r["subject"].get("embedded_copy"), ref["subject"].get("embedded_copy", "failed"),
                         problems, "the embedded copy")
        ks, rks = r["key_state"], ref["key_state"]
        if ks["status"] == rks["status"] == "verified" and any(
                ks.get(k) != rks.get(k) for k in ("time_basis", "time", "timestamp_index", "revocation_reason")):
            problems.append(f"seal {i}: the key state's time and its basis not reported as found")

    stated_ts = att.get("timestamps", [])
    for r in report["timestamps"]:
        i = r["timestamp_index"]
        if not json_integer(i) or i >= len(stated_ts):
            continue
        ref = ts_ref[i]
        if r["subject"] != ref["subject"] or r["tsa_ref"] != stated_ts[i]["tsa_ref"]:
            problems.append(f"timestamp {i}: subject or tsa_ref not as the attachment states them")
        verified_but_not(f"timestamp {i}", r["status"], ref["status"], problems, "the timestamp")
        for k in TS_CHECKS:
            verified_but_not(f"timestamp {i}", r["checks"][k], ref["checks"][k], problems, k)
        if r["status"] == ref["status"] == "verified":
            if (r["gen_time"], r["existed_no_later_than"]) != (ref["gen_time"], ref["existed_no_later_than"]):
                problems.append(f"timestamp {i}: gen_time or existed_no_later_than not as the token gives them")
        st, rst = r["signer_time"], ref["signer_time"]
        verified_but_not(f"timestamp {i}", st["status"], rst["status"], problems, "the signer's time")
        if rst.get("consistency") == "inconsistent" and st.get("consistency") != "inconsistent":
            problems.append(f"timestamp {i}: a stated time later than the timestamp not reported as inconsistent")
        if "stated" in st and "stated" in rst and (st["stated"], st["stated_in"]) != (rst["stated"], rst["stated_in"]):
            problems.append(f"timestamp {i}: the signer's time not carried through as stated")
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


def source_value(op, vectors, digests):
    if "vector" in op:
        return copy.deepcopy(pointer_get(vectors, op["vector"]))
    if "digest_of" in op:
        return digests[op["digest_of"]]
    return op["value"]


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


def resolve(spec, vectors):
    """A document named by a pointer into vectors.json, or {"from": pointer, "patch": [...]}."""
    if isinstance(spec, str):
        return copy.deepcopy(pointer_get(vectors, spec))
    return apply_patch(pointer_get(vectors, spec["from"]), spec.get("patch", []), vectors)


def errors(validator, doc):
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message[:100]}" for e in validator.iter_errors(doc)]


def schema_case(c, v, validators):
    base = pointer_get(v, c["base"])
    if c["schema"] == "core_record":
        base = json.loads(base)
    doc = apply_patch(base, c["patch"], v)
    found = errors(validators[c["schema"]], doc)
    return ("pass" if not found else "fail"), found


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_vectors", HERE / "generate_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def derived_key(k):
    s = sha256(k["seed_text"].encode("utf-8"))
    if k["algorithm"] == "Ed25519":
        private = Ed25519PrivateKey.from_private_bytes(s)
        return private, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private = ec.derive_private_key(int.from_bytes(s, "big") % (P256_N - 1) + 1, ec.SECP256R1())
    return private, private.public_key().public_bytes(serialization.Encoding.X962,
                                                      serialization.PublicFormat.UncompressedPoint)


def vector_case(c, v):
    kind = c["check"]
    bad = []
    all_assertions = {**v["person_signatures"], **v["organisation_seals"]}
    if kind == "known_vector":
        return ("match" if sha256(c["text"].encode()).hex() == c["digest"] else "mismatch"), ""
    if kind == "length_prefix":
        bad = [t for t, h in c["vectors"] if lp(t.encode("utf-8")).hex() != h]
    elif kind == "record_seals":
        bad = [k for k, r in v["records"].items() if sha256(r["text"].encode("utf-8")).hex() != r["seal_hash"]]
        bad += [k for k, h in c["published"].items() if v["records"][k]["seal_hash"] != h]
    elif kind == "anchoring_fixtures":
        anchoring = json.loads(ANCHORING_VECTORS.read_text(encoding="utf-8"))
        bad = [n for n in c["exports"] if v["exports"][n] != anchoring["exports"][n]]
        bad += [n for n in c["keys"] if v["test_keys"][n] != anchoring["test_keys"][n]]
        bad += [n for n in c["certificates"]
                if v["certificates"][n]["certificate_b64"] != anchoring["tsa_certificates"][n]["certificate_b64"]]
        if (v["trust_policy"]["profile"], v["trust_policy"]["profile_version"]) != (
                anchoring["trust_policy"]["profile"], anchoring["trust_policy"]["profile_version"]):
            bad.append("the trust policy's profile")
    elif kind == "specification":
        s = v["specification"]
        if sha256(s["text"].encode("utf-8")).hex() != s["spec_digest"] or s["spec_digest"] != c["published"]:
            bad.append("specification")
        if sha256(v["view"]["text"].encode("utf-8")).hex() != v["view"]["digest"]:
            bad.append("view")
        for d, att in v["action_binding_attachments"].items():
            for i, spec in enumerate(att["action_specifications"]):
                raw = b64decode(spec["content"]["bytes_b64"])
                if raw != s["text"].encode("utf-8") or sha256(raw).hex() != spec["spec_digest"]:
                    bad.append(f"{d} specification {i}")
    elif kind == "test_keys":
        for name, k in v["test_keys"].items():
            if k["algorithm"] == "RSA-2048":
                # Not seed-derived: the key RFC 9500 publishes, held as its public modulus and exponent (another case
                # checks them against the RFC's text).
                if (int(k["modulus_hex"], 16).bit_length() != 2048 or k["public_exponent_hex"] != "010001"
                        or k["name"] != name or "RFC 9500" not in k["published_in"]):
                    bad.append(name)
            elif derived_key(k)[1].hex() != k["public_key_hex"]:
                bad.append(name)
    elif kind == "published_rsa_key":
        # The RSA test key against RFC 9500's text: the first and last bytes of the modulus as the RFC prints them, the
        # modulus's SHA-256, the exponent, and the size. The private parameters are in generate_vectors.py.
        k = v["test_keys"][c["key"]]
        n = k["modulus_hex"]
        if not (n.startswith(c["modulus_starts_with"]) and n.endswith(c["modulus_ends_with"])
                and sha256(bytes.fromhex(n)).hex() == c["modulus_sha256"] and len(n) == c["bits"] // 4
                and k["public_exponent_hex"] == c["public_exponent_hex"] and k["published_in"] == c["published_in"]):
            bad.append(c["key"])
    elif kind == "certificates":
        for name, cert in v["certificates"].items():
            der = b64decode(cert["certificate_b64"])
            public, k = x509.load_der_x509_certificate(der).public_key(), v["test_keys"][name]
            if isinstance(public, rsa.RSAPublicKey):
                numbers = public.public_numbers()
                same = (f"{numbers.n:x}", f"{numbers.e:x}") == (k["modulus_hex"].lstrip("0"),
                                                               k["public_exponent_hex"].lstrip("0"))
            elif isinstance(public, ec.EllipticCurvePublicKey):
                point = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                same = point.hex() == k["public_key_hex"]
            else:
                raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                same = raw.hex() == k["public_key_hex"]
            if sha256(der).hex() != cert["sha256"] or not same:
                bad.append(name)
    elif kind == "signed_bytes":
        bad = [n for n, x in all_assertions.items() if assertion_signed_bytes(x["assertion"]).hex() != x["signed_bytes_hex"]]
    elif kind == "signed_bytes_fields":
        x = all_assertions[c["assertion"]]
        built = MAGIC.hex() + "".join(lp(bytes.fromhex(f)).hex() for f in c["fields_hex"])
        if built != assertion_signed_bytes(x["assertion"]).hex() or built != x["signed_bytes_hex"]:
            bad.append(c["assertion"])
    elif kind == "signatures":
        for n, x in all_assertions.items():
            if n in c["altered_after_signing"] or x["assertion"]["signature"].get("authenticator_data_b64"):
                continue
            private, _ = derived_key(v["test_keys"][x["signed_with"]])
            made_over = bytes.fromhex(x.get("signature_made_over_hex", x["signed_bytes_hex"]))
            if base64.b64encode(private.sign(made_over)).decode() != x["assertion"]["signature"]["value_b64"]:
                bad.append(n)
    elif kind == "webauthn":
        for n, x in v["person_signatures"].items():
            sig = x["assertion"]["signature"]
            if not sig.get("authenticator_data_b64"):
                continue
            w, client_raw, auth = x["webauthn"], b64decode(sig["client_data_json_b64"]), b64decode(sig["authenticator_data_b64"])
            client = json.loads(client_raw)
            expected_challenge = base64.urlsafe_b64encode(sha256(bytes.fromhex(x["signed_bytes_hex"]))).rstrip(b"=").decode()
            if n not in c["other_challenge"] and (client["challenge"] != expected_challenge
                                                  or w["challenge_b64url"] != expected_challenge):
                bad.append(f"{n}: challenge")
            if client["type"] != w["type"] or client["origin"] != w["origin"]:
                bad.append(f"{n}: client data")
            if (client.get("crossOrigin", False) != w.get("cross_origin", False)
                    or client.get("topOrigin") != w.get("top_origin")):
                bad.append(f"{n}: cross-origin statements")
            if auth[:32] != sha256(w["rp_id"].encode()) or auth[32] != int(w["flags_hex"], 16):
                bad.append(f"{n}: authenticator data")
            if (auth + sha256(client_raw)).hex() != w["authenticator_signed_hex"]:
                bad.append(f"{n}: signed bytes")
            if n in c["altered_after_signing"]:
                continue
            private, _ = derived_key(v["test_keys"][x["signed_with"]])
            made = private.sign(auth + sha256(client_raw), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
            if base64.b64encode(made).decode() != sig["value_b64"]:
                bad.append(f"{n}: signature")
    elif kind == "domain_separation":
        x = all_assertions[c["assertion"]]["assertion"]
        build = seal_signed_bytes if x["assertion"] == "organisation_seal" else person_signed_bytes
        base = build(x)
        for i, other in enumerate(c["others"]):
            kw = [{"profile": other}, {"version": other}, {"assertion": other}, {"key_ref": other}][i]
            if build(x, **kw) == base:
                bad.append(f"field {i + 1}")
    elif kind == "token_imprints":
        for n, t in v["tokens"].items():
            if n in c["not_tokens"]:
                continue
            encap = cms.ContentInfo.load(b64decode(t["token_b64"]))["content"]["encap_content_info"]
            mi = tsp.TSTInfo.load(encap["content"].contents)["message_imprint"]
            if mi["hashed_message"].native != sha256(bytes.fromhex(t["imprint_of_hex"])):
                bad.append(n)
    elif kind == "embedded_copy":
        att = v["action_binding_attachments"][c["decision_id"]]
        seal = v["organisation_seals"][c["seal"]]["assertion"]
        if att["issuer_signature"]["value_b64"] != seal["signature"]["value_b64"]:
            bad.append("copy")
        if sha256(attachment_bytes_for_seal(att)).hex() != seal["sealed"]["digest"]:
            bad.append("digest with A")
        if sha256(compact(att)).hex() == seal["sealed"]["digest"]:
            bad.append("digest over the bytes with the signature present")
    elif kind == "escaped_copy":
        # The copy's value written with \/ escapes: the writing is the same attachment; replacing the value's
        # characters (the rule) gives the sealed digest, as the writing with no escape does, and replacing the
        # written characters gives another, which is not the rule.
        e, att = v["escaped_copy"], v["action_binding_attachments"][c["decision_id"]]
        sealed = v["organisation_seals"][c["seal"]]["assertion"]["sealed"]["digest"]
        written, value = e["attachment_text"].encode("utf-8"), att["issuer_signature"]["value_b64"]
        if "\\/" not in e["value_as_written"] or e["value_as_written"].replace("\\/", "/") != value:
            bad.append("the written value")
        if json.loads(written) != att or compact(att) == written:
            bad.append("the writing")
        if (len(value), len(e["value_as_written"])) != (e["value_characters"], e["written_characters"]):
            bad.append("the counts")
        quoted = ('"value_b64":"' + e["value_as_written"] + '"').encode("utf-8")
        by_value = sha256(written.replace(quoted, b'"value_b64":"' + b"A" * len(value) + b'"')).hex()
        by_writing = sha256(written.replace(quoted, b'"value_b64":"' + b"A" * len(e["value_as_written"]) + b'"')).hex()
        if written.count(quoted) != 1 or (by_value, by_writing) != (
                e["digest_replacing_the_value_characters"], e["digest_replacing_the_written_characters"]):
            bad.append("the digests")
        if e["sealed_digest"] != sealed or sha256(attachment_bytes_for_seal(att)).hex() != sealed:
            bad.append("the sealed digest")
        if by_value != sealed:
            bad.append("replacing the value's characters does not give the sealed digest")
        if by_writing == sealed:
            bad.append("replacing the written characters gives the sealed digest")
    elif kind == "duplicate_member":
        # issuer_signature naming value_b64 twice: not read. A reader keeping the last member would find the
        # attachment as issued; one keeping the first would not.
        e, att = v["duplicate_member"], v["action_binding_attachments"][c["decision_id"]]
        raw = e["attachment_text"].encode("utf-8")
        try:
            strict_json(raw)
            bad.append("read a document that names a member twice")
        except ValueError:
            pass
        if json.loads(raw) != att:  # json.loads keeps the last member
            bad.append("the last-member reading")
        first = json.loads(raw, object_pairs_hook=lambda items: dict(reversed(items)))  # keeps the first member
        if first["issuer_signature"]["value_b64"] == att["issuer_signature"]["value_b64"]:
            bad.append("the first-member reading")
    elif kind == "reproduction":
        if load_generator().render() != (HERE / "vectors.json").read_bytes():
            bad.append("vectors.json")
    else:
        raise ValueError(f"unknown check {kind!r}")
    return ("mismatch" if bad else "match"), ", ".join(bad)


def context_for(c, v, validators, attachment):
    """The documents a reference-check case reads with: the export, the action-binding attachments, the policy."""
    base = v["base_context"]
    export = None
    if c.get("export", base["export"]) is not None:
        export = apply_patch(v["exports"][c.get("export", base["export"])], c.get("export_patch", []), v)
    action_binding = {}
    for d in c.get("action_binding", base["action_binding"]):
        action_binding[d] = apply_patch(v["action_binding_attachments"][d], c.get("action_binding_patch", {}).get(d, []), v)
    policy = apply_patch(v["trust_policy"], c.get("policy_patch", []), v)
    for name, doc in (("trust_policy", policy), ("attachment", attachment)):
        found = errors(validators[name], doc)
        if found:
            raise ValueError(f"the {name} must be schema-valid for this case: {found[0]}")
    for d, att in action_binding.items():
        if errors(validators["ab_attachment"], att):
            raise ValueError(f"the action-binding attachment of {d} must be schema-valid for this case")
    if export is not None and errors(validators["pv_export"], export):
        raise ValueError("the export must be schema-valid for this case")
    return {"attachment": attachment, "export": export, "action_binding": action_binding, "policy": policy}


def one_assertion_attachment(c, v, group):
    """An attachment holding the one assertion under test (a name in vectors.json, or from and patch), the
    assertions a timestamp may name (also), and the timestamps given."""
    kind = "person_signatures" if group == "person" else "organisation_seals"
    spec = c[group]
    if isinstance(spec, str):
        spec = f"/{kind}/{spec}/assertion"
    elif not spec["from"].startswith("/"):
        spec = dict(spec, **{"from": f"/{kind}/{spec['from']}/assertion"})
    a = resolve(spec, v)
    att = {"profile": PROFILE, "profile_version": VERSION, kind: [a]}
    for extra in c.get("also", []):
        name, kind = extra["name"], extra["kind"]
        att.setdefault(kind, []).append(copy.deepcopy(v[kind][name]["assertion"]))
    timestamps = [resolve(t, v) for t in c.get("timestamps", [])]
    if timestamps:
        att["timestamps"] = timestamps
    return att


class Raised(Exception):
    """The reference check raised an exception on input valid against the schemas: never an expected outcome."""


def reference(check, *args):
    try:
        return check(*args)
    except Exception as exc:
        raise Raised(f"the reference check raised {type(exc).__name__} on schema-valid input: {exc}") from exc


def person_case(c, v, validators):
    att = one_assertion_attachment(c, v, "person")
    ctx = context_for(c, v, validators, att)
    policy_result, persons, seals, ts = reference(run_context, ctx)
    r = persons[0]
    summary = {"policy": policy_result["status"]}
    summary.update({d: (r[d] if d == "status" else r[d]["status"]) for d in PERSON_DIMENSIONS})
    if r["key_state"]["status"] == "verified":
        summary["time_basis"] = r["key_state"]["time_basis"]
    for k in ("user_present", "user_verified", "cross_origin", "top_origin"):
        if k in c["expected"]:
            summary[k] = (r.get("authenticator") or {}).get(k)
    for k in ("covers_affirmation_record",):
        if k in c["expected"]:
            summary[k] = r["subject"].get(k)
    if "consistency" in c["expected"]:
        summary["consistency"] = r["identity"].get("consistency")
    detail = [f"{d}: {f}" for d in PERSON_DIMENSIONS[1:] for f in r[d].get("findings", [])] + r.get("findings", [])
    return summary, "; ".join(detail)


def expected_person(c):
    """Every dimension is expected verified, on the stated time, with the policy accepted, unless the case says."""
    full = {"policy": "verified", **{d: "verified" for d in PERSON_DIMENSIONS}, "time_basis": "stated_time"}
    full.update(c["expected"])
    if full["key_state"] != "verified":
        full.pop("time_basis", None)
    return full


def seal_case(c, v, validators):
    att = one_assertion_attachment(c, v, "seal")
    ctx = context_for(c, v, validators, att)
    policy_result, persons, seals, ts = reference(run_context, ctx)
    r = seals[0]
    summary = {"policy": policy_result["status"]}
    summary.update({d: (r[d] if d == "status" else r[d]["status"]) for d in SEAL_DIMENSIONS})
    if r["key_state"]["status"] == "verified":
        summary["time_basis"] = r["key_state"]["time_basis"]
    if "certificate" in c["expected"]:
        summary["certificate"] = r["signature"].get("certificate")
    if "embedded_copy" in c["expected"]:
        summary["embedded_copy"] = r["subject"].get("embedded_copy")
    detail = [f"{d}: {f}" for d in SEAL_DIMENSIONS[1:] for f in r[d].get("findings", [])] + r.get("findings", [])
    return summary, "; ".join(detail)


def expected_seal(c):
    full = {"policy": "verified", **{d: "verified" for d in SEAL_DIMENSIONS}, "time_basis": "stated_time"}
    full.update(c["expected"])
    if full["key_state"] != "verified":
        full.pop("time_basis", None)
    return full


def timestamp_case(c, v, validators):
    att = {"profile": PROFILE, "profile_version": VERSION, "timestamps": [resolve(c["timestamp"], v)]}
    for extra in c.get("held", []):  # each a name in vectors.json, with an optional patch
        held = apply_patch(v[extra["kind"]][extra["name"]]["assertion"], extra.get("patch", []), v)
        att.setdefault(extra["kind"], []).append(held)
    if "person_signatures" not in att and "organisation_seals" not in att:
        att["organisation_seals"] = [copy.deepcopy(v["organisation_seals"]["seal_export"]["assertion"])]
    ctx = context_for(c, v, validators, att)
    _, _, _, ts = reference(run_context, ctx)
    r = ts[0]
    summary = {"status": r["status"], **r["checks"], "signer_time": r["signer_time"]["status"]}
    for k in ("existed_no_later_than", "gen_time"):
        if k in c["expected"]:
            summary[k] = r.get(k)
    if "consistency" in c["expected"]:
        summary["consistency"] = r["signer_time"].get("consistency")
    detail = r["findings"] + r["signer_time"].get("findings", [])
    return summary, "; ".join(detail)


def expected_timestamp(c):
    full = {"status": "verified", **{k: "verified" for k in TS_CHECKS}, "signer_time": "verified"}
    full.update(c["expected"])
    return full


def pairing_case(c, v, validators):
    attachment = apply_patch(v["base_attachment"], c.get("attachment_patch", []), v)
    ctx = context_for(c, v, validators, attachment)
    digests = {"attachment": sha256(compact(attachment)).hex()}
    if ctx["export"] is not None:
        digests["export"] = sha256(compact(ctx["export"])).hex()
    for d, att in ctx["action_binding"].items():
        digests[f"action_binding:{d}"] = sha256(compact(att)).hex()
    report = apply_patch(v["base_report"], c["report_patch"], v, digests)
    if errors(validators["report"], report):
        return "error", "the report must be schema-valid for this case: " + errors(validators["report"], report)[0]
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
    defs = json.loads(SCHEMAS["attachment"].read_text(encoding="utf-8"))["$defs"]
    for name in ("person_signature", "organisation_seal", "timestamp"):
        validators[name] = Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": defs})
    for name, p in OTHER_SCHEMAS.items():
        validators[name] = Draft202012Validator(json.loads(p.read_text(encoding="utf-8")))
    print(f"[ok  ] the trust policy is anchoring's: {OTHER_SCHEMAS['trust_policy'].relative_to(ROOT).as_posix()}")

    same = lambda c: c["expected"]  # noqa: E731
    groups = [
        ("schema", cases["schema_cases"], lambda c: schema_case(c, v, validators), same),
        ("vector", cases["vector_cases"], lambda c: vector_case(c, v), same),
        ("person", cases["person_cases"], lambda c: person_case(c, v, validators), expected_person),
        ("seal", cases["seal_cases"], lambda c: seal_case(c, v, validators), expected_seal),
        ("timestamp", cases["timestamp_cases"], lambda c: timestamp_case(c, v, validators), expected_timestamp),
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
            print(f"[{'ok' if ok else 'FAIL':4}] {c['id']:4} {label:17} {c['description']}")
            if not ok:
                failed.append(c["id"])
                shown = "; ".join(detail[:2]) if isinstance(detail, list) else detail
                if isinstance(got, dict) and isinstance(want, dict):
                    got = {k: x for k, x in got.items() if want.get(k) != x}
                print(f"         expected {c['expected']}, got {got}" + (f": {shown[:300]}" if shown else ""))
            if c.get("limitation"):
                limits.append((c["id"], c["limitation"]))

    print("\nLimitations these cases show (they pass by design):")
    for cid, text_ in limits:
        print(f"  {cid}: {text_}")
    if failed:
        print(f"\nFAIL: {len(failed)} of {total} case(s) do not behave as expected: {', '.join(failed)}")
        return 1
    print(f"\nPASS: all {total} cases behave as expected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
