# SPDX-License-Identifier: Apache-2.0
"""Writes vectors.json for the signatures extension, version 0.1.0 (a proposal).

TEST KEYS ONLY. Every key below is derived from a published text, so anyone can recompute it. Never derive a real
key this way, and never trust anything signed by one of these keys.

  seed                      SHA-256 of the UTF-8 text "dps-signatures 0.1.0 test key " followed by the key's name
  Ed25519 (person, seal)    the seed is the private key (RFC 8032, section 5.1.5)
  ECDSA P-256 (passkey)     the private scalar is (the seed read as a big-endian integer) mod (n - 1), plus 1

Anchoring 0.2.0's test keys are reused, so that one trust policy holds a key of every role and the two sets of
vectors agree: witness-a-1 and the ECDSA time-stamping authorities tsa-example-1 and tsa-example-2, under anchoring's
seed text ("dps-anchoring 0.1.0 test key " and the name, unchanged in 0.2.0), and the RSA time-stamping authority
(tsa-rsa-1), whose key is the 2048-bit RSA test key that RFC 9500, section 2.1, publishes under the name
"testRSA2048", written here as its parameters in hex, exactly as the RFC prints them and as anchoring's generator
holds them. The authorities' certificates are read from the anchoring vectors, and this script checks that each
holds the key it derives or reconstructs. Never use a published key for anything real.

Signatures are deterministic: Ed25519 by definition, ECDSA with the deterministic nonces of RFC 6979, and RSA
PKCS#1 v1.5 by construction, through the cryptography package (OpenSSL 3.2 or later). The WebAuthn vectors are
therefore verification-only in the text but reproducible here. The RFC 3161 tokens are built with asn1crypto.
Re-running this script writes the same bytes, and run_checks.py checks that it does.

Records R0 to R2 and R4, the export and the links are those of the anchoring vectors (R0 to R2 from portable
verification). Specification S0 is the one of action binding's cases. The action-binding attachments are built
here in the shape of action binding 0.2.0.

Usage:  python extensions/signatures/tests/generate_vectors.py            write vectors.json
        python extensions/signatures/tests/generate_vectors.py --check    exit 1 if vectors.json differs
"""
import base64
import copy
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

from asn1crypto import algos, cms, core, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / "vectors.json"
ANCHORING_VECTORS = ROOT / "extensions" / "anchoring" / "tests" / "vectors.json"

PROFILE, VERSION = "dps-signatures", "0.1.0"
ANCHORING_VERSION = "0.2.0"  # the anchoring version this profile is written against; the trust policy is its
SEED_PREFIX = "dps-signatures 0.1.0 test key "
ANCHORING_SEED_PREFIX = "dps-anchoring 0.1.0 test key "
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TSA_POLICY_OID = "2.999.1"  # an OID under the arc reserved for examples
MAGIC = b"DPS-SIG\x00"
UTC = timezone.utc
RP_ID, ORIGIN = "example.org", "https://example.org"
ED25519_SIGNATURE_B64_LENGTH = 88  # 64 bytes in padded base64

RECORDS = {
    "R0": '{"decision_id":"DR-2099-001","charter_id":"CH-EXAMPLE-1","record_type":"decision","record_state":"drafted",'
          '"dispatch_mode":"mode-1","created_at":"2026-09-25T10:00:00Z","altitude":"executive","decision_statement":'
          '"Adopt option B for the example vendor review.","affirmation_record":{"timestamp":"2026-09-25T11:00:00Z",'
          '"actor_identity":"owner-example-1","method":"approval token"},"seal_algorithm":"SHA-256"}',
    "R1": '{"decision_id":"DR-2099-002","charter_id":"CH-EXAMPLE-1","record_state":"drafted","dispatch_mode":"mode-1",'
          '"created_at":"2026-09-26T09:00:00Z","altitude":"executive","decision_statement":"Adopt option C instead of '
          'option B.","supersedes":"DR-2099-001","affirmation_record":{"timestamp":"2026-09-26T10:00:00Z",'
          '"actor_identity":"owner-example-1","method":"approval token"},"seal_algorithm":"SHA-256"}',
    "R2": '{"decision_id":"DR-2099-003","charter_id":"CH-EXAMPLE-1","record_type":"decision","record_state":"drafted",'
          '"dispatch_mode":"mode-1","created_at":"2026-09-27T09:00:00Z","altitude":"executive","decision_statement":'
          '"Review the example vendor again in six months.","affirmation_record":{"timestamp":"2026-09-27T10:00:00Z",'
          '"actor_identity":"owner-example-1","method":"approval token"},"seal_algorithm":"SHA-256","seal_hash":'
          '"0000000000000000000000000000000000000000000000000000000000000000"}',
    "R4": '{"decision_id":"DR-2099-004","charter_id":"CH-EXAMPLE-1","record_type":"decision","record_state":"drafted",'
          '"dispatch_mode":"mode-1","created_at":"2026-09-28T09:00:00Z","altitude":"executive","decision_statement":'
          '"Close the example vendor review.","affirmation_record":{"timestamp":"2026-09-28T10:00:00Z",'
          '"actor_identity":"owner-example-1","method":"approval token"},"seal_algorithm":"SHA-256"}',
}
RECORD_ORDER = ("R0", "R1", "R2", "R4")
PORTABLE_VERIFICATION_SEALS = {  # as published in extensions/portable-verification/tests/cases.json
    "R0": "4671e381366fcdad7f6e2951619fa16622d826a4bbe0dd8b505692bd17cf5327",
    "R1": "b6a1a358237efc55ed8a4495166d471f65feb1697ddfa7fa3cb91dcf61b414a9",
    "R2": "b338d5e167236a058d3222ea8634b394765a71b5a04d5ab65bf4751f4696a125",
}
SPECIFICATION = ('{"operation":"payment.release","target":"urn:example:vendor:7","parameters":{"amount":"1200.00",'
                 '"currency":"EUR","destination":"urn:example:account:vendor-7-main"},"input_version_refs":'
                 '["urn:example:invoice:114#v2"],"policy_version":"urn:example:payment-policy:4"}')
ACTION_BINDING_SPEC_DIGEST = "e8c60bd5473dee8ab80760bdb81306dbf99332fa97c05f744bbaafe81ec787e9"  # S0 in its cases
VIEW = ('{"shown_to":"owner-example-1","text":"Release 1200.00 EUR to vendor 7 (account vendor-7-main), invoice 114 '
        'version 2, under payment policy 4.","spec_digest":"' + ACTION_BINDING_SPEC_DIGEST + '"}')
DECISION_A, DECISION_B = "DR-2099-101", "DR-2099-102"
EXPORT_ID = "urn:example:export:issuer-1:2026-09-27"


def sha256(data):
    return hashlib.sha256(data).digest()


def b64(data):
    return base64.b64encode(data).decode("ascii")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def compact(doc):
    """A document's bytes as received, by the convention of these vectors: JSON, UTF-8, no whitespace."""
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def when(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def flip_last_byte(data):
    return data[:-1] + bytes([data[-1] ^ 0x01])


def replace_once(data, old, new):
    if data.count(old) != 1 or len(old) != len(new):
        raise ValueError("a replacement must match once and keep the length")
    return data.replace(old, new)


# ---------------------------------------------------------------- test keys (TEST KEYS ONLY)

def seed(text):
    return sha256(text.encode("utf-8"))


def ed25519_key(text):
    return Ed25519PrivateKey.from_private_bytes(seed(text))


def p256_key(text):
    return ec.derive_private_key(int.from_bytes(seed(text), "big") % (P256_N - 1) + 1, ec.SECP256R1())


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def point_public(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


# RFC 9500, section 2.1, RSA-2048 key "testRSA2048": a PUBLISHED TEST KEY, never a real key. The parameters are those
# the RFC prints, in its order and under its names (u is the CRT coefficient q^-1 mod p, PKCS#1's qInv; exponent1 and
# exponent2 are d mod (p - 1) and d mod (q - 1), PKCS#1's dP and dQ), as anchoring 0.2.0's generator holds them.
# rsa_key() reconstructs the private key from them; build() checks that its public key is the one the anchoring
# vectors give for this authority, and that anchoring's certificate holds it.
RFC9500_TESTRSA2048 = {
    "n": (
        "b0f9e81943a7ae9892aade17ca7c40f8744fed2f8148e6c8eaa27b7d001548fb5192ab28b56c5060b118ccd131e59487"
        "4c6ca989b56c27296f09fb93a034df32e97c6ff0998cfd8e6f42dda58acd1fa97986f144f3d154d67650175e6854b3a9"
        "52003bc06887b8455ac2b19f7b2f76504ebc98ec945571b07892150ddc6a74ca0fbcd35497ce81534daf9418844b13ae"
        "a31f9d5a6b9557bbdf619efd4e887f2d42b8dd8bc987eae1bf89cab85ee21e356305df6c07a8838e3ef41c595dcce43d"
        "afc49123ef4d8abba93d3905e4028d7ba91484a27596e07b4b6ed992f077b524d3dcfe7ddd5549be7cce8da035cfa0b3"
        "fb8f9e46f732b2a86b460165c08f5313"
    ),
    "e": (
        "010001"
    ),
    "d": (
        "41188b20cfdbdbc2cf1ffe752dcbaa723906352e2615d49dce80597fcf0a05403bef00fa065182f72decfb596f4b0ce8"
        "ff5970baf07a89a519ecc816b2f4ffac5069af1b06bfef7bf6bcd79e4e81c8c5a3a7d9130dc3cfbadae5f6d288f9aee3"
        "f6ff92fae0f81af597bec96ae9fab9402cd5fe41f705bebdb47bb736d3fe6c5a51e0e20732a97b5e46c1cbdb26d74854"
        "c6b6604aed463735ff9076046557caf949bf448895c20432c1e09c014ea75660434f1a0f3be294babc5d530e6a10213f"
        "53b60375fc84a7573f2af1215584f5b4bda6d4e8f9e17a78d97e77b86da4a1846475318a7a10a561014effa23a81ec56"
        "e9e4109def8cb3f797223f7d8d0d4351"
    ),
    "p": (
        "dd105702382f232b3681f53791e22617c7bf4e9acb81ed48daf6d6995da3eab642839aff012d2ea628b90af279fd3e6f"
        "7c93cd80f072f01ff2443b3ee8f24ed469a79613a41bd24020f92fd11059bd1d0f301b5ba7a9d3637ca8d65c1a981541"
        "7d8eab734b0b4f3a2c661d9a1a82f3ac734c40530669ab8e473045a58e65539d"
    ),
    "q": (
        "ccf1e5bb90c8e9781ea75bebf10bc252e11eb023a0260f1887552a56863f4a6421e8c600bf523d6cb1b0adbdd65bfee4"
        "a88a037e3d1a415e5bb95648da5a0ca26b54f4a63948522c3d5f89b94a72efff95134d5940ce45758f30898090895658"
        "8eef575b3e4bc4c368cfe813ee9c252c2b02e0df91f1aa01938d38685d60ba6f"
    ),
    "exponent1": (
        "09ed54eaed98f84c557b4a86bf4f578493dcbc6be91da189370404a9087276f4ce51d8a100ed857dc2b0649474f3f15c"
        "d24c54db287110e56e5cb008682f9168aa81f31458b7431ecc1c44906fda87ca894710c371e9076c1d49fbae51276934"
        "f2ad787789f42d0fa0b4c939855d4212096f70280a4eae7c8a27d9c8d0772e65"
    ),
    "exponent2": (
        "8cb6857a7bd5465f80047e9b87bc002731840581e0626139012a5b505f0a33847eb7b8c3289949ad486f3b4b3d539ab5"
        "da763021cbc82c1ba234a5668ded0801b859f343f1ce9304e6faa2b002cad9b78cde5cdc2c1fb4171c42421670a6ab0f"
        "50cc4a194eb36d1c91e935ba01b959d8728b9e64426b3fc3a7506deb5239a8a7"
    ),
    "u": (
        "0a81d8a618314a803af61c06711f2c39b266ff414d53476d1da52a4318aafe4b96f0da07155f8a5134dab88ee29e8168"
        "076fcd78ca791ac63442a81cd0693927d808e335e8d8cbf2121907509a57759b4f9a18fa3a7b333779edde7a459384f8"
        "444adaecffec95fd552b0cfcb6c7f692626dde1ef268a40d2f67b5c8aa387ff7"
    ),
}
RFC9500_TESTRSA2048_NAME = "testRSA2048"
RSA_TSA_REF = "tsa-rsa-1"  # the reference anchoring's policy gives the RSA authority


def rsa_key():
    """The RFC 9500 test key, reconstructed from its published parameters."""
    k = {name: int(value, 16) for name, value in RFC9500_TESTRSA2048.items()}
    public = rsa.RSAPublicNumbers(e=k["e"], n=k["n"])
    key = rsa.RSAPrivateNumbers(p=k["p"], q=k["q"], d=k["d"], dmp1=k["exponent1"], dmq1=k["exponent2"], iqmp=k["u"],
                                public_numbers=public).private_key()
    if key.key_size != 2048 or key.public_key().public_numbers() != public:
        raise ValueError("the RSA test key does not reconstruct to the published public key")
    return key


def sign_der(key, data):
    """A deterministic signature over data: ECDSA P-256 with RFC 6979 nonces, or RSA PKCS#1 v1.5, with SHA-256."""
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))


ED25519_NAMES = ("person-a-1", "person-a-2", "person-b-0", "person-b-1", "person-e-1", "person-x-1", "personne-é-1",
                 "org-seal-0", "org-seal-1", "org-seal-x")
P256_NAMES = ("person-a-passkey-1",)
ANCHORING_ED25519 = ("witness-a-1",)
ANCHORING_P256 = ("tsa-example-1", "tsa-example-2")


# ---------------------------------------------------------------- signed bytes (the shared rule)

def lp(data):
    return len(data).to_bytes(4, "big") + data


def signed_bytes(fields):
    return MAGIC + b"".join(lp(f) for f in fields)


def text(value):
    return value.encode("utf-8")


def digest(value):
    """A digest field: 32 raw bytes, or the empty byte string for a digest the source does not state."""
    return b"" if value is None else bytes.fromhex(value)


def header(obj, profile, version, assertion, key_ref):
    return [text(profile), text(version), text(assertion or obj["assertion"]),
            text(key_ref or obj["signature"]["key_ref"])]


def person_fields(ps, profile=PROFILE, version=VERSION, assertion=None, key_ref=None):
    """The fixed field orders of the person's assertions (see the README):
    person_approval     5 decision_id, 6 stage_id, 7 outcome, 8 shown_spec_digest, 9 shown_view_digest (or empty),
                        10 approved_spec_digest, 11 signed_at
    person_review       5 decision_id, 6 stage_id, 7 outcome, 8 shown_spec_digest, 9 shown_view_digest (or empty),
                        10 signed_at
    person_affirmation  5 decision_id, 6 affirmed_digest, 7 signed_at"""
    kind = assertion or ps["assertion"]
    fields = header(ps, profile, version, assertion, key_ref) + [text(ps["decision_id"])]
    if kind == "person_affirmation":
        fields.append(digest(ps["affirmed_digest"]))
    else:
        fields += [text(ps["stage_id"]), text(ps["outcome"]), digest(ps["shown_spec_digest"]),
                   digest(ps.get("shown_view_digest"))]
        if kind == "person_approval":
            fields.append(digest(ps["approved_spec_digest"]))
    fields.append(text(ps["signed_at"]))
    return fields


def seal_fields(seal, profile=PROFILE, version=VERSION, assertion=None, key_ref=None):
    """organisation_seal: 5 sealed.kind, 6 sealed.id, 7 sealed.digest, 8 sealed_at."""
    s = seal["sealed"]
    return header(seal, profile, version, assertion, key_ref) + [text(s["kind"]), text(s["id"]), digest(s["digest"]),
                                                                 text(seal["sealed_at"])]


# ---------------------------------------------------------------- records, export, action-binding attachments

def link(previous, digest_hex):
    return sha256((previous or bytes(32)) + bytes.fromhex(digest_hex))


def export_entry(name, seal, sequence, previous_link):
    entry = {
        "decision_id": json.loads(RECORDS[name])["decision_id"],
        "record_type": "decision",
        "covered_representation": {"kind": "original_bytes", "media_type": "application/json"},
        "content": {"availability": "available", "covered_bytes_b64": b64(RECORDS[name].encode("utf-8"))},
        "seal": {
            "seal_hash": seal[name],
            "seal_algorithm": "SHA-256",
            "seal_field_handling": "seal_hash_zeroed" if name == "R2" else "seal_hash_absent",
            "affirmation_record_covered": True,
        },
    }
    if name == "R1":
        entry["predecessors"] = {"supersedes": "DR-2099-001"}
    entry["chain"] = {"sequence": sequence, "previous_link": previous_link}
    return entry


def build_exports(seal):
    """Portable verification 0.1.0 exports: full (R0, R1, R2, as anchoring's) and extended (R4 added)."""
    links, head = [], None
    for k in RECORD_ORDER:
        head = link(head, seal[k])
        links.append(head.hex())
    chained = {"R0": (0, None), "R1": (1, links[0]), "R2": (2, links[1]), "R4": (3, links[2])}

    def export(names):
        return {"profile": "dps-portable-verification", "profile_version": "0.1.0",
                "entries": [export_entry(n, seal, *chained[n]) for n in names]}

    return {"full": export(["R0", "R1", "R2"]), "extended": export(["R0", "R1", "R2", "R4"])}, links


def specification(spec_text):
    return {"spec_digest": sha256(spec_text.encode("utf-8")).hex(),
            "representation": {"kind": "original_bytes", "media_type": "application/json"},
            "content": {"availability": "available", "bytes_b64": b64(spec_text.encode("utf-8"))},
            "summary": {"operation": "payment.release", "target": "urn:example:vendor:7",
                        "policy_version": "urn:example:payment-policy:4",
                        "input_version_refs": ["urn:example:invoice:114#v2"]}}


def approved_attachment(spec_digest, view_digest):
    """Action binding 0.2.0: an AI proposal, a review that was shown the specification and a view, an approval."""
    return {
        "profile": "dps-action-binding", "profile_version": "0.2.0", "decision_id": DECISION_A,
        "action_specifications": [specification(SPECIFICATION)],
        "stages": [
            {"stage_id": "p1", "kind": "proposal", "at": "2026-10-01T09:00:00Z", "origin": "ai",
             "spec_digest": spec_digest, "deployer_role_pointer": "urn:example:role:payables-drafting",
             "system_name": "example-model", "version": "1"},
            {"stage_id": "v1", "kind": "review", "at": "2026-10-01T09:10:00Z", "reviewer_ref": "owner-example-1",
             "shown_spec_digest": spec_digest, "proposal_ref": "p1",
             "shown_view_ref": "urn:example:review-view:101-1", "shown_view_digest": view_digest},
            {"stage_id": "o1", "kind": "outcome", "at": "2026-10-01T09:12:00Z", "review_ref": "v1",
             "outcome": "approved", "actor_ref": "owner-example-1", "method": "signature",
             "approved_spec_digest": spec_digest,
             "authority": {"authority_ref": "urn:example:charter:CH-EXAMPLE-1#payables-delegation"},
             "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": "2026-10-01T09:12:00Z",
                           "text_ref": "urn:example:rationale:101-1"},
             "core_ref": {"field": "affirmation_record"}},
        ],
    }


def rejected_attachment(spec_digest):
    """Action binding 0.2.0: the same specification proposed again for another record, shown with no view digest,
    and rejected."""
    return {
        "profile": "dps-action-binding", "profile_version": "0.2.0", "decision_id": DECISION_B,
        "action_specifications": [specification(SPECIFICATION)],
        "stages": [
            {"stage_id": "p1", "kind": "proposal", "at": "2026-10-02T09:00:00Z", "origin": "ai",
             "spec_digest": spec_digest, "deployer_role_pointer": "urn:example:role:payables-drafting",
             "system_name": "example-model", "version": "1"},
            {"stage_id": "v1", "kind": "review", "at": "2026-10-02T09:20:00Z", "reviewer_ref": "reviewer-example-2",
             "shown_spec_digest": spec_digest, "proposal_ref": "p1", "shown_view_ref": "urn:example:review-view:102-1"},
            {"stage_id": "o1", "kind": "outcome", "at": "2026-10-02T09:21:00Z", "review_ref": "v1",
             "outcome": "rejected", "actor_ref": "reviewer-example-2", "method": "signature",
             "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": "2026-10-02T09:21:00Z",
                           "text_ref": "urn:example:rationale:102-1"},
             "core_ref": {"field": "review_log", "index": 0}},
        ],
    }


# ---------------------------------------------------------------- an organisation's certificate (TEST ONLY)

def seal_certificate(key, serial):
    """A self-signed Ed25519 certificate for an organisation's seal key (TEST ONLY). Whether such a certificate is a
    qualified one is outside the extension; the verifier pins it because it chose to."""
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example issuer (test only)"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example issuer seal (test only)"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 12, 31, 23, 59, 59, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, None)
    )
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------- time-stamp tokens (anchoring's shape)

def make_token(key, cert_der, imprint_of, gen_time, serial, *, accuracy_seconds=None, cert_id_of=None,
               with_cert_id=True, signature_algorithm=None, sid_cert_der=None, cert_id_hash="sha256",
               cert_id_values=1, gen_time_text=None, accuracy_millis=None):
    """An RFC 3161 TimeStampToken over the SHA-256 of imprint_of: CMS SignedData over a TSTInfo, signed with ECDSA
    P-256 (RFC 6979) or RSA PKCS#1 v1.5, with SHA-256, as anchoring 0.2.0's generator builds them. signature_algorithm
    labels the signature; without it, the label fits the key. gen_time_text, when given, is written as the genTime's
    exact characters (to make one that is not in UTC)."""
    if signature_algorithm is None:
        signature_algorithm = "sha256_rsa" if isinstance(key, rsa.RSAPrivateKey) else "sha256_ecdsa"
    cert = asn1_x509.Certificate.load(cert_der)
    sid_cert = asn1_x509.Certificate.load(sid_cert_der or cert_der)
    info = {
        "version": "v1",
        "policy": TSA_POLICY_OID,
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": sha256(imprint_of)},
        "serial_number": serial,
        "gen_time": gen_time if gen_time_text is None else core.GeneralizedTime.load(
            b"\x18" + bytes([len(gen_time_text)]) + gen_time_text.encode("ascii")),
    }
    if accuracy_seconds is not None or accuracy_millis is not None:
        info["accuracy"] = {k: x for k, x in (("seconds", accuracy_seconds), ("millis", accuracy_millis))
                            if x is not None}
    econtent = tsp.TSTInfo(info).dump()
    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [sha256(econtent)]}),
    ]
    if with_cert_id:
        cert_id = {"cert_hash": hashlib.new(cert_id_hash, cert_id_of or cert_der).digest()}
        if cert_id_hash != "sha256":  # SHA-256 is the default, which DER leaves out
            cert_id = {"hash_algorithm": {"algorithm": cert_id_hash}, **cert_id}
        attrs.append(cms.CMSAttribute({"type": "signing_certificate_v2",
                                       "values": [{"certs": [cert_id]}] * cert_id_values}))
    signed_attrs = cms.CMSAttributes(sorted(attrs, key=lambda a: a.dump()))  # DER: a SET OF is sorted
    signature = sign_der(key, signed_attrs.dump())
    signer = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": sid_cert.issuer, "serial_number": sid_cert.serial_number})}),
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attrs,
        "signature_algorithm": {"algorithm": signature_algorithm},
        "signature": signature,
    })
    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": {"content_type": "tst_info", "content": core.ParsableOctetString(econtent)},
        "certificates": [cert],
        "signer_infos": [signer],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump(), signature


# ---------------------------------------------------------------- the assertions

def present(obj, presented):
    """Change what the object says after signing: a member of the signature, or of the object (None removes it)."""
    for k, v in (presented or {}).items():
        target = obj["signature"] if k in ("key_ref", "algorithm") else obj
        if v is None:
            target.pop(k, None)
        else:
            target[k] = v
    return obj


def make_person(keys, key_name, body, presented=None, signed_as=None):
    """A person's assertion signed with Ed25519. presented changes what the object says after signing; signed_as
    changes what the key signed (another profile, version, assertion type or key reference)."""
    ps = {"profile": PROFILE, "profile_version": VERSION, **body, "signature": {"algorithm": "Ed25519", "key_ref": key_name}}
    made_over = signed_bytes(person_fields(ps, **(signed_as or {})))
    ps["signature"]["value_b64"] = b64(keys[key_name].sign(made_over))
    present(ps, presented)
    out = {"signed_with": key_name, "assertion": ps, "signed_bytes_hex": signed_bytes(person_fields(ps)).hex()}
    if made_over.hex() != out["signed_bytes_hex"]:
        out["signature_made_over_hex"] = made_over.hex()
    return out


def make_passkey(keys, key_name, body, *, rp_id=RP_ID, origin=ORIGIN, flags=0x05, type_="webauthn.get",
                 challenge_over=None, sign_count=7, presented=None, cross_origin=False, top_origin=None):
    """A person's assertion signed with a WebAuthn passkey (ES256). The authenticator signs
    authenticatorData || SHA-256(clientDataJSON); the challenge in clientDataJSON is SHA-256 of the signed bytes,
    in base64url without padding, as a browser writes it."""
    ps = {"profile": PROFILE, "profile_version": VERSION, **body,
          "signature": {"algorithm": "WebAuthn-ES256", "key_ref": key_name}}
    made_over = signed_bytes(person_fields(ps))
    challenge = sha256(challenge_over if challenge_over is not None else made_over)
    client = {"type": type_, "challenge": b64url(challenge), "origin": origin, "crossOrigin": cross_origin}
    if top_origin:
        client["topOrigin"] = top_origin
    client_data = json.dumps(client, separators=(",", ":")).encode("utf-8")
    authenticator_data = sha256(rp_id.encode("utf-8")) + bytes([flags]) + sign_count.to_bytes(4, "big")
    signature = keys[key_name].sign(authenticator_data + sha256(client_data),
                                    ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    ps["signature"].update(value_b64=b64(signature), authenticator_data_b64=b64(authenticator_data),
                           client_data_json_b64=b64(client_data))
    present(ps, presented)
    return {"signed_with": key_name, "assertion": ps, "signed_bytes_hex": made_over.hex(),
            "webauthn": {"challenge_b64url": b64url(challenge), "rp_id": rp_id, "origin": origin, "type": type_,
                         "cross_origin": cross_origin, **({"top_origin": top_origin} if top_origin else {}),
                         "flags_hex": f"{flags:02x}", "authenticator_signed_hex":
                         (authenticator_data + sha256(client_data)).hex()}}


def make_seal(keys, key_name, sealed, sealed_at, presented=None, signed_as=None):
    seal = {"profile": PROFILE, "profile_version": VERSION, "assertion": "organisation_seal", "sealed": sealed,
            "sealed_at": sealed_at, "signature": {"algorithm": "Ed25519", "key_ref": key_name}}
    made_over = signed_bytes(seal_fields(seal, **(signed_as or {})))
    seal["signature"]["value_b64"] = b64(keys[key_name].sign(made_over))
    present(seal, presented)
    out = {"signed_with": key_name, "assertion": seal, "signed_bytes_hex": signed_bytes(seal_fields(seal)).hex()}
    if made_over.hex() != out["signed_bytes_hex"]:
        out["signature_made_over_hex"] = made_over.hex()
    return out


def embedded_signature(key_ref, value_b64):
    """Action binding 0.2.0's issuer_signature member, holding a copy of the organisation's seal."""
    return {"algorithm": "Ed25519", "key_ref": key_ref, "signed_bytes_ref": "dps-signatures 0.1.0 organisation_seal",
            "value_b64": value_b64}


# ---------------------------------------------------------------- the whole file

def build():
    anchoring = json.loads(ANCHORING_VECTORS.read_text(encoding="utf-8"))
    seal = {k: sha256(RECORDS[k].encode("utf-8")).hex() for k in RECORD_ORDER}
    for k, v in PORTABLE_VERIFICATION_SEALS.items():
        if seal[k] != v:
            raise ValueError(f"{k}: the record no longer matches the portable verification fixture")
    exports, links = build_exports(seal)
    if exports["full"] != anchoring["exports"]["full"] or exports["extended"] != anchoring["exports"]["extended"]:
        raise ValueError("the exports no longer match the anchoring fixtures")
    spec_digest = sha256(SPECIFICATION.encode("utf-8")).hex()
    if spec_digest != ACTION_BINDING_SPEC_DIGEST:
        raise ValueError("the specification no longer matches action binding's S0")
    view_digest = sha256(VIEW.encode("utf-8")).hex()

    ed = {n: ed25519_key(SEED_PREFIX + n) for n in ED25519_NAMES}
    ed.update({n: ed25519_key(ANCHORING_SEED_PREFIX + n) for n in ANCHORING_ED25519})
    ecc = {n: p256_key(SEED_PREFIX + n) for n in P256_NAMES}
    ecc.update({n: p256_key(ANCHORING_SEED_PREFIX + n) for n in ANCHORING_P256})
    test_keys = {}
    for n in ED25519_NAMES + ANCHORING_ED25519:
        prefix = ANCHORING_SEED_PREFIX if n in ANCHORING_ED25519 else SEED_PREFIX
        test_keys[n] = {"algorithm": "Ed25519", "seed_text": prefix + n, "public_key_hex": raw_public(ed[n]).hex()}
    for n in P256_NAMES + ANCHORING_P256:
        prefix = ANCHORING_SEED_PREFIX if n in ANCHORING_P256 else SEED_PREFIX
        algorithm = "WebAuthn-ES256" if n in P256_NAMES else "ECDSA P-256"
        test_keys[n] = {"algorithm": algorithm, "seed_text": prefix + n, "public_key_hex": point_public(ecc[n]).hex()}
    for n in ANCHORING_ED25519 + ANCHORING_P256:
        if test_keys[n]["public_key_hex"] != anchoring["test_keys"][n]["public_key_hex"]:
            raise ValueError(f"{n}: the key no longer matches the anchoring vectors")
    # The RSA authority: RFC 9500's published test key, as anchoring's vectors give it (modulus and exponent).
    rsa_tsa = rsa_key()
    rsa_name = RFC9500_TESTRSA2048_NAME
    test_keys[rsa_name] = {"algorithm": "RSA-2048", "published_in": "RFC 9500, section 2.1", "name": rsa_name,
                           "modulus_hex": RFC9500_TESTRSA2048["n"], "public_exponent_hex": RFC9500_TESTRSA2048["e"]}
    if test_keys[rsa_name] != anchoring["test_keys"][rsa_name]:
        raise ValueError(f"{rsa_name}: the RSA key no longer matches the anchoring vectors")

    certs = {"org-seal-1": seal_certificate(ed["org-seal-1"], 0x0B01)}
    tsa_certs = {n: base64.b64decode(anchoring["tsa_certificates"][n]["certificate_b64"])
                 for n in ANCHORING_P256 + (rsa_name,)}
    for n, der in tsa_certs.items():
        public = x509.load_der_x509_certificate(der).public_key()
        if n == rsa_name:
            held = public.public_numbers() == rsa_tsa.public_key().public_numbers()
        else:
            held = public.public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.UncompressedPoint) == point_public(ecc[n])
        if not held:
            raise ValueError(f"{n}: the anchoring certificate does not hold the key derived from its seed text")
    certificates = {n: {"certificate_b64": b64(d), "sha256": sha256(d).hex()} for n, d in {**certs, **tsa_certs}.items()}

    # ---- the person's assertions
    persons = {}

    def person(name, about, key, body, **kw):
        persons[name] = {"about": about, **make_person(ed, key, body, **kw)}

    def passkey(name, about, key, body, **kw):
        persons[name] = {"about": about, **make_passkey(ecc, key, body, **kw)}

    approval = {"assertion": "person_approval", "decision_id": DECISION_A, "stage_id": "o1", "outcome": "approved",
                "shown_spec_digest": spec_digest, "shown_view_digest": view_digest, "approved_spec_digest": spec_digest,
                "signed_at": "2026-10-01T09:12:00Z"}
    rejection = {"assertion": "person_review", "decision_id": DECISION_B, "stage_id": "o1", "outcome": "rejected",
                 "shown_spec_digest": spec_digest, "signed_at": "2026-10-02T09:21:00Z"}
    affirmation_r0 = {"assertion": "person_affirmation", "decision_id": "DR-2099-001", "affirmed_digest": seal["R0"],
                      "signed_at": "2026-09-25T11:00:00Z"}

    person("approval_a", "person-a-1 approves outcome o1 of DR-2099-101, shown the specification and a view",
           "person-a-1", approval)
    person("approval_a_moved_to_b0", "approval_a's signature presented under key reference person-b-0", "person-a-1",
           approval, presented={"key_ref": "person-b-0"})
    person("approval_a_other_profile", "the key signed the same fields under profile dps-anchoring", "person-a-1",
           approval, signed_as={"profile": "dps-anchoring"})
    person("approval_a_other_version", "the key signed the same fields under profile_version 0.2.0", "person-a-1",
           approval, signed_as={"version": "0.2.0"})
    person("approval_a_other_type", "the key signed the same fields under assertion type organisation_seal",
           "person-a-1", approval, signed_as={"assertion": "organisation_seal"})
    person("approval_a_view_dropped", "signed with no view digest (the empty field), presented with the review's view "
           "digest", "person-a-1", dict(approval, shown_view_digest=None),
           presented={"shown_view_digest": view_digest})
    person("approval_a_time_changed", "signed at 09:12:00Z, presented a minute later", "person-a-1", approval,
           presented={"signed_at": "2026-10-01T09:13:00Z"})
    person("approval_a_before_validity", "person-a-1, stated as signed before the key's not_before", "person-a-1",
           dict(approval, signed_at="2026-08-15T09:12:00Z"))
    person("approval_a_wrong_stage", "names the review stage v1, not the outcome", "person-a-1",
           dict(approval, stage_id="v1"))
    person("approval_a_other_decision", "names DR-2099-102, whose outcome o1 is a rejection", "person-a-1",
           dict(approval, decision_id=DECISION_B))
    person("approval_a_other_algorithm", "approval_a with an algorithm label the reference check does not support",
           "person-a-1", approval, presented={"algorithm": "ECDSA-P256-SHA256"})
    person("approval_a_feb30", "signed_at 2026-02-30: the schema admits the form, but it is not a real UTC time",
           "person-a-1", dict(approval, signed_at="2026-02-30T09:12:00Z"))
    person("approval_a_leap_second", "signed_at 23:59:60: a leap second, which a signed time never carries",
           "person-a-1", dict(approval, signed_at="2026-06-30T23:59:60Z"))
    person("approval_a2", "person-a-2, a key of the same person later revoked as compromised, approves o1",
           "person-a-2", approval)
    person("approval_e", "person-e-1, stated as signed after the key's not_after", "person-e-1", approval)
    person("approval_by_org", "org-seal-1, a key in role organisation, signs a person's approval", "org-seal-1",
           approval)
    person("approval_by_witness", "witness-a-1, a key in role witness, signs a person's approval", "witness-a-1",
           approval)
    person("approval_x", "person-x-1, a key the policy does not list", "person-x-1", approval)
    bad = copy.deepcopy(persons["approval_a"])
    bad["about"] = "approval_a with the last byte of its signature changed"
    bad["assertion"]["signature"]["value_b64"] = b64(flip_last_byte(base64.b64decode(
        bad["assertion"]["signature"]["value_b64"])))
    persons["approval_a_bad_signature"] = bad

    person("review_b0", "person-b-0 rejects outcome o1 of DR-2099-102, shown no view digest; the key was superseded "
           "later", "person-b-0", rejection)
    person("review_b0_as_approval", "review_b0's signature presented in a person_approval object: a signed rejection "
           "presented as an approval", "person-b-0", rejection,
           presented={"assertion": "person_approval", "outcome": "approved", "approved_spec_digest": spec_digest})
    person("review_b0_escalated", "signed as rejected, presented as escalated", "person-b-0", rejection,
           presented={"outcome": "escalated"})
    person("review_b0_view_added", "signed with a view digest that the review does not state", "person-b-0",
           dict(rejection, shown_view_digest=view_digest))
    person("review_b0_late", "person-b-0, stated as signed after the key was superseded", "person-b-0",
           dict(rejection, signed_at="2026-10-04T10:00:00Z"))
    person("review_b0_at_revocation", "person-b-0, stated as signed at exactly the time it was superseded",
           "person-b-0", dict(rejection, signed_at="2026-10-03T00:00:00Z"))
    person("review_b1_escalated", "person-b-1, the successor key, signs o1 of DR-2099-102 as escalated", "person-b-1",
           dict(rejection, outcome="escalated", signed_at="2026-10-04T10:00:00Z"))

    person("affirmation_r0", "person-a-1 affirms DR-2099-001: the digest of its covered bytes, which is its seal",
           "person-a-1", affirmation_r0)
    person("affirmation_r0_e", "personne-é-1, a key reference with a non-ASCII character (12 characters, 13 bytes), "
           "affirms DR-2099-001", "personne-é-1", affirmation_r0)
    r0_without_affirmation = json.loads(RECORDS["R0"])
    del r0_without_affirmation["affirmation_record"]
    person("affirmation_r0_without_affirmation", "a digest over R0's bytes with affirmation_record removed: not the "
           "bytes the Standard seals", "person-a-1",
           dict(affirmation_r0, affirmed_digest=sha256(compact(r0_without_affirmation)).hex()))
    person("affirmation_r0_by_org", "org-seal-1 signs a person's affirmation", "org-seal-1", affirmation_r0)
    person("affirmation_r2", "person-a-1 affirms DR-2099-003, whose covered bytes carry the seal field zeroed",
           "person-a-1", {"assertion": "person_affirmation", "decision_id": "DR-2099-003",
                          "affirmed_digest": seal["R2"], "signed_at": "2026-09-27T10:00:00Z"})
    stored_r2 = RECORDS["R2"].replace("0" * 64, seal["R2"])
    person("affirmation_r2_as_stored", "a digest over R2 with its seal value in place, not zeroed", "person-a-1",
           {"assertion": "person_affirmation", "decision_id": "DR-2099-003",
            "affirmed_digest": sha256(stored_r2.encode("utf-8")).hex(), "signed_at": "2026-09-27T10:00:00Z"})

    passkey_approval = dict(approval, signed_at="2026-10-01T09:12:30Z")
    passkey("approval_passkey", "person-a-passkey-1 (WebAuthn, ES256) approves o1, user present and verified",
            "person-a-passkey-1", passkey_approval)
    passkey("approval_passkey_up_only", "the same, with the UV flag absent: the authenticator did not verify its user",
            "person-a-passkey-1", passkey_approval, flags=0x01)
    passkey("approval_passkey_no_up", "the UP flag absent: no user presence", "person-a-passkey-1", passkey_approval,
            flags=0x04)
    passkey("approval_passkey_wrong_challenge", "a challenge that is the SHA-256 of other bytes",
            "person-a-passkey-1", passkey_approval, challenge_over=b"other bytes")
    passkey("approval_passkey_wrong_origin", "signed from another origin", "person-a-passkey-1", passkey_approval,
            origin="https://example.net")
    passkey("approval_passkey_wrong_rpid", "an authenticator bound to another relying party", "person-a-passkey-1",
            passkey_approval, rp_id="example.net")
    passkey("approval_passkey_create", "a registration ceremony (webauthn.create), not an assertion",
            "person-a-passkey-1", passkey_approval, type_="webauthn.create")
    bad = copy.deepcopy(persons["approval_passkey"])
    bad["about"] = "approval_passkey with the last byte of its signature changed"
    bad["assertion"]["signature"]["value_b64"] = b64(flip_last_byte(base64.b64decode(
        bad["assertion"]["signature"]["value_b64"])))
    persons["approval_passkey_bad_signature"] = bad
    passkey("approval_passkey_rs256_label", "approval_passkey labelled WebAuthn-RS256, a suite the reference check does "
            "not support", "person-a-passkey-1", passkey_approval, presented={"algorithm": "WebAuthn-RS256"})
    passkey("approval_passkey_cross_origin", "the same approval signed in a cross-origin frame: the client data states "
            "crossOrigin true and a topOrigin, which the check carries through as facts and fails the signature for, "
            "since the policy cannot say which outside pages are expected", "person-a-passkey-1",
            passkey_approval, cross_origin=True, top_origin="https://top.example.org")
    passkey("approval_passkey_cross_origin_only", "crossOrigin true with no topOrigin: fails all the same",
            "person-a-passkey-1", passkey_approval, cross_origin=True)
    passkey("approval_passkey_top_origin_only", "crossOrigin false with a topOrigin: fails all the same",
            "person-a-passkey-1", passkey_approval, top_origin="https://top.example.org")
    passkey("approval_passkey_cross_origin_text", "crossOrigin written as the text \"true\", which no browser writes: "
            "not a same-origin ceremony, so it fails; carried as no fact, since it is not a boolean",
            "person-a-passkey-1", passkey_approval, cross_origin="true")

    # ---- the organisation's seals
    seals = {}
    ab_approved = approved_attachment(spec_digest, view_digest)
    ab_rejected = rejected_attachment(spec_digest)

    def mk_seal(name, about, key, sealed, sealed_at, **kw):
        seals[name] = {"about": about, **make_seal(ed, key, sealed, sealed_at, **kw)}

    # The seal of an attachment that carries a copy of it: sign the digest of the bytes with the copy's value made of
    # A, then put the value in place.
    placeholder = embedded_signature("org-seal-1", "A" * ED25519_SIGNATURE_B64_LENGTH)
    ab_approved["issuer_signature"] = placeholder
    digest_with_placeholder = sha256(compact(ab_approved)).hex()
    mk_seal("seal_attachment", "org-seal-1 seals the attachment of DR-2099-101, which carries a copy of the seal as "
            "its issuer_signature", "org-seal-1",
            {"kind": "attachment", "id": DECISION_A, "digest": digest_with_placeholder}, "2026-10-01T09:30:00Z")
    value = seals["seal_attachment"]["assertion"]["signature"]["value_b64"]
    if len(value) != ED25519_SIGNATURE_B64_LENGTH:
        raise ValueError("an Ed25519 signature in padded base64 has 88 characters")
    ab_approved["issuer_signature"] = embedded_signature("org-seal-1", value)
    # Copies that are not copies: the issuer sealed the attachment with a copy whose algorithm label, or whose
    # signed_bytes_ref, is not the seal's. The sealed digest matches those bytes; the copy does not agree. Each seal
    # gives the member as the issuer wrote it (issuer_signature), the value in place, for the cases to put in.
    for name, about, member in (
            ("seal_attachment_copy_relabelled", "org-seal-1 seals the attachment of DR-2099-101 carrying a copy "
             "of the seal labelled EdDSA: the digest is over those bytes, so it matches; the copy does not agree "
             "with the seal",
             {"algorithm": "EdDSA"}),
            ("seal_attachment_copy_other_ref", "org-seal-1 seals the attachment of DR-2099-101 carrying a copy whose "
             "signed_bytes_ref names anchoring's checkpoint: the digest matches; the copy does not agree with the seal",
             {"signed_bytes_ref": "dps-anchoring 0.2.0 checkpoint"})):
        variant = copy.deepcopy(ab_approved)
        variant["issuer_signature"] = dict(placeholder, **member)
        mk_seal(name, about, "org-seal-1",
                {"kind": "attachment", "id": DECISION_A, "digest": sha256(compact(variant)).hex()},
                "2026-10-01T09:32:00Z")
        seals[name]["issuer_signature"] = dict(variant["issuer_signature"],
                                               value_b64=seals[name]["assertion"]["signature"]["value_b64"])
    # The copy written with an escape: JSON lets a writer escape / as \/. The rule replaces the value's characters,
    # whatever the writing, so this writing gives the sealed digest, as the writing with no escape does; replacing the
    # 92 written characters instead gives another digest, and is not the rule. Both are given here.
    written = compact(ab_approved)
    escaped_value = value.replace("/", "\\/")
    old, new = f'"value_b64":"{value}"'.encode("utf-8"), f'"value_b64":"{escaped_value}"'.encode("utf-8")
    if written.count(old) != 1 or escaped_value == value or json.loads(written.replace(old, new)) != ab_approved:
        raise ValueError("the escaped writing of the attachment is not what this generator expects")
    escaped = written.replace(old, new)
    escaped_copy = {
        "about": "The attachment of DR-2099-101 written with the copy's value escaped (/ as \\/). The rule replaces "
                 "the value's characters, 88 here, whatever the writing: this writing gives the sealed digest, as the "
                 "writing with no escape does (digest_replacing_the_value_characters); replacing the 92 written "
                 "characters instead gives another digest (digest_replacing_the_written_characters), which is not "
                 "the rule.",
        "attachment_text": escaped.decode("utf-8"),
        "value_as_written": escaped_value,
        "value_characters": len(value),
        "written_characters": len(escaped_value),
        "sealed_digest": digest_with_placeholder,
        "digest_replacing_the_value_characters": sha256(escaped.replace(new, b'"value_b64":"' + b"A" * len(value)
                                                                        + b'"')).hex(),
        "digest_replacing_the_written_characters": sha256(escaped.replace(new, b'"value_b64":"'
                                                                          + b"A" * len(escaped_value) + b'"')).hex(),
    }
    # The copy's member written twice, which only the issuer can do: a reader that keeps the last member finds the
    # attachment as issued, one that keeps the first does not. The profile does not read such a document.
    twice = written.replace(old, b'"value_b64":"' + b"B" * len(value) + b'",' + old, 1)
    if twice.count(b'"value_b64"') != 2 or json.loads(twice) != ab_approved:
        raise ValueError("the duplicate-member writing is not what this generator expects")
    duplicate_member = {
        "about": "The attachment of DR-2099-101 with issuer_signature naming value_b64 twice, a placeholder first and "
                 "the seal's value last. Not read under the profile: a reader keeping the last member would find the "
                 "attachment as issued (a matching digest, an agreeing copy), one keeping the first neither.",
        "attachment_text": twice.decode("utf-8"),
        "differs_at": "/issuer_signature/value_b64",
    }
    # The same, deeper: the approved outcome stage naming its approved digest twice, zeros first and the digest last.
    stage = next(i for i, st in enumerate(ab_approved["stages"]) if "approved_spec_digest" in st)
    old_d = f'"approved_spec_digest":"{ab_approved["stages"][stage]["approved_spec_digest"]}"'.encode("utf-8")
    deep = written.replace(old_d, b'"approved_spec_digest":"' + b"0" * 64 + b'",' + old_d, 1)
    if written.count(old_d) < 1 or deep == written or json.loads(deep) != ab_approved:
        raise ValueError("the deep duplicate-member writing is not what this generator expects")
    duplicate_member_deep = {
        "about": "The attachment of DR-2099-101 with the approved outcome stage naming approved_spec_digest twice, 64 "
                 "zeros first and the digest last. Not read under the profile: the seal verifies for every reader, a "
                 "last-member reader sees the digest, a first-member reader sees zeros.",
        "attachment_text": deep.decode("utf-8"),
        "differs_at": f"/stages/{stage}/approved_spec_digest",
    }
    mk_seal("seal_attachment_wrong_rule", "a seal over the digest of the attachment's bytes with the embedded copy's "
            "value present, not replaced by A", "org-seal-1",
            {"kind": "attachment", "id": DECISION_A, "digest": sha256(compact(ab_approved)).hex()},
            "2026-10-01T09:31:00Z")
    mk_seal("seal_attachment_102", "org-seal-1 seals the attachment of DR-2099-102, which carries no copy",
            "org-seal-1", {"kind": "attachment", "id": DECISION_B, "digest": sha256(compact(ab_rejected)).hex()},
            "2026-10-02T09:40:00Z")
    record_r0 = {"kind": "record", "id": "DR-2099-001", "digest": seal["R0"]}
    mk_seal("seal_record_r0", "org-seal-1 seals the record DR-2099-001: its seal_hash", "org-seal-1", record_r0,
            "2026-09-25T11:30:00Z")
    mk_seal("seal_record_r2", "org-seal-1 seals DR-2099-003, whose covered bytes carry the seal field zeroed",
            "org-seal-1", {"kind": "record", "id": "DR-2099-003", "digest": seal["R2"]}, "2026-09-27T10:30:00Z")
    mk_seal("seal_record_wrong_digest", "a seal naming DR-2099-001 with the seal of DR-2099-002 as its digest",
            "org-seal-1", dict(record_r0, digest=seal["R1"]), "2026-09-25T11:30:00Z")
    mk_seal("seal_export", "org-seal-1 seals the export as issued, under the issuer's reference for it", "org-seal-1",
            {"kind": "export", "id": EXPORT_ID, "digest": sha256(compact(exports["full"])).hex()},
            "2026-09-27T12:30:00Z")
    mk_seal("seal_record_moved_to_org0", "seal_record_r0's signature presented under key reference org-seal-0",
            "org-seal-1", record_r0, "2026-09-25T11:30:00Z", presented={"key_ref": "org-seal-0"})
    mk_seal("seal_record_other_profile", "the key signed the same fields under profile dps-anchoring", "org-seal-1",
            record_r0, "2026-09-25T11:30:00Z", signed_as={"profile": "dps-anchoring"})
    mk_seal("seal_record_other_version", "the key signed the same fields under profile_version 0.2.0", "org-seal-1",
            record_r0, "2026-09-25T11:30:00Z", signed_as={"version": "0.2.0"})
    mk_seal("seal_record_other_type", "the key signed the same fields under assertion type checkpoint", "org-seal-1",
            record_r0, "2026-09-25T11:30:00Z", signed_as={"assertion": "checkpoint"})
    mk_seal("seal_record_kind_changed", "signed as a record, presented as an attachment", "org-seal-1", record_r0,
            "2026-09-25T11:30:00Z", presented={"sealed": dict(record_r0, kind="attachment")})
    mk_seal("seal_record_id_changed", "signed for DR-2099-001, presented for DR-2099-002", "org-seal-1", record_r0,
            "2026-09-25T11:30:00Z", presented={"sealed": dict(record_r0, id="DR-2099-002")})
    mk_seal("seal_record_digest_changed", "signed over R0's seal, presented with R1's", "org-seal-1", record_r0,
            "2026-09-25T11:30:00Z", presented={"sealed": dict(record_r0, digest=seal["R1"])})
    mk_seal("seal_record_time_changed", "sealed at 11:30:00Z, presented an hour later", "org-seal-1", record_r0,
            "2026-09-25T11:30:00Z", presented={"sealed_at": "2026-09-25T12:30:00Z"})
    mk_seal("seal_record_other_algorithm", "seal_record_r0 with an algorithm label the reference check does not "
            "support", "org-seal-1", record_r0, "2026-09-25T11:30:00Z", presented={"algorithm": "ECDSA-P256-SHA256"})
    mk_seal("seal_record_before_validity", "org-seal-1, stated as sealed before the key's not_before", "org-seal-1",
            record_r0, "2025-12-31T23:00:00Z")
    mk_seal("seal_record_feb30", "sealed_at 2026-02-30: the schema admits the form, but it is not a real UTC time",
            "org-seal-1", record_r0, "2026-02-30T11:30:00Z")
    mk_seal("seal_record_org0", "org-seal-0, before the key was superseded", "org-seal-0", record_r0,
            "2026-09-25T11:30:00Z")
    mk_seal("seal_record_org0_late", "org-seal-0, stated as sealed after it was superseded", "org-seal-0", record_r0,
            "2026-10-06T09:00:00Z")
    mk_seal("seal_record_by_person", "person-a-1, a key in role person, signs an organisation's seal", "person-a-1",
            record_r0, "2026-09-25T11:30:00Z")
    mk_seal("seal_record_by_witness", "witness-a-1, a key in role witness, signs an organisation's seal",
            "witness-a-1", record_r0, "2026-09-25T11:30:00Z")
    mk_seal("seal_record_x", "org-seal-x, a key the policy does not list", "org-seal-x", record_r0,
            "2026-09-25T11:30:00Z")
    bad = copy.deepcopy(seals["seal_record_r0"])
    bad["about"] = "seal_record_r0 with the last byte of its signature changed"
    bad["assertion"]["signature"]["value_b64"] = b64(flip_last_byte(base64.b64decode(
        bad["assertion"]["signature"]["value_b64"])))
    seals["seal_record_bad_signature"] = bad

    # ---- time-stamp tokens over signature values (anchoring 0.2.0's assertion, by reference)
    tsa1 = (ecc["tsa-example-1"], tsa_certs["tsa-example-1"])
    tsa2 = (ecc["tsa-example-2"], tsa_certs["tsa-example-2"])
    tsa_rsa = (rsa_tsa, tsa_certs[rsa_name])
    tokens = {}

    def sig_of(group, name):
        return base64.b64decode(group[name]["assertion"]["signature"]["value_b64"])

    def tok(name, about, subject_bytes, signer, gen_time, serial, **kw):
        token, signature = make_token(signer[0], signer[1], subject_bytes, when(gen_time), serial, **kw)
        tokens[name] = {"about": about, "imprint_of_hex": subject_bytes.hex(), "token_b64": b64(token)}
        return token, signature

    a2 = sig_of(persons, "approval_a2")
    at_915 = "2026-10-01T09:15:00Z"
    good, signature = tok("sig_approval_a2_before", "TSA 1 over approval_a2's signature value, before person-a-2 was "
                          "revoked", a2, tsa1, at_915, 301)
    tok("sig_approval_a2_before_bis", "the same request answered again: another serial number, the same genTime, so "
        "the same result from other bytes", a2, tsa1, at_915, 309)
    tok("sig_approval_a2_after", "TSA 1 over approval_a2's signature value, after person-a-2 was revoked", a2, tsa1,
        "2026-10-04T09:00:00Z", 302)
    tok("sig_approval_a2_at_revocation", "TSA 1 over approval_a2's signature value, at exactly the time of the "
        "revocation", a2, tsa1, "2026-10-03T00:00:00Z", 303)
    tok("sig_approval_a2_boundary", "TSA 1 over approval_a2's signature value, one second before the revocation, "
        "accuracy 2 s", a2, tsa1, "2026-10-02T23:59:59Z", 304, accuracy_seconds=2)
    tok("sig_approval_a2_early", "TSA 1 over approval_a2's signature value, before the time the signer states", a2,
        tsa1, "2026-10-01T09:00:00Z", 305)
    tok("sig_approval_a2_tsa2", "TSA 2, which the policy does not list, over approval_a2's signature value", a2, tsa2,
        at_915, 401)
    tok("sig_approval_a", "TSA 1 over approval_a's signature value", sig_of(persons, "approval_a"), tsa1, at_915, 306)
    tok("sig_review_b0", "TSA 1 over review_b0's signature value", sig_of(persons, "review_b0"), tsa1,
        "2026-10-02T09:25:00Z", 307)
    tok("sig_seal_attachment", "TSA 1 over seal_attachment's signature value", sig_of(seals, "seal_attachment"), tsa1,
        "2026-10-01T09:35:00Z", 308)
    # The token's own shape, as anchoring 0.2.0's reference check reads it.
    tok("sig_approval_a2_no_cert_id", "TSA 1 over approval_a2's signature value, with no signingCertificateV2 "
        "attribute", a2, tsa1, at_915, 310, with_cert_id=False)
    tok("sig_approval_a2_wrong_cert_id", "TSA 1 over approval_a2's signature value, its ESSCertIDv2 naming TSA 2's "
        "certificate", a2, tsa1, at_915, 311, cert_id_of=tsa_certs["tsa-example-2"])
    tok("sig_approval_a2_cert_id_sha512", "TSA 1 over approval_a2's signature value, its ESSCertIDv2 made with "
        "SHA-512", a2, tsa1, at_915, 312, cert_id_hash="sha512")
    tok("sig_approval_a2_cert_id_no_value", "TSA 1 over approval_a2's signature value, its signingCertificateV2 "
        "attribute with no value", a2, tsa1, at_915, 313, cert_id_values=0)
    tok("sig_approval_a2_other_sid", "signed with TSA 1's key, its signer identifier naming TSA 2's certificate", a2,
        tsa1, at_915, 314, sid_cert_der=tsa_certs["tsa-example-2"])
    tok("sig_approval_a2_not_utc", "TSA 1 over approval_a2's signature value, its genTime written with no time zone "
        "(20261001091500)", a2, tsa1, at_915, 315, gen_time_text="20261001091500")
    tok("sig_approval_a2_accuracy_negative", "TSA 1 over approval_a2's signature value, with an accuracy of -60 s",
        a2, tsa1, at_915, 316, accuracy_seconds=-60)
    tok("sig_approval_a2_accuracy_too_large", "TSA 1 over approval_a2's signature value, with an accuracy of 10^12 s, "
        "past the year 9999", a2, tsa1, at_915, 317, accuracy_seconds=10 ** 12)
    tok("sig_approval_a2_accuracy_millis", "TSA 1 over approval_a2's signature value, with an accuracy of 1000 millis "
        "(RFC 3161 allows 1 to 999)", a2, tsa1, at_915, 318, accuracy_millis=1000)
    tok("sig_approval_a2_rsa_label", "TSA 1 over approval_a2's signature value, its ECDSA signature labelled "
        "sha256WithRSAEncryption", a2, tsa1, at_915, 319, signature_algorithm="sha256_rsa")
    tok("sig_approval_a2_sha384_label", "TSA 1 over approval_a2's signature value, its signature labelled "
        "ecdsa-with-SHA384", a2, tsa1, at_915, 320, signature_algorithm="sha384_ecdsa")
    # The RSA authority (RFC 9500's testRSA2048), RSA PKCS#1 v1.5 with SHA-256, at the same genTime as TSA 1.
    good_rsa, rsa_signature = tok("sig_approval_a2_rsa", "the RSA authority over approval_a2's signature value, before "
                                  "person-a-2 was revoked", a2, tsa_rsa, at_915, 501)
    tok("sig_approval_a_rsa", "the RSA authority over approval_a's signature value", sig_of(persons, "approval_a"),
        tsa_rsa, at_915, 502)
    tok("sig_approval_a2_rsa_pss_label", "the RSA authority over approval_a2's signature value, its PKCS#1 v1.5 "
        "signature labelled RSASSA-PSS", a2, tsa_rsa, at_915, 503, signature_algorithm="rsassa_pss")
    tok("sig_approval_a2_rsa_ecdsa_label", "the RSA authority over approval_a2's signature value, its signature "
        "labelled ecdsa-with-SHA256", a2, tsa_rsa, at_915, 504, signature_algorithm="sha256_ecdsa")
    tok("sig_approval_a2_rsa_no_cert_id", "the RSA authority over approval_a2's signature value, with no "
        "signingCertificateV2 attribute", a2, tsa_rsa, at_915, 505, with_cert_id=False)
    # Changed after signing, without re-signing.
    tokens["sig_approval_a2_bad_signature"] = {"about": "sig_approval_a2_before with the last byte of its signature "
                                               "changed", "imprint_of_hex": a2.hex(),
                                               "token_b64": b64(replace_once(good, signature, flip_last_byte(signature)))}
    tokens["sig_approval_a2_backdated"] = {"about": "sig_approval_a2_before with its genTime moved one day earlier "
                                           "after signing, so the messageDigest attribute no longer matches the "
                                           "TSTInfo", "imprint_of_hex": a2.hex(),
                                           "token_b64": b64(replace_once(good, b"20261001091500Z", b"20260930091500Z"))}
    tokens["sig_approval_a2_rsa_bad_signature"] = {"about": "sig_approval_a2_rsa with the last byte of its signature "
                                                   "changed", "imprint_of_hex": a2.hex(),
                                                   "token_b64": b64(replace_once(good_rsa, rsa_signature,
                                                                                 flip_last_byte(rsa_signature)))}
    tokens["not_a_token"] = {"about": "bytes that are not a time-stamp token", "imprint_of_hex": a2.hex(),
                             "token_b64": b64(b"not a time-stamp token")}

    # ---- the trust policy: anchoring 0.2.0's, holding the authorities, a key of every role and a checkpoint source
    policy = {
        "profile": "dps-anchoring-trust-policy",
        "profile_version": ANCHORING_VERSION,
        "policy_ref": "urn:example:trust-policy:verifier-2",
        "tsas": [{"tsa_ref": "tsa-example-1", "holder": "Example time-stamping authority 1 (test only)",
                  "certificate_b64": certificates["tsa-example-1"]["certificate_b64"],
                  "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z"},
                 {"tsa_ref": RSA_TSA_REF, "holder": "Example time-stamping authority 3 (test only; its key is RFC "
                                                     "9500's testRSA2048)",
                  "certificate_b64": certificates[rsa_name]["certificate_b64"],
                  "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z"}],
        "keys": [],
        "checkpoint_sources": [{"source_ref": "witness-a", "kind": "witness", "holder": "Example witness A (test only)",
                                "chain_ids": ["urn:example:chain:issuer-1"], "key_refs": ["witness-a-1"]}],
    }

    def key(ref, holder, role, not_before, not_after, revoked=None, **extra):
        entry = {"key_ref": ref, "holder": holder, "role": role, "algorithm": test_keys[ref]["algorithm"],
                 "public_key_hex": test_keys[ref]["public_key_hex"], "not_before": not_before, "not_after": not_after}
        if revoked:
            entry["revoked_at"], entry["revocation_reason"] = revoked
        entry.update(extra)
        policy["keys"].append(entry)

    directory = "urn:example:directory:issuer-1"
    key("person-a-1", "owner-example-1", "person", "2026-09-01T00:00:00Z", "2027-08-31T23:59:59Z",
        identity_source_ref=directory)
    key("person-a-passkey-1", "owner-example-1", "person", "2026-09-01T00:00:00Z", "2027-08-31T23:59:59Z",
        identity_source_ref=directory, webauthn={"rp_id": RP_ID, "origins": [ORIGIN]})
    key("person-a-2", "owner-example-1", "person", "2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z",
        ("2026-10-03T00:00:00Z", "compromised"), identity_source_ref=directory)
    key("person-b-0", "reviewer-example-2", "person", "2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z",
        ("2026-10-03T00:00:00Z", "superseded"), identity_source_ref=directory)
    key("person-b-1", "reviewer-example-2", "person", "2026-10-03T00:00:00Z", "2027-10-02T23:59:59Z",
        identity_source_ref=directory)
    key("person-e-1", "reviewer-example-5", "person", "2026-01-01T00:00:00Z", "2026-09-15T23:59:59Z",
        identity_source_ref=directory)
    key("personne-é-1", "signataire-exemple-6", "person", "2026-09-01T00:00:00Z", "2027-08-31T23:59:59Z",
        identity_source_ref=directory)
    key("org-seal-1", "Example issuer (test only)", "organisation", "2026-01-01T00:00:00Z", "2027-12-31T23:59:59Z",
        certificate_b64=certificates["org-seal-1"]["certificate_b64"])
    key("org-seal-0", "Example issuer (test only)", "organisation", "2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z",
        ("2026-10-05T00:00:00Z", "superseded"))
    key("witness-a-1", "Example witness A (test only)", "witness", "2026-09-01T00:00:00Z", "2027-08-31T23:59:59Z")

    # ---- the base attachment, its context and its report
    def subject_of(group, name):
        a = group[name]["assertion"]
        of = {"assertion": a["assertion"], "key_ref": a["signature"]["key_ref"]}
        if a["assertion"] == "organisation_seal":
            of.update(sealed_kind=a["sealed"]["kind"], sealed_id=a["sealed"]["id"])
        else:
            of["decision_id"] = a["decision_id"]
            if "stage_id" in a:
                of["stage_id"] = a["stage_id"]
        return {"kind": "signature", "of": of, "value_b64": a["signature"]["value_b64"]}

    def timestamp(subject, token_name, tsa_ref="tsa-example-1"):
        return {"assertion": "timestamp", "subject": subject, "hash_algorithm": "SHA-256", "tsa_ref": tsa_ref,
                "token_b64": tokens[token_name]["token_b64"]}

    base_persons = ["approval_a", "approval_passkey", "review_b0", "affirmation_r0", "approval_a2"]
    base_seals = ["seal_attachment", "seal_record_r0", "seal_export"]
    attachment = {
        "profile": PROFILE,
        "profile_version": VERSION,
        "person_signatures": [persons[n]["assertion"] for n in base_persons],
        "organisation_seals": [seals[n]["assertion"] for n in base_seals],
        "timestamps": [timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_before")],
    }
    timestamp_assertions = {
        "sig_approval_a2_before_bis": timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_before_bis"),
        "sig_approval_a2_after": timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_after"),
        "sig_approval_a2_at_revocation": timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_at_revocation"),
        "sig_approval_a2_boundary": timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_boundary"),
        "sig_approval_a2_early": timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_early"),
        "sig_approval_a2_tsa2": timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_tsa2", "tsa-example-2"),
        "sig_approval_a": timestamp(subject_of(persons, "approval_a"), "sig_approval_a"),
        "sig_review_b0": timestamp(subject_of(persons, "review_b0"), "sig_review_b0"),
        "sig_seal_attachment": timestamp(subject_of(seals, "seal_attachment"), "sig_seal_attachment"),
        # The subject's of may name this profile, as anchoring 0.2.0's attachment schema admits.
        "sig_approval_a2_named_profile": timestamp(
            {"kind": "signature", "of": {"profile": PROFILE, **subject_of(persons, "approval_a2")["of"]},
             "value_b64": subject_of(persons, "approval_a2")["value_b64"]}, "sig_approval_a2_before"),
        "sig_approval_a2_rsa": timestamp(subject_of(persons, "approval_a2"), "sig_approval_a2_rsa", RSA_TSA_REF),
    }
    action_binding = {DECISION_A: ab_approved, DECISION_B: ab_rejected}
    context = {"export": "full", "action_binding": [DECISION_A, DECISION_B]}

    def person_result(i, name, at, identity_holder, basis="stated_time", timestamp_index=None, revocation=None,
                      extra=None, authenticator=None, checked_against="action_binding_attachment"):
        a = persons[name]["assertion"]
        key_ref = a["signature"]["key_ref"]
        key_state = {"status": "verified", "key_ref": key_ref}
        if revocation:
            key_state["revocation_reason"] = revocation
        key_state.update(time_basis=basis, time=at)
        if timestamp_index is not None:
            key_state["timestamp_index"] = timestamp_index
        out = {"signature_index": i, "assertion": a["assertion"], "decision_id": a["decision_id"]}
        if "stage_id" in a:
            out["stage_id"] = a["stage_id"]
        out.update(key_ref=key_ref, status="verified",
                   signature={"status": "verified", "key_ref": key_ref, "algorithm": a["signature"]["algorithm"],
                              "reference_source": "trust_policy"})
        if authenticator:
            out["authenticator"] = authenticator
        subject = {"status": "verified", "checked_against": checked_against}
        subject.update(extra or {})
        out.update(subject=subject, key_state=key_state,
                   identity={"status": "verified", "basis": "trust_policy", "source_ref": directory,
                             "holder": identity_holder, "issuer_named": identity_holder, "consistency": "consistent"})
        return out

    def seal_result(i, name, at, certificate="not_checked", embedded_copy=None, revocation=None):
        a = seals[name]["assertion"]
        key_ref = a["signature"]["key_ref"]
        key_state = {"status": "verified", "key_ref": key_ref}
        if revocation:
            key_state["revocation_reason"] = revocation
        key_state.update(time_basis="stated_time", time=at)
        checked = {"attachment": "action_binding_attachment", "record": "export_entry", "export": "export"}
        subject = {"status": "verified", "checked_against": checked[a["sealed"]["kind"]]}
        if embedded_copy:
            subject["embedded_copy"] = embedded_copy
        return {"seal_index": i, "sealed": {"kind": a["sealed"]["kind"], "id": a["sealed"]["id"]}, "key_ref": key_ref,
                "status": "verified",
                "signature": {"status": "verified", "key_ref": key_ref, "algorithm": "Ed25519",
                              "reference_source": "trust_policy", "certificate": certificate},
                "subject": subject, "key_state": key_state}

    every_check = {k: "verified" for k in ("token", "message_imprint", "subject_bytes", "message_digest",
                                           "tsa_signature", "signer_certificate", "tsa_state")}
    documents = [{"kind": "export", "digest": sha256(compact(exports["full"])).hex()}] + [
        {"kind": "action_binding_attachment", "decision_id": d, "digest": sha256(compact(action_binding[d])).hex()}
        for d in context["action_binding"]]
    report = {
        "profile": "dps-signatures-report",
        "profile_version": VERSION,
        "trust_policy_ref": policy["policy_ref"],
        "trust_policy": {"status": "verified"},
        "attachment_digest": sha256(compact(attachment)).hex(),
        "documents": documents,
        "person_signature_count": 5,
        "person_signatures": [
            person_result(0, "approval_a", "2026-10-01T09:12:00Z", "owner-example-1"),
            person_result(1, "approval_passkey", "2026-10-01T09:12:30Z", "owner-example-1",
                          authenticator={"user_present": True, "user_verified": True, "cross_origin": False}),
            person_result(2, "review_b0", "2026-10-02T09:21:00Z", "reviewer-example-2", revocation="superseded"),
            person_result(3, "affirmation_r0", "2026-09-25T11:00:00Z", "owner-example-1",
                          extra={"covers_affirmation_record": True}, checked_against="export_entry"),
            person_result(4, "approval_a2", "2026-10-01T09:15:00Z", "owner-example-1", basis="independent_timestamp",
                          timestamp_index=0, revocation="compromised"),
        ],
        "organisation_seal_count": 3,
        "organisation_seals": [
            seal_result(0, "seal_attachment", "2026-10-01T09:30:00Z", certificate="verified", embedded_copy="verified"),
            seal_result(1, "seal_record_r0", "2026-09-25T11:30:00Z", certificate="verified"),
            seal_result(2, "seal_export", "2026-09-27T12:30:00Z", certificate="verified"),
        ],
        "timestamp_count": 1,
        "timestamps": [{
            "timestamp_index": 0,
            "subject": {k: v for k, v in attachment["timestamps"][0]["subject"].items() if k != "value_b64"},
            "status": "verified", "tsa_ref": "tsa-example-1", "reference_source": "trust_policy",
            "gen_time": "2026-10-01T09:15:00Z", "existed_no_later_than": "2026-10-01T09:15:00Z",
            "checks": dict(every_check),
            "signer_time": {"status": "verified", "stated": "2026-10-01T09:12:00Z", "stated_in": "signed_at",
                            "consistency": "consistent"},
        }],
        "scope_of_conclusion": {
            "covers": "supplied_attachment_and_documents_only",
            "not_assessed": ["legal_requirements", "conformance_level", "truth_of_record_content",
                             "whether_the_person_read_or_understood", "view_matched_action", "who_held_the_key",
                             "organisational_authority", "legal_effect", "that_any_person_reviewed",
                             "time_of_issue"],
        },
    }

    return {
        "about": "Generated by generate_vectors.py; do not edit by hand. TEST KEYS ONLY: every key but one is derived "
                 "from its seed_text (seed = SHA-256 of the text; Ed25519: the seed is the private key; ECDSA P-256: "
                 "the scalar is the seed as a big-endian integer mod (n - 1), plus 1); the RSA key is the 2048-bit "
                 "test key RFC 9500, section 2.1, publishes as testRSA2048, given here by its public modulus and "
                 "exponent, as in the anchoring vectors. Records, exports and links are those of the anchoring "
                 "vectors (R0 to R2 from portable verification); the specification is action binding's S0; "
                 "witness-a-1 and the time-stamping authorities are anchoring 0.2.0's test keys, and the trust "
                 "policy is anchoring 0.2.0's trust policy. Each assertion names the test key it was signed with "
                 "(signed_with) and gives signed_bytes_hex, the bytes a verifier builds from it under the shared "
                 "rule, and, where the key signed something else, signature_made_over_hex. A WebAuthn assertion also "
                 "gives its challenge and the bytes the authenticator signed. Each token gives imprint_of_hex, the "
                 "bytes its messageImprint is the SHA-256 of. A document's bytes as received (for attachment_digest "
                 "and the documents' digests) are its JSON with no whitespace, in UTF-8.",
        "test_keys": test_keys,
        "records": {k: {"text": RECORDS[k], "seal_hash": seal[k]} for k in RECORD_ORDER},
        "chain": {"about": "link(i) = SHA-256(link(i-1) || seal(i)), with 32 zero bytes before the first entry, as "
                           "in anchoring's vectors.", "links": {f"L{i}": h for i, h in enumerate(links)}},
        "exports": exports,
        "specification": {"text": SPECIFICATION, "spec_digest": spec_digest},
        "view": {"text": VIEW, "digest": view_digest},
        "action_binding_attachments": action_binding,
        "escaped_copy": escaped_copy,
        "duplicate_member": duplicate_member,
        "duplicate_member_deep": duplicate_member_deep,
        "certificates": certificates,
        "person_signatures": persons,
        "organisation_seals": seals,
        "tokens": tokens,
        "trust_policy": policy,
        "base_attachment": attachment,
        "timestamp_assertions": timestamp_assertions,
        "base_context": context,
        "base_report": report,
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
