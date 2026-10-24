# SPDX-License-Identifier: Apache-2.0
"""Writes vectors.json for the anchoring extension, version 0.2.0 (a proposal).

TEST KEYS ONLY. Every key below but one is derived from a published text, so anyone can recompute it. The one
exception is the RSA key of the second time-stamping authority: it is the 2048-bit RSA test key that RFC 9500,
section 2.1, publishes under the name "testRSA2048", written here as its parameters in hex, exactly as the RFC prints
them. It is a published test key, so that no RSA key had to be generated here. Never derive a real key this way, never
use a published key for anything real, and never trust anything signed by one of these keys.

  seed               SHA-256 of the UTF-8 text "dps-anchoring 0.1.0 test key " followed by the key's name (the text
                     is unchanged in 0.2.0, so the keys are those of 0.1.0)
  Ed25519 (witness)  the seed is the private key (RFC 8032, section 5.1.5)
  ECDSA P-256 (TSA)  the private scalar is (the seed read as a big-endian integer) mod (n - 1), plus 1
  RSA-2048 (TSA)     RFC 9500, section 2.1, "testRSA2048", from its published parameters

Signatures are deterministic: Ed25519 by definition, ECDSA with the deterministic nonces of RFC 6979, and RSA
PKCS#1 v1.5 by construction, through the cryptography package (OpenSSL 3.2 or later). The RFC 3161 tokens are built
with asn1crypto. Re-running this script therefore writes the same bytes, and run_checks.py checks that it does.

Records R0 to R2 and their chain are those of the portable verification extension's cases. R1x is R1 with one
changed word, re-sealed. R4 is a fourth synthetic record. CHAIN_ACCENTED is a chain identifier that is not ASCII, so
that its length prefix (in UTF-8 bytes) differs from its number of characters.

Usage:  python extensions/anchoring/tests/generate_vectors.py            write vectors.json
        python extensions/anchoring/tests/generate_vectors.py --check    exit 1 if vectors.json differs
"""
import base64
import copy
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

from asn1crypto import algos, cms, core, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import cbor2  # pinned; writes the CBOR of the SCITT vectors. The runner reads CBOR with its own strict reader.

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "vectors.json"

PROFILE, VERSION = "dps-anchoring", "0.2.0"
CHAIN = "urn:example:chain:issuer-1"
CHAIN_2 = "urn:example:chain:issuer-2"
CHAIN_ACCENTED = "cha\u00eene-\u00e9metteur-1"  # "chaîne-émetteur-1", precomposed: 17 characters, 19 UTF-8 bytes
SEED_PREFIX = "dps-anchoring 0.1.0 test key "
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TSA_POLICY_OID = "2.999.1"  # an OID under the arc reserved for examples
MAGIC = b"DPS-SIG\x00"
UTC = timezone.utc

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
RECORDS["R1x"] = RECORDS["R1"].replace("Adopt option C instead", "Adopt option D instead")
RECORD_ORDER = ("R0", "R1", "R1x", "R2", "R4")
PORTABLE_VERIFICATION_SEALS = {  # as published in extensions/portable-verification/tests/cases.json
    "R0": "4671e381366fcdad7f6e2951619fa16622d826a4bbe0dd8b505692bd17cf5327",
    "R1": "b6a1a358237efc55ed8a4495166d471f65feb1697ddfa7fa3cb91dcf61b414a9",
    "R2": "b338d5e167236a058d3222ea8634b394765a71b5a04d5ab65bf4751f4696a125",
}


def sha256(data):
    return hashlib.sha256(data).digest()


def b64(data):
    return base64.b64encode(data).decode("ascii")


def compact(doc):
    """A document's bytes as received, by the convention of these vectors: JSON, UTF-8, no whitespace."""
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def when(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def iso(dt):
    """An instant as YYYY-MM-DDTHH:MM:SS[.fraction]Z, with no trailing zero in the fraction."""
    dt = dt.astimezone(UTC)
    out = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        out += "." + f"{dt.microsecond:06d}".rstrip("0")
    return out + "Z"


# ---------------------------------------------------------------- test keys (TEST KEYS ONLY)

def seed(name):
    return sha256((SEED_PREFIX + name).encode("utf-8"))


def ed25519_key(name):
    return Ed25519PrivateKey.from_private_bytes(seed(name))


def p256_key(name):
    return ec.derive_private_key(int.from_bytes(seed(name), "big") % (P256_N - 1) + 1, ec.SECP256R1())


# RFC 9500, section 2.1, RSA-2048 key "testRSA2048": a PUBLISHED TEST KEY, never a real key. The parameters are those
# the RFC prints, in its order and under its names (u is the CRT coefficient q^-1 mod p, PKCS#1's qInv; exponent1 and
# exponent2 are d mod (p - 1) and d mod (q - 1), PKCS#1's dP and dQ). rsa_key() reconstructs the private key from
# them and checks that its public key is the RFC's.
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


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


ED25519_NAMES = ("witness-a-1", "witness-b-1", "witness-b-2", "witness-c-1", "witness-d-1", "witness-x-1",
                 "issuer-seal-1",
                 # The test transparency service's keys (role transparency_service), and one the policy does not list.
                 "service-s-1", "service-s-2", "service-z-1",
                 # The witnesses' statement keys: a key of their own for SCITT statements (RFC 9943 section 9.4).
                 "witness-a-scitt-1", "witness-b-scitt-1")
WA, WB = "witness-a-scitt-1", "witness-b-scitt-1"  # the statement keys of witnesses A and B
P256_NAMES = ("tsa-example-1", "tsa-example-2", "attacker-1")


# ---------------------------------------------------------------- signed bytes (the shared rule)

def lp(data):
    return len(data).to_bytes(4, "big") + data


def signed_bytes(fields):
    return MAGIC + b"".join(lp(f) for f in fields)


TEXT_FIELDS = (0, 1, 2, 3, 4, 7)  # the checkpoint's text fields, by position in its field order


def signed_bytes_counting_characters(fields):
    """A wrong encoder, to show what it gives (TEST ONLY): each text field's prefix counts its characters, not its
    UTF-8 bytes. For ASCII text the two are the same."""
    return MAGIC + b"".join((len(f.decode("utf-8")) if i in TEXT_FIELDS else len(f)).to_bytes(4, "big") + f
                            for i, f in enumerate(fields))


def checkpoint_fields(cp, profile=PROFILE, version=VERSION, assertion="checkpoint", key_ref=None):
    """The fixed field order of a checkpoint: profile, profile_version, assertion type, key_ref, chain_id,
    count (8-byte big-endian), head_link (32 raw bytes), checkpoint_time (UTF-8)."""
    return [profile.encode("utf-8"), version.encode("utf-8"), assertion.encode("utf-8"),
            (cp["signature"]["key_ref"] if key_ref is None else key_ref).encode("utf-8"), cp["chain_id"].encode("utf-8"),
            cp["count"].to_bytes(8, "big"), bytes.fromhex(cp["head_link"]), cp["checkpoint_time"].encode("utf-8")]


# ---------------------------------------------------------------- records, chain, exports

def link(previous, digest_hex):
    return sha256((previous or bytes(32)) + bytes.fromhex(digest_hex))


def seals():
    return {k: sha256(RECORDS[k].encode("utf-8")).hex() for k in RECORD_ORDER}


def chain_links(order, seal):
    out, head = [], None
    for k in order:
        head = link(head, seal[k])
        out.append(head.hex())
    return out


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
    if name in ("R1", "R1x"):
        entry["predecessors"] = {"supersedes": "DR-2099-001"}
    entry["chain"] = {"sequence": sequence, "previous_link": previous_link}
    return entry


def build_exports(seal, links):
    """Portable verification 0.3.0 exports (unsigned entries, as 0.1.0 wrote them). Each entry keeps the chain fields
    it was exported with."""
    L = links
    as_chained = {"R0": (0, None), "R1": (1, L["L0"]), "R2": (2, L["L1"]), "R4": (3, L["L2"])}

    def export(names, chained=None):
        chained = chained or as_chained
        return {"profile": "dps-portable-verification", "profile_version": "0.3.0",
                "entries": [export_entry(n, seal, *chained[n]) for n in names]}

    rewritten = dict(as_chained, R1x=(1, L["L0"]), R2=(2, L["L1x"]))
    out = {
        "full": export(["R0", "R1", "R2"]),
        "tail_dropped": export(["R0", "R1"]),
        "middle_dropped": export(["R0", "R2"]),
        "reordered": export(["R0", "R2", "R1"]),
        "rewritten": export(["R0", "R1x", "R2"], rewritten),
        "extended": export(["R0", "R1", "R2", "R4"]),
    }
    with_cp = export(["R0", "R1"])
    with_cp["issuer_checkpoint"] = {"count": 2, "head_link": L["L1"]}
    out["tail_dropped_with_issuer_checkpoint"] = with_cp
    return out


# ---------------------------------------------------------------- time-stamping authorities and tokens

def tsa_certificate(key, number, serial):
    """A self-signed TSA certificate (TEST ONLY): extendedKeyUsage id-kp-timeStamping, critical (RFC 3161 2.3). Signed
    with ECDSA (RFC 6979 nonces) or RSA PKCS#1 v1.5, with SHA-256: deterministic either way."""
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example time-stamping authority (test only)"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Example TSA {number} (test only)"),
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
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if isinstance(key, rsa.RSAPrivateKey):
        cert = cert.sign(key, hashes.SHA256())
    else:
        cert = cert.sign(key, hashes.SHA256(), ecdsa_deterministic=True)
    return cert.public_bytes(serialization.Encoding.DER)


def make_token(key, cert_der, imprint_of, gen_time, serial, *, hash_algorithm="sha256", accuracy_seconds=None,
               cert_id_of=None, with_cert_id=True, content_type="tst_info", signature_algorithm=None,
               signers=1, hash_label=None, attr_content_type=None, sid_cert_der=None, cert_id_hash="sha256",
               cert_id_values=1, gen_time_text=None, accuracy_millis=None):
    """An RFC 3161 TimeStampToken: CMS SignedData over a TSTInfo, signed with ECDSA P-256 (RFC 6979) or RSA PKCS#1
    v1.5, with SHA-256. signature_algorithm labels the signature; without it, the label fits the key. gen_time_text,
    when given, is written as the genTime's exact characters (to make one that is not in UTC)."""
    if signature_algorithm is None:
        signature_algorithm = "sha256_rsa" if isinstance(key, rsa.RSAPrivateKey) else "sha256_ecdsa"
    cert = asn1_x509.Certificate.load(cert_der)
    sid_cert = asn1_x509.Certificate.load(sid_cert_der or cert_der)
    hashed = hashlib.new(hash_algorithm, imprint_of).digest()
    info = {
        "version": "v1",
        "policy": TSA_POLICY_OID,
        "message_imprint": {"hash_algorithm": {"algorithm": hash_label or hash_algorithm}, "hashed_message": hashed},
        "serial_number": serial,
        "gen_time": gen_time if gen_time_text is None else core.GeneralizedTime.load(
            b"\x18" + bytes([len(gen_time_text)]) + gen_time_text.encode("ascii")),
    }
    if accuracy_seconds is not None or accuracy_millis is not None:
        info["accuracy"] = {k: x for k, x in (("seconds", accuracy_seconds), ("millis", accuracy_millis))
                            if x is not None}
    econtent = tsp.TSTInfo(info).dump()
    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": [attr_content_type or content_type]}),
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
        "encap_content_info": {"content_type": content_type, "content": core.ParsableOctetString(econtent)},
        "certificates": [cert],
        "signer_infos": [signer] * signers,
    })
    token = cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
    return token, signature


def replace_once(data, old, new):
    if data.count(old) != 1 or len(old) != len(new):
        raise ValueError("a replacement must match once and keep the length")
    return data.replace(old, new)


def flip_last_byte(data):
    return data[:-1] + bytes([data[-1] ^ 0x01])


# ---------------------------------------------------------------- witness checkpoints

def make_checkpoint(keys, key_name, chain_id, count, head_link, checkpoint_time, presented=None, signed_as=None,
                    counting_characters=False):
    """A checkpoint signed by a witness key. presented changes what the object says after signing; signed_as
    changes what the key signed (another profile, version, assertion type or key reference); counting_characters
    signs the bytes of an encoder whose length prefixes count characters instead of bytes."""
    cp = {"profile": PROFILE, "profile_version": VERSION, "assertion": "checkpoint", "chain_id": chain_id,
          "count": count, "head_link": head_link, "checkpoint_time": checkpoint_time,
          "signature": {"algorithm": "Ed25519", "key_ref": key_name}}
    fields = checkpoint_fields(cp, **(signed_as or {}))
    made_over = (signed_bytes_counting_characters if counting_characters else signed_bytes)(fields)
    cp["signature"]["value_b64"] = b64(keys[key_name].sign(made_over))
    for k, v in (presented or {}).items():
        if k in ("key_ref", "algorithm"):
            cp["signature"][k] = v
        else:
            cp[k] = v
    out = {"signed_with": key_name, "checkpoint": cp, "signed_bytes_hex": signed_bytes(checkpoint_fields(cp)).hex()}
    if made_over.hex() != out["signed_bytes_hex"]:
        out["signature_made_over_hex"] = made_over.hex()
    return out


# ---------------------------------------------------------------- a SCITT transparency service (test only)

COSE_SIGN1_TAG = 18                                        # RFC 9052: a tagged COSE_Sign1
ALG_ED25519 = -19                                          # RFC 9864: Ed25519; -8 (EdDSA) is deprecated there
HDR_ALG, HDR_CRIT, HDR_KID, HDR_CWT_CLAIMS = 1, 2, 4, 15    # RFC 9052 header labels; 15 is RFC 9597's CWT claims
CWT_ISS, CWT_SUB = 1, 2                                    # RFC 8392 claim keys
HDR_VDS, HDR_VDP = 395, 396                                # RFC 9942: the verifiable data structure, and its proofs
VDS_RFC9162_SHA256 = 1                                     # RFC 9942: the RFC 9162 SHA-256 Merkle tree
VDP_INCLUSION_PROOFS = -1                                  # RFC 9942: inclusion proofs, [tree-size, leaf-index, path]


def sig_structure(protected, payload):
    """RFC 9052 section 4.4 for COSE_Sign1: ["Signature1", the protected header's bytes, external_aad (empty), the
    payload]. These bytes start 84 6a "Signature1"; the shared rule's start "DPS-SIG" 00: no bytes are both."""
    return cbor2.dumps(["Signature1", protected, b"", payload])


def cose_sign1(key, protected, unprotected, payload, detached=False):
    """A tagged COSE_Sign1 over the payload. protected: the protected header's bytes, given encoded so that a test can
    write them otherwise than cbor2 would. Returns the bytes and the signature."""
    signature = key.sign(sig_structure(protected, payload))
    item = cbor2.CBORTag(COSE_SIGN1_TAG, [protected, unprotected, None if detached else payload, signature])
    return cbor2.dumps(item), signature


def leaf_hash(data):
    """RFC 9162 section 2.1.1: a leaf's hash is SHA-256(0x00 || the leaf's data). Here the data is the signed
    statement's bytes as registered, tag included."""
    return sha256(b"\x00" + data)


def merkle_root(hashes_):
    """RFC 9162 section 2.1.1, MTH over leaf hashes: an interior node is SHA-256(0x01 || left || right), the split at
    the largest power of two smaller than the count."""
    n = len(hashes_)
    if n == 1:
        return hashes_[0]
    k = 1 << (n - 1).bit_length() - 1
    return sha256(b"\x01" + merkle_root(hashes_[:k]) + merkle_root(hashes_[k:]))


def inclusion_path(hashes_, m):
    """RFC 9162 section 2.1.3.1, PATH(m, D[n]): the sibling hashes from leaf m up to the root."""
    n = len(hashes_)
    if n == 1:
        return []
    k = 1 << (n - 1).bit_length() - 1
    if m < k:
        return inclusion_path(hashes_[:k], m) + [merkle_root(hashes_[k:])]
    return inclusion_path(hashes_[k:], m - k) + [merkle_root(hashes_[:k])]


# ---------------------------------------------------------------- OpenTimestamps (a real proof and a synthetic chain)

# A REAL OpenTimestamps proof, made for these vectors: the SHA-256 of R0's seal (its 32 raw bytes) was submitted to the
# public calendars alice.btc.calendar.opentimestamps.org and bob.btc.calendar.opentimestamps.org on 2026-10-24 at
# 00:29 UTC; their answers were upgraded once each calendar's commitment was in a Bitcoin block, and combined into one
# proof with two Bitcoin attestations, at heights 972840 (alice) and 972842 (bob). The two headers are the blocks'
# real 80-byte headers, as blockstream.info and mempool.space both gave them (identical, each hashing to its block's
# hash). Public data: no key is involved. Only a real proof catches a misreading the generator and the reader share.
REAL_OTS_PROOF_B64 = (
    "AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI1lpHvcd/+mRCcFWeLmXGj7w7EzQwlsxdnd/+nvnacBn/8AhO79qOjk5B"
    "9QjwIGP7+TTIz6AgbpeoSwzfY8YDSRtNq79OkfhzJaDcWG9ACPAQPPClHeeSP4UiY0DWmd5WwwjwIEyQhzkDnjaEHQizHAWLkvBn"
    "fELwXwBn+qlwq4KI/cl/CPEg6vjCszRm3BgnggDi3Am1GJokcy/Zy+DjrbW583CxjfcI8CDQJzcyJVphIa1FEejg44z7Ladbz+ct"
    "n8snDiwz0M6R+wjxBGrb37TwCGQ0nMXrQrIoCPEgPtTKGSjfG8LQrqxGATUlDve3FsGG14ZbD4YFFuYbVXMI8SBLbM3eHWmlwRey"
    "Ma1RMftASn4Rn629nyR7Fnfz4ornSwjwINCs1+FhkseffEQxkcuLSW22RctOzae0/RMvAOOy0eXrCPAg8/y9mM9N6/EnvuLeCeV5"
    "earCGmxMwfQT8AUq1GDPjE0I8SAjMqKRYH3H1LbKw7CSk08Q9WgFxU+nwWUqnGYPc1tEbwjxINN4deKdOrWCBMwkKaESo7EGflq7"
    "5GXVAUsrBQXj/SWsCPEgEyefFHtUhU58t4tGazgikjPLiJRmna3b+TBCSLhDfyAI8SCXOFWAkZbwGEVj/CKDLYedorXZgjAauxbh"
    "pwQaq4zw5gjwIIg/aShUM/xgCBfTBs8jSmN3KY9L19hsYYDwvqxzdC/4CPEgD3w0hh2NC8vVPdcxQOeGT1ivViUoa0LnYtwe64PQ"
    "PNsI8VkBAAAAAamlKJNdjW2MW6INmKUa5mGHTS1WixcHEporGnClgYiHAAAAAAD+////AgZ5AQAAAAAAFgAUGwzkflzDkiukfGz0"
    "ALu63rmsqkYAAAAAAAAAACJqIPAEJ9gOAAgI8CCrVEHGytnbsXC+KMRfS1pxEvz8wgaXkdlUlDVtvlrAkQgI8SAR40s85yAp754A"
    "VcNlFnxR9KLf8rcjkOUnUC5G0CUz9wgI8SCx1pBmUsq22aA9kiRio0ZXcaGg+J834gfpPZBQloiefAgI8CDGXVFVu4o6Gp/Z0v4f"
    "mCz4gxjjRccKZkh77q2ud9/KOQgI8SBe27/PbC5w4cfmMZjCiGi35mFoyXrGdOuvWtWXq0avqggI8CCbgjJmgq99t/tWamj+D1G6"
    "nQVF2x7LYFSLGugt5g02CggI8SDiw+SHBIuFg5AY3EHOKz8DODLm6P/J6Dc3N7hJSa/MMAgI8SAZhEL+NhlJx9av+TEP8WfoSsWs"
    "SnMb6WX+mXtq8K2lywgI8CBQYfAxdqPeIeiiO5o/weUHZ/tcZTuxzoZ7QsdYpFZbYggI8CB4oFu3kHJPiwMjWaKsv8mRWKySbNVy"
    "iq4AIHPBLYJg7AgI8SCMVne7z18Z2Jl+QkzBodP8AhvBN5fO+TIQ0IiMk5GJMwgI8CDVTQN5cD4Y1d1l2HygQ+IkTt8XIwtCeRWm"
    "gzKGKWdBrggI8CBmYtAbDopoU883o1P4xf3B5BuQ4axd9b80/mFJ5Bv0RggIAAWIlg1z1xkBA6iwO/AIU9xiry4FX9wI8BAaJ3wN"
    "IOq/eKHJgTDwW42zCPEghn7K46SgNck8YKLYCwXf03Wu6YZP15h/A8ZCmAf7mZEI8QRq29+18Ai0NFwAn/13sQjxIMgxJFPMgsmG"
    "PkBXtF/XaS0i9xH2FhBdvLwE5mP9AiG3CPEgBu4PYvi44+gaqc+mVWTDZeKB40oZyNCVTA593hAaCxsI8CDZ9YAgsuSgwiv4FAo/"
    "JxyTGSM3rZ0P+fApULORrDCowgjwIJUA/xTTWsio00v8gXs+bMTDheHlF5wukWClx9wrkWkUCPAgwv3xNt8JVbqNiRhbqF8rCHGQ"
    "MOlLkL5JskIlC/wasrEI8SA0sO+d09dQza11qC4Un9p8oQpD+E1P8hzHiVuCKTJI9QjxIC0pTYmx5/dDA/jUBSoBMjCz1kVNE+OM"
    "xDPU4U4CvprJCPAgaC4K4znscUDE+awduUqITUIHudl9s6FS9sGWmYl9ozYI8SDJRpiTK1MStzdSjXj1y5dFwtk20NPk+32/4/+v"
    "+CcCRwjxIOWia9fPE58pT3U6tMb1lsjPtgarbJ/LOTGRUq759egLCPAg5d4n4n1wqpBTiJoWMf9+tieacHN2G7HH/D3M/rKnbuoI"
    "8VkBAAAAAYlCcLF/5kv4uRUE1hQod8P3umDPsy9y2KE2IEwKlCF9AAAAAAD+////AgsdAQAAAAAAFgAU2z03TE+JYiXcsxE+hMOj"
    "rkTw/SEAAAAAAAAAACJqIPAEKdgOAAgI8CADU9YS/gXLSulrFhzUdso8GQdBSNFgwCWu92154YScfQgI8CC+18/OIj5XIQSF0FOa"
    "mOUvjwm1yw93vBXsnSPOgsMJpggI8CBJDgXcfO69bIcn60UxSF271jbyqkjona+29sgc1qGY3wgI8CDj1l4UG9nmKaGFsDTcVojX"
    "aINXpogiYuQQpEcXelzroAgI8CAp9gcizAFZgWbwBAwbjkdR9880yyu84R8yuxgzb9evtAgI8SA3tJg5PWn9sMFWH2csQXnOQMPQ"
    "zuCXz7oMQU1XHoEQkQgI8CDitU+mdUKi8ewhBwyVLXjTNgLrQ2SzLUSb4fjiOs6C1QgI8CC5Y9SkADpsKvIDDM+pGCYqv9GsB4k7"
    "J0uHXsvOkvx0GQgI8SAnrAUUauyYsQlHYcUB++TEIs9q21GQCRx0IjkjYJoWywgI8CABsoOoUiZGoGU9ATGtGqy+GvJWAkjRIKDm"
    "iXgwa0wvsQgI8CDtogdq6C8xU7Prb9o50YHcY/afntC9KcI7vRNjkrNQ8wgI8CABcbxFcE/AjAyld3XZT4qb0tOJXxI2okNfyYju"
    "fHmaRggI8CBjqF8C7rLCDLOOwWsy5WODoyjr/5IV9adC8+H67ZKH4AgIAAWIlg1z1xkBA6qwOw=="
)
REAL_OTS_HEADERS = {
    "972840": {"block_hash": "000000000000000000016b64fc88053f707560b94f660ac1392aa2e73adb7401",
               "header_hex": "0020393423fb061183ff8af7080c99418fb52fe77df68ef7b663010000000000000000009883bde5"
                             "e4af64daa2579276cf6671fa57b33a4bcdbf365e58386ab5c17b90c007e1db6a930002171e264e4a"},
    "972842": {"block_hash": "000000000000000000014f904572d9a524bdc78599fe8c1d29cabae105290a6f",
               "header_hex": "00000034b92efaa80858d42231edab33c5a57a867183937793d10000000000000000000078b99d7c"
                             "dcb3b72f2abdaeb05ba443cc12e6d33859b426239a0bdbc3c40aa3a314e2db6a93000217f2c9ba1e"},
}

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")


def ots_varuint(n):
    out = b""
    while True:
        b, n = n & 0x7f, n >> 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def ots_varbytes(data):
    return ots_varuint(len(data)) + data


def ots_tree(items):
    """A timestamp tree written as the OpenTimestamps serialisation writes it. items: a list of ("op", tag, arg,
    subtree) and ("att", tag8, payload); every item but the last is preceded by 0xff."""
    out = []
    for item in items:
        if item[0] == "att":
            out.append(b"\x00" + item[1] + ots_varbytes(item[2]))
        else:
            _, tag, arg, sub = item
            out.append(bytes([tag]) + (ots_varbytes(arg) if tag in (0xf0, 0xf1) else b"") + ots_tree(sub))
    return b"".join(b"\xff" + x for x in out[:-1]) + out[-1]


def ots_proof(digest, tree, version=1, magic=OTS_MAGIC):
    return magic + ots_varuint(version) + b"\x08" + digest + tree


def ots_path(digest, steps, tail):
    """A straight path of operations from the digest, ending in tail (a list of items); returns (items, the message at
    the end). steps: ("append" | "prepend", bytes) or ("sha256",)."""
    msg, chain = digest, []
    for step in steps:
        if step[0] == "sha256":
            msg = sha256(msg)
            chain.append((0x08, b""))
        elif step[0] == "append":
            msg = msg + step[1]
            chain.append((0xf0, step[1]))
        else:
            msg = step[1] + msg
            chain.append((0xf1, step[1]))
    items = tail(msg)
    for tag, arg in reversed(chain):
        items = [("op", tag, arg, items)]
    return items, msg


def synthetic_header(merkle_root, height, time_text):
    """A test block header: version 0x20000000, a previous hash derived from the height, the given Merkle root as
    stored (the header's own byte order), the time, and fixed bits and nonce. It carries no proof of work: the check
    does not test any, and says so."""
    prev = sha256(b"dps-anchoring test block " + str(height - 1).encode("ascii"))
    t = int(datetime.strptime(time_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    return (0x20000000).to_bytes(4, "little") + prev + merkle_root + t.to_bytes(4, "little") + bytes.fromhex(
        "ffff001d") + (height & 0xffffffff).to_bytes(4, "little")


# ---------------------------------------------------------------- the whole file

def build():
    seal = seals()
    for k, v in PORTABLE_VERIFICATION_SEALS.items():
        if seal[k] != v:
            raise ValueError(f"{k}: the record no longer matches the portable verification fixture")
    chained = chain_links(["R0", "R1", "R2", "R4"], seal)
    links = {"L0": chained[0], "L1": chained[1], "L2": chained[2], "L3": chained[3]}
    links["L1x"] = link(bytes.fromhex(links["L0"]), seal["R1x"]).hex()
    links["L2x"] = link(bytes.fromhex(links["L1x"]), seal["R2"]).hex()
    exports = build_exports(seal, links)

    ed = {n: ed25519_key(n) for n in ED25519_NAMES}
    ec_keys = {n: p256_key(n) for n in P256_NAMES}
    test_keys = {}
    for n in ED25519_NAMES:
        test_keys[n] = {"algorithm": "Ed25519", "seed_text": SEED_PREFIX + n, "public_key_hex": raw_public(ed[n]).hex()}
    for n in P256_NAMES:
        point = ec_keys[n].public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
        test_keys[n] = {"algorithm": "ECDSA P-256", "seed_text": SEED_PREFIX + n, "public_key_hex": point.hex()}
    rsa_tsa = rsa_key()
    test_keys[RFC9500_TESTRSA2048_NAME] = {
        "algorithm": "RSA-2048", "published_in": "RFC 9500, section 2.1", "name": RFC9500_TESTRSA2048_NAME,
        "modulus_hex": RFC9500_TESTRSA2048["n"], "public_exponent_hex": RFC9500_TESTRSA2048["e"]}

    certs = {
        "tsa-example-1": tsa_certificate(ec_keys["tsa-example-1"], 1, 0x0A11),
        "tsa-example-2": tsa_certificate(ec_keys["tsa-example-2"], 2, 0x0A12),
        # The attacker's certificate copies the name and serial number of TSA 1, with the attacker's own key.
        "attacker-1": tsa_certificate(ec_keys["attacker-1"], 1, 0x0A11),
        # The RSA authority: RFC 9500's test key, in a self-signed certificate (sha256WithRSAEncryption).
        RFC9500_TESTRSA2048_NAME: tsa_certificate(rsa_tsa, 3, 0x0A13),
    }
    certificates = {n: {"certificate_b64": b64(d), "sha256": sha256(d).hex()} for n, d in certs.items()}

    checkpoints = {}

    def cp(name, about, key, chain_id, count, head, at, **kw):
        checkpoints[name] = {"about": about, **make_checkpoint(ed, key, chain_id, count, links[head], at, **kw)}

    cp("cp_a", "witness-a-1, the three entries of the full export", "witness-a-1", CHAIN, 3, "L2",
       "2026-09-27T12:00:00Z")
    cp("cp_a_count_2", "witness-a-1, the first two entries", "witness-a-1", CHAIN, 2, "L1", "2026-09-26T12:00:00Z")
    cp("cp_a_count_4", "witness-a-1, the four entries of the extended export", "witness-a-1", CHAIN, 4, "L3",
       "2026-09-29T12:00:00Z")
    cp("cp_a_moved_to_mirror", "cp_a's signature presented under witness-a-mirror, another reference to the same "
       "key", "witness-a-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z", presented={"key_ref": "witness-a-mirror"})
    cp("cp_a_other_profile", "the key signed the same fields under profile dps-portable-verification",
       "witness-a-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z", signed_as={"profile": "dps-portable-verification"})
    cp("cp_a_other_version", "the key signed the same fields under profile_version 0.1.0, the earlier version",
       "witness-a-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z", signed_as={"version": "0.1.0"})
    cp("cp_a_other_type", "the key signed the same fields under assertion type seal", "witness-a-1", CHAIN, 3, "L2",
       "2026-09-27T12:00:00Z", signed_as={"assertion": "seal"})
    cp("cp_a_count_changed", "signed with count 3, presented with count 2", "witness-a-1", CHAIN, 3, "L2",
       "2026-09-27T12:00:00Z", presented={"count": 2})
    cp("cp_a_head_changed", "signed with head link L2, presented with L1", "witness-a-1", CHAIN, 3, "L2",
       "2026-09-27T12:00:00Z", presented={"head_link": links["L1"]})
    cp("cp_a_time_changed", "signed at 2026-09-27T12:00:00Z, presented a day later", "witness-a-1", CHAIN, 3, "L2",
       "2026-09-27T12:00:00Z", presented={"checkpoint_time": "2026-09-28T12:00:00Z"})
    cp("cp_a_chain_2", "witness-a-1, correctly signed, for a chain the policy does not configure witness-a for",
       "witness-a-1", CHAIN_2, 3, "L2", "2026-09-27T12:00:00Z")
    cp("cp_a_before_validity", "witness-a-1, stated before the key's not_before", "witness-a-1", CHAIN, 1, "L0",
       "2026-08-15T12:00:00Z")
    cp("cp_a_other_algorithm", "cp_a with an algorithm the reference check does not support", "witness-a-1", CHAIN,
       3, "L2", "2026-09-27T12:00:00Z", presented={"algorithm": "ECDSA-P256-SHA256"})
    cp("cp_b", "witness-b-1, before the key was superseded", "witness-b-1", CHAIN, 2, "L1", "2026-09-26T12:00:00Z")
    cp("cp_b_at_revocation", "witness-b-1, stated at exactly the time the key was superseded", "witness-b-1", CHAIN, 2,
       "L1", "2026-09-30T00:00:00Z")
    cp("cp_b_late", "witness-b-1, stated after the key was superseded", "witness-b-1", CHAIN, 3, "L2",
       "2026-10-02T12:00:00Z")
    cp("cp_b2", "witness-b-2, the successor key", "witness-b-2", CHAIN, 3, "L2", "2026-10-02T12:00:00Z")
    cp("cp_c", "witness-c-1, a key later revoked as compromised", "witness-c-1", CHAIN, 3, "L2",
       "2026-09-27T12:00:00Z")
    cp("cp_c_time_changed", "cp_c presented with another checkpoint_time, an hour later: a copy whose signature does "
       "not verify over its fields, held next to cp_c (T63)", "witness-c-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z",
       presented={"checkpoint_time": "2026-09-27T13:00:00Z"})
    cp("cp_d", "witness-d-1, stated after the key's not_after", "witness-d-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z")
    cp("cp_x", "witness-x-1, a key the policy does not list", "witness-x-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z")
    cp("cp_a_statement_key", "cp_a's fields signed under the shared rule by witness-a-scitt-1, a key the policy lists "
       "for SCITT statements only (K139)", "witness-a-scitt-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z")
    cp("cp_x_chain_2", "witness-x-1, correctly signed, for chain 2: with witness-x-1 listed for a source of chain 2 "
       "only, the key the checkpoint's own chain_id would name (K84)", "witness-x-1", CHAIN_2, 3, "L2",
       "2026-09-27T12:00:00Z")
    cp("cp_org", "issuer-seal-1, the issuer's own key (role organisation)", "issuer-seal-1", CHAIN, 3, "L2",
       "2026-09-27T12:00:00Z")
    cp("cp_org_as_witness", "the issuer's own key, signing under issuer-witness-1, a second reference a policy may "
       "give it", "issuer-seal-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z", presented={"key_ref": "issuer-witness-1"},
       signed_as={"key_ref": "issuer-witness-1"})
    cp("cp_a_feb30", "witness-a-1, correctly signed, stating 2026-02-30, a date that does not exist", "witness-a-1",
       CHAIN, 3, "L2", "2026-02-30T12:00:00Z")
    cp("cp_a_leap_second", "witness-a-1, correctly signed, stating a leap second", "witness-a-1", CHAIN, 3, "L2",
       "2026-12-31T23:59:60Z")
    cp("cp_accented", "witness-a-1, the three entries of the full export, for a chain identifier that is not ASCII",
       "witness-a-1", CHAIN_ACCENTED, 3, "L2", "2026-09-27T12:00:00Z")
    cp("cp_accented_char_count", "cp_accented, signed over bytes whose length prefixes count characters instead of "
       "bytes", "witness-a-1", CHAIN_ACCENTED, 3, "L2", "2026-09-27T12:00:00Z", counting_characters=True)
    # Two histories for one chain and count: the rewritten export's last link (L2x) signed for count 3, by the same
    # witness as cp_a and by another. Both verify; they cannot both hold with cp_a.
    cp("cp_a_fork", "witness-a-1 signs a second history of the chain for count 3: the rewritten export's last link",
       "witness-a-1", CHAIN, 3, "L2x", "2026-09-27T13:00:00Z")
    cp("cp_b2_fork", "witness-b-2 signs the rewritten export's last link for count 3", "witness-b-2", CHAIN, 3, "L2x",
       "2026-10-02T13:00:00Z")
    bad = copy.deepcopy(checkpoints["cp_a"])
    bad["about"] = "cp_a with the last byte of its signature changed"
    sig = base64.b64decode(bad["checkpoint"]["signature"]["value_b64"])
    bad["checkpoint"]["signature"]["value_b64"] = b64(flip_last_byte(sig))
    checkpoints["cp_a_bad_signature"] = bad

    def sig_of(name):
        return base64.b64decode(checkpoints[name]["checkpoint"]["signature"]["value_b64"])

    tsa1 = (ec_keys["tsa-example-1"], certs["tsa-example-1"])
    tsa_rsa = (rsa_tsa, certs[RFC9500_TESTRSA2048_NAME])
    tokens = {}

    def tok(name, about, subject_bytes, signer, gen_time, serial, **kw):
        token, _ = make_token(signer[0], signer[1], subject_bytes, when(gen_time), serial, **kw)
        tokens[name] = {"about": about, "imprint_of_hex": subject_bytes.hex(), "token_b64": b64(token)}
        return token

    r0 = bytes.fromhex(seal["R0"])
    good = tok("seal_r0", "TSA 1 over the seal of R0", r0, tsa1, "2026-09-25T11:05:00Z", 101)
    tok("seal_r0_early", "TSA 1 over the seal of R0, before R0's stated affirmation time", r0, tsa1,
        "2026-09-25T10:30:00Z", 102)
    tok("seal_r0_accuracy", "TSA 1 over the seal of R0, 30 s before its affirmation time, accuracy 60 s", r0, tsa1,
        "2026-09-25T10:59:30Z", 103, accuracy_seconds=60)
    tok("seal_r1", "TSA 1 over the seal of R1", bytes.fromhex(seal["R1"]), tsa1, "2026-09-26T10:05:00Z", 104)
    tok("link_2", "TSA 1 over link(2), the head link of the full export", bytes.fromhex(links["L2"]), tsa1,
        "2026-09-27T10:30:00Z", 105)
    tok("seal_r0_tsa2", "TSA 2, which the policy does not list, over the seal of R0", r0,
        (ec_keys["tsa-example-2"], certs["tsa-example-2"]), "2026-09-25T11:05:00Z", 201)
    tok("seal_r0_spoofed", "signed with the attacker's key, naming TSA 1's issuer and serial number and carrying "
        "the attacker's certificate", r0, (ec_keys["attacker-1"], certs["attacker-1"]), "2026-09-25T11:05:00Z", 901)
    tok("seal_r0_wrong_cert_id", "TSA 1 over the seal of R0, its ESSCertIDv2 naming TSA 2's certificate", r0, tsa1,
        "2026-09-25T11:05:00Z", 107, cert_id_of=certs["tsa-example-2"])
    tok("seal_r0_no_cert_id", "TSA 1 over the seal of R0, with no signingCertificateV2 attribute", r0, tsa1,
        "2026-09-25T11:05:00Z", 108, with_cert_id=False)
    tok("seal_r0_sha512", "TSA 1 over the seal of R0, its messageImprint made with SHA-512", r0, tsa1,
        "2026-09-25T11:05:00Z", 109, hash_algorithm="sha512")
    tok("seal_r0_not_tst", "a CMS SignedData over the same TSTInfo bytes, labelled id-data, not id-ct-TSTInfo", r0,
        tsa1, "2026-09-25T11:05:00Z", 110, content_type="data")
    tok("seal_r0_rsa_label", "TSA 1 over the seal of R0, its signatureAlgorithm labelled sha256WithRSAEncryption",
        r0, tsa1, "2026-09-25T11:05:00Z", 111, signature_algorithm="sha256_rsa")
    tok("sig_cp_c_before", "TSA 1 over cp_c's signature value, before witness-c-1 was revoked", sig_of("cp_c"), tsa1,
        "2026-09-27T12:05:00Z", 112)
    tok("sig_cp_c_after", "TSA 1 over cp_c's signature value, after witness-c-1 was revoked", sig_of("cp_c"), tsa1,
        "2026-10-02T09:00:00Z", 113)
    tok("sig_cp_c_boundary", "TSA 1 over cp_c's signature value, genTime one second before the revocation, "
        "accuracy 2 s", sig_of("cp_c"), tsa1, "2026-10-01T11:59:59Z", 114, accuracy_seconds=2)
    tok("sig_cp_c_early", "TSA 1 over cp_c's signature value, an hour before cp_c's stated time", sig_of("cp_c"),
        tsa1, "2026-09-27T11:00:00Z", 115)
    tok("sig_cp_b", "TSA 1 over cp_b's signature value", sig_of("cp_b"), tsa1, "2026-09-26T12:05:00Z", 116)
    tok("seal_r0_same_time", "TSA 1 over the seal of R0, at exactly R0's stated affirmation time", r0, tsa1,
        "2026-09-25T11:00:00Z", 117)
    tok("link_1_early", "TSA 1 over link(1), after R0's affirmation time but before R1's", bytes.fromhex(links["L1"]),
        tsa1, "2026-09-26T09:00:00Z", 118)
    tok("sig_cp_c_at_revocation", "TSA 1 over cp_c's signature value, at exactly the time witness-c-1 was revoked",
        sig_of("cp_c"), tsa1, "2026-10-01T12:00:00Z", 119)
    tok("seal_r0_mislabelled", "TSA 1 over the seal of R0, its messageImprint labelled SHA-512 but holding the "
        "SHA-256 value", r0, tsa1, "2026-09-25T11:05:00Z", 121, hash_label="sha512")
    tok("seal_r0_wrong_content_type", "TSA 1 over the seal of R0, its signed content-type attribute id-data", r0, tsa1,
        "2026-09-25T11:05:00Z", 122, attr_content_type="data")
    tok("seal_r0_other_sid", "signed with TSA 1's key, its signer identifier naming TSA 2's certificate", r0, tsa1,
        "2026-09-25T11:05:00Z", 123, sid_cert_der=certs["tsa-example-2"])
    tok("seal_r0_two_signers", "TSA 1 over the seal of R0, with its SignerInfo given twice", r0, tsa1,
        "2026-09-25T11:05:00Z", 120, signers=2)
    tok("seal_r0_cert_id_sha512", "TSA 1 over the seal of R0, its ESSCertIDv2 made with SHA-512", r0, tsa1,
        "2026-09-25T11:05:00Z", 124, cert_id_hash="sha512")
    tok("seal_r0_cert_id_no_value", "TSA 1 over the seal of R0, its signingCertificateV2 attribute with no value", r0,
        tsa1, "2026-09-25T11:05:00Z", 125, cert_id_values=0)
    tok("seal_r0_not_utc", "TSA 1 over the seal of R0, its genTime written with no time zone (20260925110500)", r0,
        tsa1, "2026-09-25T11:05:00Z", 126, gen_time_text="20260925110500")
    tok("seal_r0_accuracy_negative", "TSA 1 over the seal of R0, with an accuracy of -60 s", r0, tsa1,
        "2026-09-25T11:05:00Z", 127, accuracy_seconds=-60)
    tok("seal_r0_accuracy_too_large", "TSA 1 over the seal of R0, with an accuracy of 10^12 s, past the year 9999",
        r0, tsa1, "2026-09-25T11:05:00Z", 128, accuracy_seconds=10 ** 12)
    tok("seal_r0_accuracy_millis", "TSA 1 over the seal of R0, with an accuracy of 1000 millis (RFC 3161 allows 1 "
        "to 999)", r0, tsa1, "2026-09-25T11:05:00Z", 130, accuracy_millis=1000)
    tok("sig_cp_a_feb30", "TSA 1 over cp_a_feb30's signature value", sig_of("cp_a_feb30"), tsa1,
        "2026-09-27T12:05:00Z", 129)
    tok("seal_r0_sha384_label", "TSA 1 over the seal of R0, its signatureAlgorithm labelled ecdsa-with-SHA384", r0,
        tsa1, "2026-09-25T11:05:00Z", 131, signature_algorithm="sha384_ecdsa")
    # The RSA authority (RFC 9500's testRSA2048), RSA PKCS#1 v1.5 with SHA-256.
    good_rsa = tok("seal_r0_rsa", "the RSA authority over the seal of R0", r0, tsa_rsa, "2026-09-25T11:05:00Z", 301)
    tok("seal_r1_rsa", "the RSA authority over the seal of R1", bytes.fromhex(seal["R1"]), tsa_rsa,
        "2026-09-26T10:05:00Z", 302)
    tok("seal_r0_rsa_pss_label", "the RSA authority over the seal of R0, its PKCS#1 v1.5 signature labelled "
        "RSASSA-PSS", r0, tsa_rsa, "2026-09-25T11:05:00Z", 303, signature_algorithm="rsassa_pss")
    tok("seal_r0_rsa_ecdsa_label", "the RSA authority over the seal of R0, its signature labelled ecdsa-with-SHA256",
        r0, tsa_rsa, "2026-09-25T11:05:00Z", 304, signature_algorithm="sha256_ecdsa")
    tok("seal_r0_rsa_no_cert_id", "the RSA authority over the seal of R0, with no signingCertificateV2 attribute", r0,
        tsa_rsa, "2026-09-25T11:05:00Z", 305, with_cert_id=False)
    # Changed after signing, without re-signing.
    _, signature = make_token(tsa1[0], tsa1[1], r0, when("2026-09-25T11:05:00Z"), 101)
    tokens["seal_r0_bad_signature"] = {"about": "seal_r0 with the last byte of its signature changed",
                                       "imprint_of_hex": r0.hex(),
                                       "token_b64": b64(replace_once(good, signature, flip_last_byte(signature)))}
    tokens["seal_r0_backdated"] = {"about": "seal_r0 with its genTime moved one day earlier after signing, so the "
                                   "messageDigest attribute no longer matches the TSTInfo", "imprint_of_hex": r0.hex(),
                                   "token_b64": b64(replace_once(good, b"20260925110500Z", b"20260924110500Z"))}
    tokens["not_a_token"] = {"about": "bytes that are not a time-stamp token", "imprint_of_hex": r0.hex(),
                             "token_b64": b64(b"not a time-stamp token")}
    _, rsa_signature = make_token(tsa_rsa[0], tsa_rsa[1], r0, when("2026-09-25T11:05:00Z"), 301)
    tokens["seal_r0_rsa_bad_signature"] = {"about": "seal_r0_rsa with the last byte of its signature changed",
                                           "imprint_of_hex": r0.hex(),
                                           "token_b64": b64(replace_once(good_rsa, rsa_signature,
                                                                         flip_last_byte(rsa_signature)))}

    policy = {
        "profile": "dps-anchoring-trust-policy",
        "profile_version": VERSION,
        "policy_ref": "urn:example:trust-policy:verifier-1",
        "tsas": [{"tsa_ref": "tsa-example-1", "holder": "Example time-stamping authority 1 (test only)",
                  "certificate_b64": certificates["tsa-example-1"]["certificate_b64"],
                  "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z"},
                 {"tsa_ref": "tsa-rsa-1", "holder": "Example time-stamping authority 3 (test only; its key is RFC "
                                                    "9500's testRSA2048)",
                  "certificate_b64": certificates[RFC9500_TESTRSA2048_NAME]["certificate_b64"],
                  "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z"}],
        "keys": [],
        "checkpoint_sources": [],
    }

    def key(ref, name, holder, role, not_before, not_after, revoked=None):
        entry = {"key_ref": ref, "holder": holder, "role": role, "algorithm": "Ed25519",
                 "public_key_hex": test_keys[name]["public_key_hex"], "not_before": not_before, "not_after": not_after}
        if revoked:
            entry["revoked_at"], entry["revocation_reason"] = revoked
        policy["keys"].append(entry)

    # One public key has one key reference, one holder and one role: the check refuses a policy that breaks this.
    key("witness-a-1", "witness-a-1", "Example witness A (test only)", "witness", "2026-09-01T00:00:00Z",
        "2027-08-31T23:59:59Z")
    key("witness-b-1", "witness-b-1", "Example witness B (test only)", "witness", "2026-01-01T00:00:00Z",
        "2026-12-31T23:59:59Z", ("2026-09-30T00:00:00Z", "superseded"))
    key("witness-b-2", "witness-b-2", "Example witness B (test only)", "witness", "2026-09-30T00:00:00Z",
        "2027-09-29T23:59:59Z")
    key("witness-c-1", "witness-c-1", "Example witness C (test only)", "witness", "2026-01-01T00:00:00Z",
        "2026-12-31T23:59:59Z", ("2026-10-01T12:00:00Z", "compromised"))
    key("witness-d-1", "witness-d-1", "Example witness D (test only)", "witness", "2026-01-01T00:00:00Z",
        "2026-09-15T23:59:59Z")
    key("issuer-seal-1", "issuer-seal-1", "Example issuer (test only)", "organisation", "2026-01-01T00:00:00Z",
        "2027-12-31T23:59:59Z")
    for ref, holder, refs, chains in (
            ("witness-a", "Example witness A (test only)", ["witness-a-1"], [CHAIN, CHAIN_ACCENTED]),
            ("witness-b", "Example witness B (test only)", ["witness-b-1", "witness-b-2"], [CHAIN]),
            ("witness-c", "Example witness C (test only)", ["witness-c-1"], [CHAIN]),
            ("witness-d", "Example witness D (test only)", ["witness-d-1"], [CHAIN]),
            # Misconfigured on purpose: the issuer's own key listed for a checkpoint source. The role check stops it.
            ("witness-f", "Example issuer (test only)", ["issuer-seal-1"], [CHAIN])):
        policy["checkpoint_sources"].append({"source_ref": ref, "kind": "witness", "holder": holder,
                                             "chain_ids": chains, "key_refs": refs})
    policy["checkpoint_sources"].append({"source_ref": "log-e", "kind": "transparency_log",
                                         "holder": "Example log E (test only)", "chain_ids": [CHAIN]})
    # A SCITT transparency service: its keys in role transparency_service, listed in order; the witness keys whose
    # statements it registers; the chain it is used for. log-e above keeps no format, as in 0.2.0 (K24).
    key("service-s-1", "service-s-1", "Example log S (test only)", "transparency_service", "2026-01-01T00:00:00Z",
        "2027-12-31T23:59:59Z")
    key("service-s-2", "service-s-2", "Example log S (test only)", "transparency_service", "2026-06-01T00:00:00Z",
        "2027-12-31T23:59:59Z")
    # Each witness signs its statements with a key of its own, never the one it signs checkpoints with under the
    # shared rule (RFC 9943 section 9.4: one key, one purpose).
    key(WA, WA, "Example witness A (test only)", "witness", "2026-09-01T00:00:00Z", "2027-08-31T23:59:59Z")
    key(WB, WB, "Example witness B (test only)", "witness", "2026-09-30T00:00:00Z", "2027-09-29T23:59:59Z")
    policy["checkpoint_sources"].append({"source_ref": "log-s", "kind": "transparency_log", "format": "scitt",
                                         "holder": "Example log S (test only)", "chain_ids": [CHAIN],
                                         "key_refs": [WA, WB],
                                         "service_key_refs": ["service-s-1", "service-s-2"]})

    # ---- SCITT signed statements, registered in a small RFC 9162 log kept by the test service
    holder_of = {k["key_ref"]: k["holder"] for k in policy["keys"]}
    statements = {}

    def protected_header(kid, iss, sub, alg=ALG_ED25519, extra=None, no_iss=False):
        claims = {CWT_SUB: sub} if no_iss else {CWT_ISS: iss, CWT_SUB: sub}
        header = {HDR_ALG: alg, HDR_KID: kid.encode("utf-8"), HDR_CWT_CLAIMS: claims}
        header.update(extra or {})
        return cbor2.dumps(header)

    def statement(name, about, key_name, of, *, kid=None, iss=None, sub=None, alg=ALG_ED25519, extra=None,
                  no_iss=False, payload=None, protected=None, rewrite=None):
        """A signed statement whose payload is the checkpoint `of`'s signed bytes under the shared rule (its key_ref
        field set to kid), made by key_name. rewrite(raw, protected, payload, signature) writes the bytes otherwise."""
        cp = checkpoints[of]["checkpoint"]
        kid = key_name if kid is None else kid
        iss = holder_of.get(key_name, "") if iss is None else iss
        sub = cp["chain_id"] if sub is None else sub
        protected = protected_header(kid, iss, sub, alg, extra, no_iss) if protected is None else protected
        payload = signed_bytes(checkpoint_fields(cp, key_ref=kid)) if payload is None else payload
        raw, signature = cose_sign1(ed[key_name], protected, {}, payload)
        if rewrite:
            raw = rewrite(raw, protected, payload, signature)
        statements[name] = {"about": about, "signed_with": key_name,
                            "checkpoint": {k: cp[k] for k in ("chain_id", "count", "head_link", "checkpoint_time")},
                            "key_ref": kid, "statement_b64": b64(raw), "payload_hex": payload.hex(),
                            "to_be_signed_hex": sig_structure(protected, payload).hex(),
                            "carrier": {"format": "scitt", "statement_b64": b64(raw)}}
        return raw

    def tagged(protected, payload, signature):
        return cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, payload, signature]))

    a_claims = cbor2.dumps({CWT_ISS: holder_of[WA], CWT_SUB: CHAIN})
    statement("st_a", "witness-a-scitt-1's statement of cp_a: the payload is cp_a's signed bytes under the shared rule, "
              "the header pinned (alg -19, kid witness-a-scitt-1, CWT claims iss the holder and sub the chain)", WA,
              "cp_a")
    statement("st_b2", "witness-b-scitt-1's statement of cp_b2", WB, "cp_b2")
    statement("st_a_count_4", "witness-a-scitt-1's statement of cp_a_count_4, four entries", WA, "cp_a_count_4")
    statement("st_a_count_2", "witness-a-scitt-1's statement of cp_a_count_2, a filler leaf of the log", WA,
              "cp_a_count_2")
    statement("st_a_chain_2", "witness-a-scitt-1's statement of cp_a_chain_2: for chain 2, which log-s is not configured "
              "for", WA, "cp_a_chain_2")
    statement("st_by_service", "the service's own key signs a statement of cp_a's fields (kid service-s-1): not a "
              "witness", "service-s-1", "cp_a")
    statement("st_a_sub_other", "st_a with sub naming chain 2 while the payload names chain 1", WA, "cp_a",
              sub=CHAIN_2)
    statement("st_a_no_iss", "st_a with no iss claim", WA, "cp_a", no_iss=True)
    statement("st_a_iss_other", "st_a with iss naming someone other than the key's holder", WA, "cp_a",
              iss="Someone else (test only)")
    statement("st_a_alg_8", "st_a with alg -8 (EdDSA), which RFC 9864 deprecates", WA, "cp_a", alg=-8)
    statement("st_a_crit", "st_a with a critical header this check does not know", WA, "cp_a",
              extra={HDR_CRIT: ["urn:example:x"], "urn:example:x": 1})
    statement("st_a_kid_unknown", "st_a signed by witness-a-scitt-1 under a kid the policy does not list", WA,
              "cp_a", kid="witness-z-1")
    statement("st_a_map_payload", "st_a with its payload written as a CBOR map of the fields, not the signed bytes",
              WA, "cp_a", payload=cbor2.dumps({"chain_id": CHAIN, "count": 3, "head_link": links["L2"],
                                                         "checkpoint_time": "2026-09-27T12:00:00Z"}))
    statement("st_a_dup_label", "st_a with the protected header naming label 1 (alg) twice: not read",
              WA, "cp_a",
              protected=b"\xa4" + cbor2.dumps(1) + cbor2.dumps(ALG_ED25519) + cbor2.dumps(1) + cbor2.dumps(ALG_ED25519)
              + cbor2.dumps(4) + cbor2.dumps(WA.encode("utf-8")) + cbor2.dumps(15) + a_claims)
    statement("st_a_long_int", "st_a with alg written as 39 00 12 (-19 in three bytes, not its shortest form 32): "
              "not read", WA, "cp_a",
              protected=b"\xa3" + cbor2.dumps(1) + b"\x39\x00\x12" + cbor2.dumps(4) + cbor2.dumps(WA.encode("utf-8"))
              + cbor2.dumps(15) + a_claims)
    statement("st_a_indefinite", "st_a written as an indefinite-length array: not read", WA, "cp_a",
              rewrite=lambda raw, p, pl, s: b"\xd2\x9f" + cbor2.dumps(p) + b"\xa0" + cbor2.dumps(pl) + cbor2.dumps(s)
              + b"\xff")
    statement("st_a_trailing", "st_a followed by one more byte: not read", WA, "cp_a",
              rewrite=lambda raw, p, pl, s: raw + b"\x00")
    statement("st_a_untagged", "st_a without the COSE_Sign1 tag: not read", WA, "cp_a",
              rewrite=lambda raw, p, pl, s: cbor2.dumps([p, {}, pl, s]))
    statement("st_a_dps_value", "witness-a-1's statement of cp_a with cp_a's own signature under the shared rule in place "
              "of the COSE signature: same key, same fields, but the two formats' bytes differ, so it does not verify",
              "witness-a-1", "cp_a",
              rewrite=lambda raw, p, pl, s: tagged(p, pl, base64.b64decode(
                  checkpoints["cp_a"]["checkpoint"]["signature"]["value_b64"])))
    # A statement made with witness-a-1, the key that signs checkpoints under the shared rule: one key for two purposes,
    # which the check refuses (K133); its COSE signature also serves the reverse direction below.
    statement("st_a_shared_key", "witness-a-1's statement of cp_a: made with the key witness-a-1 signs checkpoints "
              "with under the shared rule", "witness-a-1", "cp_a")
    # The reverse: a plain checkpoint carrying a COSE signature by its own key over its own fields.
    reverse = copy.deepcopy(checkpoints["cp_a"])
    reverse["about"] = "cp_a with st_a_shared_key's COSE signature as its signature value: same key, same fields, " \
                       "made over the Sig_structure, not the shared rule's bytes, so it does not verify"
    reverse["checkpoint"]["signature"]["value_b64"] = b64(cbor2.loads(
        base64.b64decode(statements["st_a_shared_key"]["statement_b64"])).value[3])
    reverse["signature_made_over_hex"] = statements["st_a_shared_key"]["to_be_signed_hex"]
    checkpoints["cp_a_cose_value"] = reverse

    # The log: five leaves, each a statement's bytes as registered; st_a is leaf 1, st_b2 leaf 2, st_a_count_4 leaf 4.
    log_order = ["st_a_count_2", "st_a", "st_b2", "st_a_chain_2", "st_a_count_4"]
    leaf_hashes = [leaf_hash(base64.b64decode(statements[n]["statement_b64"])) for n in log_order]
    root = merkle_root(leaf_hashes)

    def receipt(name, of, about, service_key, *, index=None, proof=None, kid=None, alg=ALG_ED25519,
                vds=VDS_RFC9162_SHA256, no_proof=False, break_path=False, signed_root=None):
        """A receipt (RFC 9942) for the statement `of`: a COSE_Sign1 by the service over the root, its payload
        detached, the inclusion proof in the unprotected header. The vector keeps the statement's members.
        signed_root: the root the service signs, where it is not the five-leaf log's."""
        index = log_order.index(of) if index is None else index
        path = inclusion_path(leaf_hashes, index)
        if break_path:
            path = [bytes([path[0][0] ^ 0x01]) + path[0][1:]] + path[1:]
        proof = [len(leaf_hashes), index, path] if proof is None else proof
        protected = cbor2.dumps({HDR_ALG: alg, HDR_KID: (kid or service_key).encode("utf-8"), HDR_VDS: vds})
        unprotected = {} if no_proof else {HDR_VDP: {VDP_INCLUSION_PROOFS: [cbor2.dumps(proof)]}}
        signed = root if signed_root is None else signed_root
        raw, _ = cose_sign1(ed[service_key], protected, unprotected, signed, detached=True)
        entry = copy.deepcopy(statements[of])
        entry.update(about=about, receipt_signed_with=service_key, receipt_b64=b64(raw), tree_size=proof[0],
                     leaf_index=proof[1], root_hex=signed.hex(),
                     leaf_hash_hex=leaf_hash(base64.b64decode(entry["statement_b64"])).hex(),
                     receipt_to_be_signed_hex=sig_structure(protected, signed).hex())
        entry["carrier"]["receipt_b64"] = b64(raw)
        statements[name] = entry

    for n in log_order:
        receipt(n, n, statements[n]["about"] + "; with the service's receipt (service-s-1), leaf "
                f"{log_order.index(n)} of {len(log_order)}", "service-s-1")
    statements["st_a_no_receipt"] = {**copy.deepcopy(statements["st_a"]), "about": "st_a without a receipt"}
    for k in ("receipt_b64", "receipt_signed_with", "tree_size", "leaf_index", "root_hex", "leaf_hash_hex",
              "receipt_to_be_signed_hex"):
        statements["st_a_no_receipt"].pop(k, None)
    statements["st_a_no_receipt"]["carrier"].pop("receipt_b64", None)
    receipt("st_a_receipt_other", "st_a", "st_a with the receipt of leaf 2 (st_b2): a proof for another statement",
            "service-s-1", index=2)
    receipt("st_a_path_broken", "st_a", "st_a with one bit of the first sibling hash changed: the path does not "
            "reach the root", "service-s-1", break_path=True)
    receipt("st_a_receipt_s2", "st_a", "st_a with a receipt by the service's second key, service-s-2, listed too",
            "service-s-2")
    receipt("st_a_receipt_by_witness", "st_a", "st_a with a receipt signed by witness-a-1: a witness key, not a "
            "service key", "witness-a-1")
    receipt("st_a_receipt_unknown_key", "st_a", "st_a with a receipt by service-z-1, a key the policy does not list",
            "service-z-1")
    receipt("st_a_receipt_small_tree", "st_a", "st_a with a proof naming tree size 1 for leaf 1", "service-s-1",
            proof=[1, 1, []])
    receipt("st_a_receipt_no_proof", "st_a", "st_a with a receipt carrying no inclusion proof", "service-s-1",
            no_proof=True)
    receipt("st_a_receipt_other_vds", "st_a", "st_a with a receipt naming verifiable data structure 2, which this "
            "check does not know", "service-s-1", vds=2)
    receipt("st_a_receipt_alg_8", "st_a", "st_a with a receipt under alg -8", "service-s-1", alg=-8)
    receipt("st_a_receipt_one_leaf", "st_a", "st_a with a proof [1, 1, []] and a receipt signed over st_a's own leaf "
            "hash, the root of a one-leaf log: a leaf index equal to the tree size, with a path that otherwise fits",
            "service-s-1", proof=[1, 1, []], signed_root=leaf_hash(base64.b64decode(statements["st_a"]["statement_b64"])))
    # Payloads stating a checkpoint_time in another form than the one signed as text: signed by witness-a-scitt-1 over
    # cp_a's other fields. The checkpoint schema refuses these times, so the check fails the signature.
    for name, other_time in (("st_a_time_offset", "2026-09-27T17:00:00+05:00"),
                             ("st_a_time_fraction", "2026-09-27T12:00:00.000+00:00"),
                             ("st_a_time_basic", "20260927T120000Z")):
        statement(name, f"st_a whose payload states checkpoint_time {other_time}, a form the checkpoint schema "
                  "refuses", WA, "cp_a",
                  payload=signed_bytes(checkpoint_fields({**checkpoints["cp_a"]["checkpoint"],
                                                          "checkpoint_time": other_time}, key_ref=WA)))
    statement("st_a_chain_empty", "st_a whose payload states an empty chain_id, which the checkpoint schema refuses",
              WA, "cp_a", payload=signed_bytes(checkpoint_fields({**checkpoints["cp_a"]["checkpoint"], "chain_id": ""},
                                                                 key_ref=WA)))
    statement("st_a_kid_empty", "st_a with an empty kid, its payload's key_ref empty too", WA, "cp_a", kid="",
              payload=signed_bytes(checkpoint_fields(checkpoints["cp_a"]["checkpoint"], key_ref="")))
    statement("st_a_kid_long", "st_a with a kid of 300 characters, its payload's key_ref the same", WA, "cp_a",
              kid="k" * 300)
    # Carriers too large or too deep to keep as full statement vectors: each is only what a verifier would hold.
    deep = b"\xd2" + b"\x81" * 990 + b"\x00"
    long_iss, _ = cose_sign1(ed[WA], protected_header(WA, "x" * 70000, CHAIN), {},
                             signed_bytes(checkpoint_fields(checkpoints["cp_a"]["checkpoint"], key_ref=WA)))
    carriers = {
        "deep_nesting": {"about": "a tagged item nesting 990 one-item arrays: well formed, and far deeper than any "
                                  "statement", "format": "scitt", "statement_b64": b64(deep)},
        "long_iss": {"about": "witness-a-scitt-1's statement of cp_a with an iss of 70,000 characters, so that the "
                              "protected header and its Sig_structure length need four bytes",
                     "format": "scitt", "statement_b64": b64(long_iss)},
    }
    scitt = {
        "about": "A test SCITT transparency service (RFC 9943), test keys only. A statement is a tagged COSE_Sign1 "
                 "(RFC 9052) by a witness key whose payload is the checkpoint's signed bytes under the shared rule, "
                 "with its key_ref field equal to kid; the protected header has alg -19 (Ed25519, RFC 9864), kid, "
                 "and the CWT claims (RFC 9597, label 15) iss, the key's holder, and sub, the chain. A receipt (RFC "
                 "9942) is a tagged COSE_Sign1 by a service key over the RFC 9162 SHA-256 tree's root, its payload "
                 "detached, with the verifiable data structure (label 395, value 1) in the protected header and "
                 "the inclusion proof [tree-size, leaf-index, path] (label 396, key -1) in the unprotected one. A "
                 "leaf's data is the statement's bytes as registered, tag included; its hash is SHA-256(0x00 || data). "
                 "to_be_signed_hex is the Sig_structure each signature was made over.",
        "leaf_rule": "SHA-256(0x00 || statement bytes as registered)",
        "log": {"leaves": log_order, "leaf_hashes_hex": [h.hex() for h in leaf_hashes], "root_hex": root.hex()},
        "statements": statements,
        "carriers": carriers,
    }

    def subject_signature(name):
        c = checkpoints[name]["checkpoint"]
        return {"kind": "signature", "of": {"assertion": "checkpoint", "key_ref": c["signature"]["key_ref"],
                                            "chain_id": c["chain_id"], "count": c["count"]},
                "value_b64": c["signature"]["value_b64"]}

    def timestamp(subject, token_name, tsa_ref="tsa-example-1"):
        return {"assertion": "timestamp", "subject": subject, "hash_algorithm": "SHA-256", "tsa_ref": tsa_ref,
                "token_b64": tokens[token_name]["token_b64"]}

    attachment = {
        "profile": PROFILE,
        "profile_version": VERSION,
        "chain_id": CHAIN,
        "timestamps": [
            timestamp({"kind": "seal", "decision_id": "DR-2099-001", "value_hex": seal["R0"]}, "seal_r0"),
            timestamp({"kind": "chain_link", "chain_id": CHAIN, "sequence": 2, "value_hex": links["L2"]}, "link_2"),
            timestamp(subject_signature("cp_c"), "sig_cp_c_before"),
        ],
        "checkpoint_refs": [{"source_ref": s, "chain_id": CHAIN} for s in ("witness-a", "witness-b", "witness-c")],
    }
    timestamp_assertions = {
        "seal_r1": timestamp({"kind": "seal", "decision_id": "DR-2099-002", "value_hex": seal["R1"]}, "seal_r1"),
        "sig_cp_b": timestamp(subject_signature("cp_b"), "sig_cp_b"),
        "sig_cp_c_after": timestamp(subject_signature("cp_c"), "sig_cp_c_after"),
        "sig_cp_c_boundary": timestamp(subject_signature("cp_c"), "sig_cp_c_boundary"),
        "sig_cp_c_early": timestamp(subject_signature("cp_c"), "sig_cp_c_early"),
        "sig_cp_c_at_revocation": timestamp(subject_signature("cp_c"), "sig_cp_c_at_revocation"),
        "link_1_early": timestamp({"kind": "chain_link", "chain_id": CHAIN, "sequence": 1, "value_hex": links["L1"]},
                                  "link_1_early"),
        "sig_cp_a_feb30": timestamp(subject_signature("cp_a_feb30"), "sig_cp_a_feb30"),
        "seal_r0_rsa": timestamp({"kind": "seal", "decision_id": "DR-2099-001", "value_hex": seal["R0"]}, "seal_r0_rsa",
                                 tsa_ref="tsa-rsa-1"),
    }
    context = {
        "chain_id": CHAIN,
        "export": "full",
        "checkpoints": [{"checkpoint": n, "obtained_from": "configured_source", "source_ref": s}
                        for n, s in (("cp_a", "witness-a"), ("cp_b", "witness-b"), ("cp_c", "witness-c"))],
    }

    every_check = {k: "verified" for k in ("token", "message_imprint", "subject_bytes", "message_digest",
                                           "tsa_signature", "signer_certificate", "tsa_state")}

    def ts_result(i, subject, at, stated, stated_in):
        shown = {k: v for k, v in subject.items() if k not in ("value_hex", "value_b64")}
        return {"timestamp_index": i, "subject": shown, "status": "verified", "tsa_ref": "tsa-example-1",
                "reference_source": "trust_policy", "gen_time": at, "existed_no_later_than": at,
                "checks": dict(every_check),
                "issuer_time": {"status": "verified", "stated": stated, "stated_in": stated_in,
                                "consistency": "consistent"}}

    def cp_result(i, name, source, time_basis, at, covered, not_covered, revocation=None, timestamp_index=None):
        c = checkpoints[name]["checkpoint"]
        key_state = {"status": "verified", "key_ref": c["signature"]["key_ref"]}
        if revocation:
            key_state["revocation_reason"] = revocation
        key_state.update({"time_basis": time_basis, "time": at})
        if timestamp_index is not None:
            key_state["timestamp_index"] = timestamp_index
        return {"checkpoint_index": i, "obtained_from": "configured_source", "source_ref": source, "status": "verified",
                "checkpoint": {k: c[k] for k in ("chain_id", "count", "head_link", "checkpoint_time")},
                "independence": {"status": "verified"},
                "signature": {"status": "verified", "key_ref": c["signature"]["key_ref"],
                              "reference_source": "trust_policy"},
                "key_state": key_state,
                "comparison": {"status": "verified", "covered_count": covered, "not_covered_indexes": not_covered}}

    ts = attachment["timestamps"]
    report = {
        "profile": "dps-anchoring-report",
        "profile_version": VERSION,
        "trust_policy_ref": policy["policy_ref"],
        "trust_policy": {"status": "verified"},
        "attachment_digest": sha256(compact(attachment)).hex(),
        "export_digest": sha256(compact(exports["full"])).hex(),
        "export_entry_count": 3,
        "chain_id": CHAIN,
        "timestamp_count": 3,
        "timestamps": [
            ts_result(0, ts[0]["subject"], "2026-09-25T11:05:00Z", "2026-09-25T11:00:00Z",
                      "affirmation_record.timestamp"),
            ts_result(1, ts[1]["subject"], "2026-09-27T10:30:00Z", "2026-09-27T10:00:00Z",
                      "affirmation_record.timestamp"),
            ts_result(2, ts[2]["subject"], "2026-09-27T12:05:00Z", "2026-09-27T12:00:00Z", "checkpoint_time"),
        ],
        "checkpoint_count": 3,
        "checkpoints": [
            cp_result(0, "cp_a", "witness-a", "stated_time", "2026-09-27T12:00:00Z", 3, []),
            cp_result(1, "cp_b", "witness-b", "stated_time", "2026-09-26T12:00:00Z", 2, [2], revocation="superseded"),
            cp_result(2, "cp_c", "witness-c", "independent_timestamp", "2026-09-27T12:05:00Z", 3, [],
                      revocation="compromised", timestamp_index=2),
        ],
        "scope_of_conclusion": {
            "covers": "supplied_export_and_attachment_only",
            "not_assessed": ["legal_requirements", "conformance_level", "truth_of_record_content", "time_of_decision",
                             "earliest_existence", "events_never_recorded", "content_reviewed_by_witness"],
        },
    }

    # ---- checkpoints carried beside the export: the result a verifier reports for cp_a so carried (after the three
    # from sources, so at index 3), and a wrong one for the pairing cases (cp_a_count_4 reported with its prefix
    # verified, though the full export has three entries)
    def beside_result(i, name, prefix):
        c = checkpoints[name]["checkpoint"]
        return {"checkpoint_index": i, "obtained_from": "beside_export", "status": "failed",
                "checkpoint": {k: c[k] for k in ("chain_id", "count", "head_link", "checkpoint_time")},
                "independence": {"status": "failed", "findings": ["carried beside the export: the issuer chose which "
                                                                  "checkpoint to carry, so it is never independent"]},
                "signature": {"status": "verified", "key_ref": c["signature"]["key_ref"],
                              "reference_source": "trust_policy"},
                "key_state": {"status": "verified", "key_ref": c["signature"]["key_ref"], "time_basis": "stated_time",
                              "time": c["checkpoint_time"]},
                "comparison": {"status": "not_checked"},
                "prefix": prefix, "freshness": "not_established"}

    # ---- OpenTimestamps proofs: the real one, and a synthetic chain for every rule
    ots_ts, syn_headers = {}, {}
    nonce = sha256(b"dps-anchoring test calendar nonce")[:16]
    sibling = sha256(b"dps-anchoring test calendar sibling")
    subj_r0 = {"kind": "seal", "decision_id": "DR-2099-001", "value_hex": seal["R0"]}
    subj_r1 = {"kind": "seal", "decision_id": "DR-2099-002", "value_hex": seal["R1"]}
    subj_l2 = {"kind": "chain_link", "chain_id": CHAIN, "sequence": 2, "value_hex": links["L2"]}
    subj_c = subject_signature("cp_c")
    value_of = {id(subj_r0): bytes.fromhex(seal["R0"]), id(subj_r1): bytes.fromhex(seal["R1"]),
                id(subj_l2): bytes.fromhex(links["L2"]), id(subj_c): base64.b64decode(subj_c["value_b64"])}
    steps = [("prepend", nonce), ("sha256",), ("append", sibling), ("sha256",)]

    def bitcoin(height):
        return lambda msg: [("att", OTS_BITCOIN, ots_varuint(height))]

    def block(height, root, time_text):
        hdr = synthetic_header(root, height, time_text)
        syn_headers[str(height)] = {"block_hash": sha256(sha256(hdr))[::-1].hex(), "header_hex": hdr.hex()}

    def ots(name, about, subject, proof_bytes):
        ots_ts[name] = {"about": about, "timestamp": {"assertion": "timestamp", "subject": subject,
                                                      "hash_algorithm": "SHA-256", "format": "opentimestamps",
                                                      "proof_b64": b64(proof_bytes)}}

    d_r0 = sha256(value_of[id(subj_r0)])
    items, root = ots_path(d_r0, steps, bitcoin(800001))
    block(800001, root, "2026-09-27T13:00:00Z")
    good_r0 = ots_proof(d_r0, ots_tree(items))
    ots("seal_r0", "a synthetic proof from the SHA-256 of R0's seal to block 800001", subj_r0, good_r0)
    d_l2 = sha256(value_of[id(subj_l2)])
    items, root = ots_path(d_l2, steps, bitcoin(800002))
    block(800002, root, "2026-09-27T14:00:00Z")
    ots("link_2", "a synthetic proof from the SHA-256 of link(2) to block 800002", subj_l2, ots_proof(d_l2, ots_tree(items)))
    d_c = sha256(value_of[id(subj_c)])
    items, root = ots_path(d_c, steps, bitcoin(800003))
    block(800003, root, "2026-09-27T15:00:00Z")
    ots("sig_cp_c", "a synthetic proof from the SHA-256 of cp_c's signature value to block 800003", subj_c,
        ots_proof(d_c, ots_tree(items)))
    # Two Bitcoin attestations: the same digest to block 800001 and, by another path, to block 800004.
    items_b, root_b = ots_path(d_r0, [("append", nonce), ("sha256",)], bitcoin(800004))
    block(800004, root_b, "2026-09-27T16:00:00Z")
    items_a, _ = ots_path(d_r0, steps, bitcoin(800001))
    ots("seal_r0_two_blocks", "R0's seal to block 800001 and, by another path, to block 800004", subj_r0,
        ots_proof(d_r0, ots_tree(items_a + items_b)))
    ots("seal_r0_unknown_attestation", "R0's seal with an attestation of an unknown kind beside the path to block "
        "800001", subj_r0, ots_proof(d_r0, ots_tree([("att", bytes.fromhex("0102030405060708"), b"x")] + items_a)))
    items, _ = ots_path(d_r0, steps, lambda msg: [("att", OTS_PENDING, ots_varbytes(b"https://calendar.example"))])
    ots("seal_r0_pending", "R0's seal to a pending attestation only", subj_r0, ots_proof(d_r0, ots_tree(items)))
    ots("seal_r0_ripemd160", "R0's seal through ripemd160 first, as some older proofs start", subj_r0,
        ots_proof(d_r0, ots_tree([("op", 0x03, b"", [("att", OTS_BITCOIN, ots_varuint(800001))])])))
    ots("seal_r0_trailing", "the synthetic proof of R0's seal with one byte after it", subj_r0, good_r0 + b"\x00")
    ots("seal_r0_version_long", "the same with its version written 81 00, not in its shortest form", subj_r0,
        OTS_MAGIC + b"\x81\x00" + good_r0[len(OTS_MAGIC) + 1:])
    ots("seal_r0_magic", "the same with one byte of its magic changed", subj_r0,
        OTS_MAGIC[:-1] + b"\x00" + good_r0[len(OTS_MAGIC):])
    ots("seal_r0_version_2", "the same labelled version 2", subj_r0,
        OTS_MAGIC + ots_varuint(2) + good_r0[len(OTS_MAGIC) + 1:])
    items, _ = ots_path(d_r0, [("sha256",)] * 300, bitcoin(800001))
    ots("seal_r0_deep", "R0's seal through 300 nested operations, over the limit of 256", subj_r0,
        ots_proof(d_r0, ots_tree(items)))
    items, _ = ots_path(d_r0, steps, lambda msg: [("att", OTS_BITCOIN, b"\x80" * 19 + b"\x01")])
    ots("seal_r0_height_20_bytes", "R0's seal to a height written as a 20-byte varint", subj_r0,
        ots_proof(d_r0, ots_tree(items)))
    items, _ = ots_path(d_r0, steps, bitcoin(2 ** 60))
    ots("seal_r0_height_big", "R0's seal to height 2^60, beyond what a report can carry", subj_r0,
        ots_proof(d_r0, ots_tree(items)))
    items, _ = ots_path(d_r0, [("append", b"\x00" * 5000), ("sha256",)], bitcoin(800001))
    ots("seal_r0_long_argument", "R0's seal with an append argument of 5,000 bytes, over the limit of 4,096", subj_r0,
        ots_proof(d_r0, ots_tree(items)))
    ots("seal_r0_same_operation_twice", "R0's seal with sha256 written twice at one point", subj_r0,
        ots_proof(d_r0, ots_tree([("op", 0x08, b"", [("att", OTS_BITCOIN, ots_varuint(800001))]),
                                  ("op", 0x08, b"", [("att", OTS_BITCOIN, ots_varuint(800002))])])))
    d_r1 = sha256(value_of[id(subj_r1)])
    items, root = ots_path(d_r1, steps, bitcoin(800005))
    block(800005, root, "2026-09-27T17:00:00Z")
    ots("seal_r1_as_r0", "a proof from the SHA-256 of R1's seal, presented for R0's seal", subj_r0,
        ots_proof(d_r1, ots_tree(items)))
    ots("token_as_proof", "an RFC 3161 token (seal_r0's) presented as an OpenTimestamps proof", subj_r0,
        base64.b64decode(tokens["seal_r0"]["token_b64"]))
    ots("real_r0", "the REAL proof: R0's seal, as the calendars alice and bob put it in Bitcoin blocks 972840 and "
        "972842", subj_r0, base64.b64decode("".join(REAL_OTS_PROOF_B64)))
    reversed_800001 = dict(syn_headers["800001"])
    hdr = bytes.fromhex(reversed_800001["header_hex"])
    hdr = hdr[:36] + hdr[36:68][::-1] + hdr[68:]
    opentimestamps = {
        "about": "OpenTimestamps proofs. The real one (real_r0) is described where REAL_OTS_PROOF_B64 is set in "
                 "generate_vectors.py; its headers are mainnet's, as two explorers gave them. Every other proof leads "
                 "to a synthetic header (synthetic_header): a test block with no proof of work, holding the proof's "
                 "result as its Merkle root in the header's own byte order. A header set is what a verifier holds "
                 "from its own source; header_sources is the policy entry naming that source.",
        "header_sources": [{"source_ref": "bitcoin-node-v", "network": "mainnet", "kind": "node",
                            "holder": "Example verifier (test only)"}],
        "headers": {"mainnet": REAL_OTS_HEADERS, "synthetic": syn_headers,
                    "synthetic_reversed": {"800001": {"block_hash": sha256(sha256(hdr))[::-1].hex(),
                                                      "header_hex": hdr.hex()}}},
        "timestamps": ots_ts,
        "rfc3161_with_ots_proof": {"about": "an RFC 3161 timestamp whose token is the synthetic OpenTimestamps proof "
                                            "of R0's seal", "timestamp": {**timestamp(subj_r0, "seal_r0"),
                                                                   "token_b64": b64(good_r0)}},
    }

    beside_results = {
        "about": "Checkpoint results for a checkpoint carried beside the export, for the pairing cases: cp_a as a "
                 "verifier reports it (index 3, after the three from sources), and cp_a_count_4 reported with its "
                 "prefix verified, which the full export (three entries) does not support.",
        "cp_a": beside_result(3, "cp_a", {"status": "verified", "covered_count": 3, "not_covered_indexes": [],
                                          "time_basis": "stated_time", "time": "2026-09-27T12:00:00Z"}),
        "cp_a_count_4_reported_verified": beside_result(3, "cp_a_count_4", {
            "status": "verified", "covered_count": 4, "not_covered_indexes": [], "time_basis": "stated_time",
            "time": "2026-09-29T12:00:00Z"}),
    }
    # st_a carried beside the export, as a verifier reports it: cp_a's result, with the statement's format, its
    # receipt (service-s-1, leaf 1 of 5) and the log's consistency not checked.
    beside_results["st_a"] = {**copy.deepcopy(beside_results["cp_a"]), "format": "scitt", "attachment_index": 0,
                              "receipt": {"status": "verified", "service_key_ref": "service-s-1", "tree_size": 5,
                                          "leaf_index": 1},
                              "log_consistency": {"status": "not_checked"}}
    beside_results["about"] += (" st_a is cp_a's statement carried beside the export with its receipt, as a verifier "
                                "reports it: format scitt, the receipt verified (service-s-1, leaf 1 of 5), the log's "
                                "consistency not checked.")
    # An attachment carrying cp_a with its count written twice, 5 first and 3 last: a reader keeping the last member
    # reads cp_a, whose signature verifies; one keeping the first reads a checkpoint of five entries, whose does not.
    carrying = {"profile": PROFILE, "profile_version": VERSION, "chain_id": CHAIN,
                "checkpoints": [checkpoints["cp_a"]["checkpoint"]]}
    written = compact(carrying)
    if written.count(b'"count":3') != 1:
        raise ValueError("the carried checkpoint does not write its count once")
    twice = written.replace(b'"count":3', b'"count":5,"count":3', 1)
    if json.loads(twice) != carrying:
        raise ValueError("a reader keeping the last member does not find the carried checkpoint")
    texts = {"checkpoint_count_twice": {
        "about": "An attachment carrying cp_a with its count named twice, 5 first and 3 last. Not read: a reader keeping "
                 "the last member reads cp_a, whose signature verifies; one keeping the first reads five entries.",
        "attachment_text": twice.decode("utf-8"), "differs_at": "/checkpoints/0/count",
        "first_member": 5, "last_member": 3}}

    return {
        "about": "Generated by generate_vectors.py; do not edit by hand. TEST KEYS ONLY: every key but one is derived "
                 "from its seed_text (seed = SHA-256 of the text; Ed25519: the seed is the private key; ECDSA P-256: "
                 "the scalar is the seed as a big-endian integer mod (n - 1), plus 1); the RSA key is the 2048-bit "
                 "test key RFC 9500, section 2.1, publishes as testRSA2048, given here by its public modulus and "
                 "exponent. Records R0 to R2 and links L0 to "
                 "L2 are those of the portable verification cases. Exports are portable verification 0.3.0 exports, "
                 "their entries unsigned. "
                 "Each checkpoint names the test key it was signed with (signed_with) and gives signed_bytes_hex, "
                 "the bytes a verifier builds from it under the shared rule, and, where the key signed something "
                 "else, signature_made_over_hex. cp_accented's chain_id is not ASCII: its length prefix counts 19 "
                 "UTF-8 bytes, not 17 characters. Each token gives "
                 "imprint_of_hex, the bytes its messageImprint is the SHA-256 of. A document's bytes as received "
                 "(for attachment_digest and export_digest) are its JSON with no whitespace, in UTF-8.",
        "test_keys": test_keys,
        "records": {k: {"text": RECORDS[k], "seal_hash": seal[k]} for k in RECORD_ORDER},
        "chain": {"about": "link(i) = SHA-256(link(i-1) || seal(i)), with 32 zero bytes before the first entry. "
                           "L0 to L3 chain R0, R1, R2, R4; L1x and L2x chain R0, R1x, R2.", "links": links},
        "exports": exports,
        "tsa_certificates": certificates,
        "tokens": tokens,
        "checkpoints": checkpoints,
        "trust_policy": policy,
        "base_attachment": attachment,
        "timestamp_assertions": timestamp_assertions,
        "base_context": context,
        "base_report": report,
        "beside_results": beside_results,
        "texts": texts,
        "scitt": scitt,
        "opentimestamps": opentimestamps,
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
