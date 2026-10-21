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
                 "issuer-seal-1")
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
            (key_ref or cp["signature"]["key_ref"]).encode("utf-8"), cp["chain_id"].encode("utf-8"),
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
    """Portable verification 0.2.0 exports (unsigned entries, as 0.1.0 wrote them). Each entry keeps the chain fields
    it was exported with."""
    L = links
    as_chained = {"R0": (0, None), "R1": (1, L["L0"]), "R2": (2, L["L1"]), "R4": (3, L["L2"])}

    def export(names, chained=None):
        chained = chained or as_chained
        return {"profile": "dps-portable-verification", "profile_version": "0.2.0",
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
    cp("cp_d", "witness-d-1, stated after the key's not_after", "witness-d-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z")
    cp("cp_x", "witness-x-1, a key the policy does not list", "witness-x-1", CHAIN, 3, "L2", "2026-09-27T12:00:00Z")
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
                 "L2 are those of the portable verification cases. Exports are portable verification 0.2.0 exports, "
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
