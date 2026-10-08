"""
Omni License Signing Module (v2)
=================================
Menambahkan tanda tangan kriptografis Ed25519 ke respons /api/validate
supaya client bisa membuktikan respons benar-benar dari server asli,
bukan fake server / MITM.

Canonical string (HARUS MATCH byte-for-byte dengan license_verify.cpp):

    token|valid|permanent|giveaway|expiresAfter|owner|hwid|tier|issuedAt|nonce

SETUP (sekali saja):
    pip install pynacl
    python server_signing.py --genkey

    -> print PRIVATE_KEY_HEX dan PUBLIC_KEY_HEX
    -> simpan PRIVATE_KEY_HEX sebagai SIGN_PRIVATE_KEY di .env
    -> copy PUBLIC_KEY_HEX ke license_verify.h (client C++)
"""
import os
import sys
import time
import json
from aiohttp import web

try:
    from nacl.signing import SigningKey
except ImportError:
    print("Perlu install pynacl dulu: pip install pynacl", file=sys.stderr)
    raise

# ============================================================
#  KEY LOADING
# ============================================================
_SIGNING_KEY = None


def _load_signing_key() -> SigningKey:
    global _SIGNING_KEY
    if _SIGNING_KEY is not None:
        return _SIGNING_KEY

    hex_key = os.getenv("SIGN_PRIVATE_KEY", "").strip()
    if not hex_key:
        raise RuntimeError(
            "SIGN_PRIVATE_KEY env var tidak ditemukan. "
            "Jalankan `python server_signing.py --genkey` dulu, "
            "lalu set env var-nya sebelum start bot."
        )
    try:
        _SIGNING_KEY = SigningKey(bytes.fromhex(hex_key))
    except Exception as ex:
        raise RuntimeError(f"SIGN_PRIVATE_KEY tidak valid (harus 64 hex char): {ex}")
    return _SIGNING_KEY


# ============================================================
#  CANONICAL STRING
# ============================================================
# JANGAN ubah urutan/field tanpa update license_verify.cpp juga.
#
#   token|valid|permanent|giveaway|expiresAfter|owner|hwid|tier|issuedAt|nonce
#
# - valid, permanent, giveaway -> "1" atau "0"
# - expiresAfter -> integer epoch MS, "0" kalau permanent
# - owner        -> discord_id (string)
# - hwid         -> bound HWID, atau "" kalau belum bind
# - tier         -> "premium" | "free" | ""
# - issuedAt     -> epoch DETIK saat response dibuat
# - nonce        -> echo dari query ?nonce=, atau "" kalau tidak dikirim

def _canonical_string(token: str, valid: bool, permanent: bool,
                       giveaway: bool, expires_after: int,
                       owner: str, hwid: str, tier: str,
                       issued_at: int, nonce: str) -> str:
    return "|".join([
        token,
        "1" if valid else "0",
        "1" if permanent else "0",
        "1" if giveaway else "0",
        str(int(expires_after)),
        owner or "",
        hwid or "",
        tier or "",
        str(int(issued_at)),
        nonce or "",
    ])


def sign_fields(token: str, valid: bool, permanent: bool, giveaway: bool,
                 expires_after: int, owner: str, hwid: str, tier: str,
                 issued_at: int, nonce: str) -> str:
    """Return signature hex string (128 hex char = 64 bytes)."""
    sk = _load_signing_key()
    canonical = _canonical_string(token, valid, permanent, giveaway,
                                   expires_after, owner, hwid, tier,
                                   issued_at, nonce)
    sig = sk.sign(canonical.encode("utf-8")).signature
    return sig.hex()


# ============================================================
#  BUILDING A SIGNED RESPONSE
# ============================================================
def build_signed_validate_response(token: str, *,
                                    valid: bool,
                                    permanent: bool = False,
                                    giveaway: bool = False,
                                    expires_after: int = 0,
                                    owner: str = "",
                                    hwid: str = "",
                                    tier: str = "premium",
                                    nonce: str = "",
                                    status: int = 200) -> web.Response:
    """
    Ganti web.json_response({...}) untuk SEMUA cabang valid=True.

    Contoh:
        return build_signed_validate_response(
            token,
            valid=True,
            permanent=True,
            expires_after=0,
            owner=str(row["discord_id"]),
            hwid=bound_hwid,
            tier="premium",
            nonce=req.rel_url.query.get("nonce", ""),
        )
    """
    issued_at = int(time.time())
    sig = sign_fields(token, valid, permanent, giveaway,
                       expires_after, owner, hwid, tier,
                       issued_at, nonce)

    payload = {
        "valid": valid,
        "token": token,
        "info": {
            "owner": owner,
            "expiresAfter": int(expires_after),
            "permanent": bool(permanent),
            "giveaway": bool(giveaway),
            "hwid": hwid,
            "tier": tier,
        },
        "issuedAt": issued_at,
        "nonce": nonce,
        "sig": sig,
    }
    return web.json_response(payload, status=status)


# ============================================================
#  CLI: generate keypair
# ============================================================
def _genkey():
    sk = SigningKey.generate()
    vk = sk.verify_key
    print("=" * 64)
    print("1) SIMPAN private key ini sebagai SIGN_PRIVATE_KEY di .env")
    print("   JANGAN pernah taruh di client / binary / git.")
    print("=" * 64)
    print("SIGN_PRIVATE_KEY=" + sk.encode().hex())
    print()
    print("=" * 64)
    print("2) Hardcode public key ini (64 hex char) di license_verify.h")
    print("   Ini boleh publik -- tidak rahasia.")
    print("=" * 64)
    print("PUBLIC_KEY_HEX = " + vk.encode().hex())
    print()
    print("=" * 64)
    print("Contoh .env lengkap:")
    print("=" * 64)
    print("DISCORD_TOKEN=your_discord_token_here")
    print("SERVER_PORT=10750")
    print("SIGN_PRIVATE_KEY=" + sk.encode().hex())


if __name__ == "__main__":
    if "--genkey" in sys.argv:
        _genkey()
    else:
        print("Usage: python server_signing.py --genkey")
