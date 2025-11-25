import hashlib

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    def pub_raw(priv):
        return priv.public_key().public_bytes_raw()
except Exception:
    # fallback for older cryptography
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    def pub_raw(priv):
        return priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

from ecdsa import NIST256p, NIST384p, NIST521p, SigningKey, ellipticcurve
from ecdsa.ellipticcurve import Point
from ecdsa.util import sigencode_der, sigdecode_der

class AnaState:
    """Per-connection anamorphic state (ephemeral)."""
    def __init__(self):
        self.a_priv = None   # client private (x25519)
        self.b_priv = None   # server private (x25519)
        self.A = None        # client public (32B)
        self.B = None        # server public (32B)
        self.dk = None       # shared (32B)


def to_bytes_strict(x) -> bytes:
    """Return bytes; raise if impossible."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    # Some libs return memoryview or array('B') – both work with bytes()
    try:
        return bytes(x)
    except Exception as e:
        raise TypeError(f"expected bytes-like, got {type(x).__name__}") from e


# --- client side: create A and hold a ---
def client_make_A():
    st = AnaState()
    st.a_priv = x25519.X25519PrivateKey.generate()
    st.A = pub_raw(st.a_priv)
    return st

# --- server side: create B and hold b ---
def server_make_B(st=None):
    st = st or AnaState()
    st.b_priv = x25519.X25519PrivateKey.generate()
    st.B = pub_raw(st.b_priv)
    return st

# --- derive dk on CLIENT: dk = a·B ---
def client_derive_dk(st: AnaState, B_bytes: bytes):
    st.dk = st.a_priv.exchange(x25519.X25519PublicKey.from_public_bytes(B_bytes))
    return st.dk

# --- derive dk on SERVER: dk = b·A ---
def server_derive_dk(st: AnaState, A_bytes: bytes):
    st.dk = st.b_priv.exchange(x25519.X25519PublicKey.from_public_bytes(A_bytes))
    return st.dk


def sha256(b): 
    return hashlib.sha256(b).digest()


# --- hash to scalar helper ---
def hash_to_scalar(data: bytes, n: int) -> int:
    data = to_bytes_strict(data)
    h = hashlib.sha256(data).digest()
    k = int.from_bytes(h, "big") % n
    return k or 1

def _dk_to_scalar(dk: bytes, curve=NIST256p) -> int:
    """
    Deterministically map dk (bytes) to a non-zero scalar in [1..n-1].
    This is how dk participates multiplicatively (no concatenation).
    """
    dk = to_bytes_strict(dk) 
    n = curve.order
    return hash_to_scalar(dk, n)

def curve_field_len_bytes(curve):
    # field size in bytes for underlying prime field
    p = curve.curve.p()
    return (p.bit_length() + 7) // 8

def k_from_dm_dk(dm: int, dk: bytes, curve=NIST256p) -> int:
    """
    Derive nonce scalar k from dm and dk using only x-coordinate of (dm * G).
    Returns scalar in [1..n-1].
    """
    dk = to_bytes_strict(dk)
    G: Point = curve.generator
    n = curve.order

    # 1) map dk -> scalar (non-zero)
    dk_scalar = _dk_to_scalar(dk, curve)

    # 2) multiply dm * dk_scalar (mod n)
    d = (int(dm) * dk_scalar) % n
    if d == 0:
        # avoid the degenerate 0 * G = O: map to 1 instead (rare)
        d = 1

    # 3) compute R = d * G
    R = d * G

    # 4) serialize x coordinate fixed-length
    L = curve_field_len_bytes(curve)
    x_bytes = int(R.x()).to_bytes(L, "big")

    # 5) hash x only -> scalar nonce
    k = hash_to_scalar(x_bytes, n)
    return k


def inv_mod(a: int, n: int) -> int:
    """Modular inverse (Python 3.8+ has pow(a, -1, n) but we use pow for clarity)."""
    return pow(a, -1, n)

def ecdsa_ana_sign(privkey, msg_hash: bytes, k: int, curve=NIST256p) -> bytes:
    """
    Notes:
    - This implements r = x(kG) mod n, s = k^-1 (H(m) + r*sk) mod n.
    - If r == 0 or s == 0 (extremely unlikely), raises ValueError so caller can retry with different k.
    """
    # Accept SigningKey or raw scalar
    if isinstance(privkey, SigningKey):
        sk_obj = privkey
        d = sk_obj.privkey.secret_multiplier
    elif isinstance(privkey, int):
        d = int(privkey)
        sk_obj = None
    else:
        # try to accept PEM bytes
        try:
            sk_obj = SigningKey.from_pem(privkey)
            d = sk_obj.privkey.secret_multiplier
        except Exception:
            raise TypeError("privkey must be SigningKey, private scalar int, or PEM bytes")

    n = curve.order
    G = curve.generator

    # Ensure k is in range
    k = int(k) % n
    if k == 0:
        raise ValueError("k reduced to 0, invalid nonce")

    # R = k * G
    R: Point = k * G
    rx = int(R.x()) % n
    r = rx
    if r == 0:
        raise ValueError("r == 0, choose different k")

    # H(m) as integer. msg_hash must already be the hash (e.g., sha256 digest).
    hm = int.from_bytes(msg_hash, "big") % n

    k_inv = inv_mod(k, n)
    s = (k_inv * (hm + (r * int(d) % n))) % n
    if s == 0:
        raise ValueError("s == 0, choose different k")

    # Encode DER via ecdsa.util.sigencode_der (it expects r,s and order)
    # but sigencode_der signature expects r,s and order (n) -> returns bytes
    sig_der = sigencode_der(r, s, n)
    return sig_der

def ecdsa_ana_sign_message(privkey, message: bytes, k: int,
                           hash_name: str, curve=NIST256p) -> bytes:
    """
    TLS 1.3 helper: sign the *message* using hash_name, but with forced nonce k.
    Internally does H(message) and then standard ECDSA formula with k.
    """
    h = getattr(hashlib, hash_name)(message).digest()
    return ecdsa_ana_sign(privkey, h, k, curve)


def curve_from_pubkey(tlslite_pubkey):
    """
    Map tlslite ECDSA certificate public key to ecdsa curves used here.
    """
    try:
        name = getattr(tlslite_pubkey, "curve_name", None)
        # Normalize common names
        if name in ("secp256r1", "prime256v1"):
            return NIST256p
        if name in ("secp384r1",):
            return NIST384p
        if name in ("secp521r1",):
            return NIST521p
    except Exception:
        pass
    # Default to NIST256p (tlslite most common)
    return NIST256p


def decrypt_dm(sig_der: bytes, dk: bytes, mspace: int, curve) -> int | None:
    """
    Brute-force dm in [0..mspace-1] using the DER ECDSA signature and dk.
    Works because server set k := H(x(dm·G) || dk). We recompute r_i from k_i.
    Returns dm or None if not found.
    """
    n = curve.order
    G: ellipticcurve.Point = curve.generator

    # parse DER -> (r,s)  (we only need r)
    r, s = sigdecode_der(sig_der, n)

    for i in range(mspace):
        k_i = k_from_dm_dk(i, dk, curve)
        R_i = k_i * G
        if (R_i.x() % n) == r:
            return i
    return None
