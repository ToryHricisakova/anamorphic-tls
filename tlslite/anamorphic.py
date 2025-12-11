import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from ecdsa import NIST256p, NIST384p, NIST521p, ellipticcurve
from ecdsa.ellipticcurve import Point
from ecdsa.util import sigencode_der, sigdecode_der

class AnaState:
    def __init__(self):
        self.a_priv = None   # client private
        self.b_priv = None   # server private
        self.A = None        # client public (32B)
        self.B = None        # server public (32B)
        self.dk = None       # shared (32B)


# ------------  DK DERIVATION HELPER METHODS ---------------

def client_make_A():
    st = AnaState()
    st.a_priv = x25519.X25519PrivateKey.generate()
    st.A = st.a_priv.public_key().public_bytes_raw()
    return st

def server_make_B(st=None):
    st = st or AnaState()
    st.b_priv = x25519.X25519PrivateKey.generate()
    st.B = st.b_priv.public_key().public_bytes_raw()
    return st

def client_derive_dk(st: AnaState, B_bytes: bytes):
    st.dk = st.a_priv.exchange(x25519.X25519PublicKey.from_public_bytes(B_bytes))
    return st.dk

def server_derive_dk(st: AnaState, A_bytes: bytes):
    st.dk = st.b_priv.exchange(x25519.X25519PublicKey.from_public_bytes(A_bytes))
    return st.dk


def hash_to_scalar(data: bytes, curve: any) -> int:
    h = hashlib.sha256(data).digest()
    n = curve.order
    k = int.from_bytes(h, "big") % n
    return k or 1


def curve_field_len_bytes(curve):
    # field size in bytes for underlying prime field
    p = curve.curve.p()
    return (p.bit_length() + 7) // 8


# ------------  ANAMORPHIC SIGNING ---------------

def k_from_dm_dk(dm: int, dk: bytes, curve) -> int:

    G: Point = curve.generator
    n = curve.order
    dk_scalar = hash_to_scalar(dk, curve)

    d = (int(dm) * dk_scalar) % n
    if d == 0:
        d = 1

    R = d * G
    L = curve_field_len_bytes(curve)
    x_bytes = int(R.x()).to_bytes(L, "big")
    k = hash_to_scalar(x_bytes, curve)
    return k


def inv_mod(a: int, n: int) -> int:
    return pow(a, -1, n)


def ecdsa_ana_sign(privkey, msg_hash: bytes, k: int) -> bytes:

    sk_obj = privkey
    curve = sk_obj.curve
    n = curve.order
    G = curve.generator
    d = sk_obj.privkey.secret_multiplier

    k = int(k) % n
    if k == 0:
        raise ValueError("k reduced to 0, invalid nonce")

    R: Point = k * G
    rx = int(R.x()) % n
    r = rx
    if r == 0:
        raise ValueError("r == 0, choose different k")

    hm = int.from_bytes(msg_hash, "big") % n    # msg_hash must already be the hash

    k_inv = inv_mod(k, n)
    s = (k_inv * (hm + (r * int(d) % n))) % n
    if s == 0:
        raise ValueError("s == 0, choose different k")

    sig_der = sigencode_der(r, s, n)
    return sig_der


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


# ------------  DM DECRYPTION ---------------

def decrypt_dm(sig_der: bytes, dk: bytes, mspace: int, curve) -> int | None:

    n = curve.order
    G: ellipticcurve.Point = curve.generator

    r, s = sigdecode_der(sig_der, n) # parse DER -> (r,s)
    r = int(r) % n

    for i in range(mspace):
        k_i = k_from_dm_dk(i, dk, curve)
        R_i = k_i * G
        if (R_i.x() % n) == r:
            return i
    return None
