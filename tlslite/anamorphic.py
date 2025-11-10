# tlslite/anamorph.py
import hashlib
try:
    # cryptography >= 41 convenience
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

def sha256(b): return hashlib.sha256(b).digest()

class AnaState:
    """Per-connection anamorphic state (ephemeral)."""
    def __init__(self):
        self.a_priv = None   # client private (x25519)
        self.b_priv = None   # server private (x25519)
        self.A = None        # client public (32B)
        self.B = None        # server public (32B)
        self.dk = None       # shared (32B)

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
