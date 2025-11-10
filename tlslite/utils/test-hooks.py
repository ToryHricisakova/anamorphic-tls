# test_hooks.py
from tlslite.handshakesettings import HandshakeSettings

print("Import OK. Constructing HandshakeSettings with research hooks...")

s = HandshakeSettings()
# set forced bytes and a simple nonce callback to show it's called
s.forced_client_random = b'\xAA' * 32
s.forced_server_random = b'\xBB' * 32

def demo_nonce_cb(transcript_hash: bytes, role: str) -> int:
    print("nonce_cb called! role=", role, "transcript_hash=", transcript_hash.hex())
    return 42  # demo only (not secure)

s.ecdsa_nonce_cb = demo_nonce_cb

print("forced_client_random len:", len(s.forced_client_random))
print("forced_server_random len:", len(s.forced_server_random))
print("ecdsa_nonce_cb present:", callable(s.ecdsa_nonce_cb))
