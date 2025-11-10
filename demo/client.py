# demo/client.py
from tlslite.constants import CipherSuite, HashAlgorithm, SignatureAlgorithm
import socket
from tlslite.handshakesettings import HandshakeSettings
try:
    from tlslite.api import TLSConnection
except ImportError:
    from tlslite.tlsconnection import TLSConnection


def suite_name(code: int) -> str:
    for n, v in vars(CipherSuite).items():
        if isinstance(v, int) and v == code and n.startswith("TLS_"):
            return n
    return str(code)

def hex_or_empty(b):
    return "" if b is None else (b.hex() if isinstance(b, (bytes, bytearray)) else bytes(b).hex())


def run_client(host="127.0.0.1", port=4443):
    settings = HandshakeSettings()
    settings.minVersion = (3, 3) # 1.2
    settings.maxVersion = (3, 4) # 1.3
    settings.anamorphic = True

    s = socket.socket()
    s.connect((host, port))
    tls = TLSConnection(s)

    def sigalg_str(sigalg):
        if isinstance(sigalg, tuple) and len(sigalg) == 2:
            h, s = sigalg
            return f"{SignatureAlgorithm.toStr(s)}_{HashAlgorithm.toStr(h)}"
        return str(sigalg)


    # Cert-based client handshake (server-auth)
    ok = False
    try:
        tls.handshakeClientCert(settings=settings, serverName="localhost")
        ok = True
    except TypeError:
        pass
    if not ok:
        tls.handshakeClientCert(settings=settings)

    print("[client] Handshake complete")
    print("\n[client] TLS version:", tls.version)
    print("[client] CipherSuite:", suite_name(getattr(tls.session, "cipherSuite", None)))
    sigalg = getattr(tls, "serverSigAlg", None)
    print("[client] Server Signing Algorithm:", sigalg_str(sigalg))

    print("\n[server] ClientHello.random:", hex_or_empty(getattr(tls, "_clientRandom13", None)))
    print("[server] ServerHello.random:", hex_or_empty(getattr(tls, "_serverRandom13", None)))

    # PREMASTER SECRET
    if tls.version == (3, 3):
        pms = getattr(tls, "_premasterSecret_demo", None)
        if pms:
            print("\n[server] Premaster (shared secret):", pms.hex())
        else:
            print("\n[server] Premaster not available")
    elif tls.version >= (3, 4):
        pms = getattr(tls, "_sharedSec13", None)
        print("\n[client] ECDHE shared secret:", pms.hex() if pms else "<not captured>")

    tls.write(b"\nLet's start talking!")
    resp = tls.read()
    print("\n[client] Server replied:", resp)
    tls.close()

if __name__ == "__main__":
    run_client()
