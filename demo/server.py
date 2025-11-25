# SERVER

import socket, traceback
from tlslite.handshakesettings import HandshakeSettings
from tlslite.constants import CipherSuite, HashAlgorithm, SignatureAlgorithm

try:
    from tlslite.api import TLSConnection, X509, X509CertChain, parsePEMKey
except ImportError:
    from tlslite.tlsconnection import TLSConnection
    from tlslite.x509 import X509, X509CertChain
    try:
        from tlslite.api import parsePEMKey
    except ImportError:
        from tlslite.utils.cryptomath import parsePEMKey

from tlslite.utils.pem import dePem  # PEM → DER

def suite_name(code: int) -> str:
    for n, v in vars(CipherSuite).items():
        if isinstance(v, int) and v == code and n.startswith("TLS_"):
            return n
    return str(code)

def hex_or_empty(b):
    return "" if b is None else (b.hex() if isinstance(b, (bytes, bytearray)) else bytes(b).hex())

def load_chain_and_key(cert_path="server.cert.pem", key_path="server.key.pem"):
    cert_pem_bytes = open(cert_path, "rb").read()  # bytes
    key_pem_bytes  = open(key_path,  "rb").read()  # bytes

    # ---- CERT ----
    # Use dePem with STR parameters on this build
    cert_pem_str = cert_pem_bytes.decode("ascii")
    cert_der = dePem(cert_pem_str, "CERTIFICATE")  # str, str
    x = X509()
    x.parseBinary(cert_der)                        # parse DER directly
    chain = X509CertChain([x])

    # ---- KEY ----
    # parsePEMKey generally wants a STR on this build
    try:
        priv = parsePEMKey(key_pem_bytes.decode("ascii"), private=True)
    except Exception:
        # fallback: some variants accept bytes
        priv = parsePEMKey(key_pem_bytes, private=True)

    return chain, priv


def run_server(host="127.0.0.1", port=4443):
    settings = HandshakeSettings()
    settings.minVersion = (3, 3) # 1.2
    settings.maxVersion = (3, 3) # 1.3
    settings.anamorphic = True

    settings.ana_dm = 54          # the covert message
    settings.ana_mspace = 256

    print("[server demo] anamorphic:", settings.anamorphic,
      "dm:", getattr(settings, "ana_dm", None))

    try:
        chain, priv = load_chain_and_key()
    except Exception:
        print("[server] Failed to load/parse cert or key (expect PEM files in demo/):")
        print("  server.cert.pem   server.key.pem")
        traceback.print_exc()
        return

    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, port))
    lsock.listen(1)
    print(f"[server] Listening on {host}:{port}")

    conn, addr = lsock.accept()
    print("[server] Accepted", addr)
    tls = TLSConnection(conn)


    def sigalg_str(sigalg):
        if isinstance(sigalg, tuple) and len(sigalg) == 2:
            h, s = sigalg
            return f"{SignatureAlgorithm.toStr(s)}_{HashAlgorithm.toStr(h)}"
        return str(sigalg)
    

    try:
        tls.handshakeServer(certChain=chain, privateKey=priv, settings=settings)
    except Exception:
        print("[server] handshakeServer failed:")
        traceback.print_exc()
        conn.close(); lsock.close(); return
    print("[server] Handshake complete")

    print("\n[server] TLS version:", tls.version)

    print("[server] CipherSuite:", suite_name(getattr(tls.session, "cipherSuite", None)))
    sigalg = getattr(tls, "serverSigAlg", None)
    print("[server] Server Signing Algorithm:", sigalg_str(sigalg))

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
        print("\n[server] ECDHE shared secret:", pms.hex() if pms else "<not captured>")


    dk = getattr(getattr(tls, "_ana", None), "dk", None)
    print("[server] Duplicate Key dk:", dk.hex() if dk else "<not set>")

    data = tls.read()
    print("\n[server] App data from client:", data)
    tls.write(b"OK")
    tls.close()
    lsock.close()

if __name__ == "__main__":
    run_server()