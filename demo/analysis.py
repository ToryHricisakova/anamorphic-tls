# bench_simple.py
import socket
import threading
import time
import statistics

from tlslite.handshakesettings import HandshakeSettings
try:
    from tlslite.tlsconnection import TLSConnection
except ImportError:
    from tlslite.api import TLSConnection

# reuse your existing helper
from server import load_chain_and_key


def make_settings(version=(3, 3)):
    s = HandshakeSettings()
    s.minVersion = version
    s.maxVersion = version
    # you already set anamorphic-related fields in your codebase;
    # here we just flip the flag ON to match your current experiments.
    s.anamorphic = True
    # optional: set dm/mspace if you rely on them here too
    # s.ana_dm = 54
    # s.ana_mspace = 256
    return s


def one_handshake(version=(3, 3)):
    """
    Run exactly one TLS handshake (client + server) with anamorphic
    hooks enabled, using a local socketpair. Return elapsed time in seconds.
    """
    s_server, s_client = socket.socketpair()

    tls_server = TLSConnection(s_server)
    tls_client = TLSConnection(s_client)

    server_settings = make_settings(version)
    client_settings = make_settings(version)

    chain, priv = load_chain_and_key()

    def server_thread():
        try:
            tls_server.handshakeServer(
                certChain=chain,
                privateKey=priv,
                settings=server_settings,
            )
            # tiny app-data echo to make sure channel is really up
            data = tls_server.read()
            tls_server.write(b"OK")
        except Exception as e:
            # you can print(e) for debugging if needed
            pass
        finally:
            tls_server.close()

    t = threading.Thread(target=server_thread)
    t.start()

    start = time.perf_counter()
    # client handshake (same pattern as your demo)
    ok = False
    try:
        tls_client.handshakeClientCert(
            settings=client_settings,
            serverName="localhost",
        )
        ok = True
    except TypeError:
        # fallback variant without serverName
        tls_client.handshakeClientCert(settings=client_settings)
        ok = True

    # small app-data round trip so covert channel paths have a chance
    # to finish any derivations that happen late (if any).
    if ok:
        try:
            tls_client.write(b"ping")
            _ = tls_client.read()
        except Exception:
            pass

    end = time.perf_counter()

    tls_client.close()
    t.join()

    return end - start


def main(runs=100, version=(3, 3)):
    times = []

    # Warm-up: prime cert parsing, PRF setup, etc.
    for _ in range(5):
        one_handshake(version)

    for i in range(runs):
        dt = one_handshake(version)
        times.append(dt)

    avg = statistics.mean(times)
    stdev = statistics.pstdev(times)

    print(f"\n=== TLS {version} with anamorphic hooks ===")
    print(f"Runs: {runs}")
    print(f"Mean:  {avg*1000:.2f} ms")
    print(f"σ:     {stdev*1000:.2f} ms")
    print(f"Min:   {min(times)*1000:.2f} ms")
    print(f"Max:   {max(times)*1000:.2f} ms")


if __name__ == "__main__":
    # For TLS 1.2
    main(runs=1000, version=(3, 3))

    # main(runs=100, version=(3, 4))
