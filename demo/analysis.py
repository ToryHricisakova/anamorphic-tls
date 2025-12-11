import socket
import threading
import time
import statistics

try:
    from tlslite.tlsconnection import TLSConnection
except ImportError:
    from tlslite.api import TLSConnection

from server import load_chain_and_key, make_settings


def one_handshake():
    s_server, s_client = socket.socketpair()

    tls_server = TLSConnection(s_server)
    tls_client = TLSConnection(s_client)

    server_settings = make_settings()
    client_settings = make_settings()

    chain, priv = load_chain_and_key()

    def server_thread():
        try:
            tls_server.handshakeServer(
                certChain=chain,
                privateKey=priv,
                settings=server_settings,
            )
        finally:
            tls_server.close()

    t = threading.Thread(target=server_thread)
    t.start()

    start = time.perf_counter()
    tls_client.handshakeClientCert(
            settings=client_settings,
            serverName="localhost",
        )

    end = time.perf_counter()

    tls_client.close()
    t.join()

    return end - start


def main(runs):
    times = []

    # --- Warm-up ---
    for _ in range(5):
        one_handshake()

    for i in range(runs):
        dt = one_handshake()
        times.append(dt)

    avg = statistics.mean(times)
    stdev = statistics.pstdev(times)

    if make_settings().anamorphic == True:
        print(f"\n=== Anamorphic TLS Handshake ===")
    else: print(f"\n=== Standard TLS Handshake ===")
    print(f"Runs: {runs}")
    print(f"Mean:  {avg*1000:.2f} ms")
    print(f"σ:     {stdev*1000:.2f} ms")
    print(f"Min:   {min(times)*1000:.2f} ms")
    print(f"Max:   {max(times)*1000:.2f} ms")


if __name__ == "__main__":
    main(runs=1000)