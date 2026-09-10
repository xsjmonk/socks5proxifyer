import select
import socket
import struct
import sys
import threading
from datetime import datetime


LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else None


def log_event(message):
    line = "{0} {1}".format(datetime.utcnow().isoformat(), message)
    print(line, flush=True)
    if LOG_PATH:
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def relay(a, b):
    try:
        while True:
            readable, _, _ = select.select([a, b], [], [], 30)
            if not readable:
                return
            for src in readable:
                dst = b if src is a else a
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    except OSError:
        return


def handle(client):
    try:
        greeting = client.recv(262)
        if len(greeting) < 2 or greeting[0] != 5:
            return
        client.sendall(b"\x05\x00")

        request = client.recv(4)
        if len(request) < 4 or request[0] != 5 or request[1] != 1:
            return

        atyp = request[3]
        if atyp == 1:
            address = socket.inet_ntoa(client.recv(4))
            port = struct.unpack("!H", client.recv(2))[0]
        elif atyp == 3:
            length = client.recv(1)[0]
            address = client.recv(length).decode("ascii")
            port = struct.unpack("!H", client.recv(2))[0]
        else:
            return

        try:
            remote = socket.create_connection((address, port), 5)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            log_event("CONNECT-FAIL {0}:{1}".format(address, port))
            return

        log_event("CONNECT {0}:{1}".format(address, port))

        bind = remote.getsockname()
        reply = b"\x05\x00\x00\x01" + socket.inet_aton(bind[0]) + struct.pack("!H", bind[1])
        client.sendall(reply)
        relay(client, remote)
    finally:
        client.close()


def serve(bind_host, bind_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_host, bind_port))
    server.listen(64)
    print(f"SOCKS5 listening on {bind_host}:{bind_port}", flush=True)
    log_event("LISTEN {0}:{1}".format(bind_host, bind_port))
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    serve("127.0.0.1", 1080)
