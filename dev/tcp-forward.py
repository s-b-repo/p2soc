#!/usr/bin/env python3
"""DEV: tiny TCP forwarder standing in for an autossh -L tunnel.
Usage: tcp-forward.py <listen_port> <target_host> <target_port>"""
import socket
import sys
import threading


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, host, port):
    try:
        upstream = socket.create_connection((host, port))
    except OSError:
        client.close()
        return
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


def main():
    lp, th, tp = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", lp))
    srv.listen(16)
    print(f"forwarding 127.0.0.1:{lp} -> {th}:{tp}", flush=True)
    while True:
        client, _ = srv.accept()
        handle(client, th, tp)


if __name__ == "__main__":
    main()
