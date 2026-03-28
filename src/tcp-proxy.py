#!/usr/bin/env python3
"""Bidirectional stdin/stdout <-> TCP proxy.
Usage: python3 tcp-proxy.py HOST PORT
Prints 'OK' to stdout once connected, then relays data both ways.
"""
import sys, socket, select, os

if len(sys.argv) != 3:
    sys.stderr.write("Usage: tcp-proxy.py HOST PORT\n")
    sys.exit(1)

host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

sys.stdout.buffer.write(b"OK\n")
sys.stdout.buffer.flush()

debug = os.environ.get("TCP_PROXY_DEBUG") == "1"

try:
    while True:
        readable, _, _ = select.select([s, sys.stdin.buffer], [], [], 60)
        if not readable:
            if debug:
                sys.stderr.write("select timeout\n")
            continue
        for fd in readable:
            if fd is sys.stdin.buffer:
                data = sys.stdin.buffer.read1(65536)
                if not data:
                    if debug:
                        sys.stderr.write("stdin EOF\n")
                    sys.exit(0)
                if debug:
                    sys.stderr.write(f"stdin→tcp {len(data)} bytes\n")
                    sys.stderr.flush()
                s.sendall(data)
            else:
                data = s.recv(65536)
                if not data:
                    if debug:
                        sys.stderr.write("tcp EOF\n")
                    sys.exit(0)
                if debug:
                    sys.stderr.write(f"tcp→stdout {len(data)} bytes\n")
                    sys.stderr.flush()
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
except (BrokenPipeError, ConnectionResetError):
    sys.exit(0)
