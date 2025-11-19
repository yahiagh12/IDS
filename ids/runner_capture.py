#!/usr/bin/env python3
"""
Runner used by the GUI: starts a LiveListener with given backend/interface
and prints each packet as a JSON line to stdout.
"""
import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="Run LiveListener and print packets to stdout")
    parser.add_argument("--backend", choices=("scapy", "pyshark", "socket"), default="scapy")
    parser.add_argument("--interface", default=None)
    args = parser.parse_args()

    # Import here so this script can be used as a small isolated runner
    from ids.capture.live_listener import LiveListener

    def on_packet(pkt):
        try:
            print(json.dumps(pkt, default=str), flush=True)
        except Exception:
            # best-effort: avoid crashing the runner
            print(repr(pkt), flush=True)

    listener = LiveListener(backend=args.backend, interface=args.interface)
    try:
        listener.listen(on_packet)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
