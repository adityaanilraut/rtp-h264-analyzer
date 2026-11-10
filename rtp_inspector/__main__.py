import argparse
import json
from pathlib import Path
import struct

import dpkt

from .capture import inspect_capture
from .sdp import validate


def main():
    parser = argparse.ArgumentParser(prog="python -m rtp_inspector")
    subcommands = parser.add_subparsers(dest="command", required=True)
    rtp = subcommands.add_parser("rtp", help="analyze H.264 RTP from pcap, pcapng or rtpdump")
    rtp.add_argument("capture", type=Path)
    rtp.add_argument("--payload-type", required=True, type=int, choices=range(128), metavar="0–127")
    rtp.add_argument("--port", type=int, help="match source or destination UDP port")
    sdp = subcommands.add_parser("sdp", help="validate one or more SDP files")
    sdp.add_argument("files", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "rtp":
            if args.port is not None and not 1 <= args.port <= 65535:
                parser.error("--port must be between 1 and 65535")
            result = inspect_capture(args.capture, args.payload_type, args.port)
            print(json.dumps(result, indent=2))
            return 0 if result["streams"] else 1
        results = {str(path): validate(path.read_text(encoding="utf-8")) for path in args.files}
        print(json.dumps(results, indent=2))
        return 0 if all(item["valid"] for item in results.values()) else 1
    except (OSError, ValueError, dpkt.UnpackError, struct.error) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
