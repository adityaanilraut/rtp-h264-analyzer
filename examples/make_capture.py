"""Generate the same small, synthetic test capture in three formats."""
from pathlib import Path
import socket
import struct
import sys

import dpkt


def packets():
    sps = b"\x67\x42\xe0\x1f"
    pps = b"\x68\xce\x06\xe2"
    stap = b"\x78" + b"".join(struct.pack("!H", len(nal)) + nal for nal in (sps, pps))
    rows = [
        (0, 65534, 0, stap),
        (12, 65535, 3000, b"\x7c\x85\xaa\xbb"),
        (24, 0, 3000, b"\x7c\x45\xcc\xdd"),
        (75, 2, 6000, b"\x61\x05"),  # Sequence 1 is absent.
        (110, 3, 9000, b"\x61\x06"),
    ]
    for millis, sequence, timestamp, payload in rows:
        yield millis, struct.pack("!BBHII", 0x80, 96, sequence, timestamp, 0x12345678) + payload


def frame(payload):
    udp = dpkt.udp.UDP(sport=4000, dport=5004, ulen=8 + len(payload), data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton("192.0.2.1"), dst=socket.inet_aton("192.0.2.2"),
                    p=dpkt.ip.IP_PROTO_UDP, ttl=64, len=20 + len(udp), data=udp)
    return dpkt.ethernet.Ethernet(src=b"\x02\x00\x00\x00\x00\x01",
                                 dst=b"\x02\x00\x00\x00\x00\x02", data=ip)


def write(path):
    if path.suffix not in (".rtpdump", ".pcapng", ".pcap"):
        raise ValueError("use a .rtpdump, .pcapng or .pcap extension")
    with path.open("wb") as handle:
        if path.suffix == ".rtpdump":
            handle.write(b"#!rtpplay1.0 192.0.2.2/5004\n" + b"\x00" * 16)
            for millis, rtp in packets():
                handle.write(struct.pack("!HHI", len(rtp) + 8, len(rtp), millis) + rtp)
        else:
            writer = (dpkt.pcapng.Writer if path.suffix == ".pcapng" else dpkt.pcap.Writer)(handle)
            for millis, rtp in packets():
                writer.writepkt(bytes(frame(rtp)), ts=1700000000 + millis / 1000)


if __name__ == "__main__":
    write(Path(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"))
