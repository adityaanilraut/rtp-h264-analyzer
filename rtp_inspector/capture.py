import ipaddress
import struct

import dpkt

from .rtp import Packet, Stream


def rtpdump(handle):
    if not handle.readline(256).startswith(b"#!rtpplay1.0 "):
        raise ValueError("invalid rtpdump header")
    if len(handle.read(16)) != 16:
        raise ValueError("truncated rtpdump header")
    while record := handle.read(8):
        if len(record) != 8:
            raise ValueError("truncated rtpdump record")
        stored, original, offset = struct.unpack("!HHI", record)
        if stored < 8:
            raise ValueError("invalid rtpdump record size")
        packet = handle.read(stored - 8)
        if len(packet) != stored - 8:
            raise ValueError("truncated rtpdump data")
        if original and original == len(packet):
            yield offset / 1000, ("rtpdump",), packet


def network_packet(link, data):
    if link == 1:
        return dpkt.ethernet.Ethernet(data).data
    if link == 113:
        return dpkt.sll.SLL(data).data
    if link == 276:
        return dpkt.sll2.SLL2(data).data
    if link in (0, 108):  # BSD NULL and LOOP use a four-byte family header.
        data = data[4:]
    if data and data[0] >> 4 == 4:
        return dpkt.ip.IP(data)
    if data and data[0] >> 4 == 6:
        return dpkt.ip6.IP6(data)
    return None


def udp_capture(handle, port):
    magic = handle.read(4)
    handle.seek(0)
    reader = dpkt.pcapng.Reader(handle) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(handle)
    link = reader.datalink()
    if link not in (0, 1, 12, 101, 108, 113, 228, 229, 276):
        raise ValueError(f"unsupported capture link type {link}")
    for arrival, data in reader:
        try:
            ip = network_packet(link, data)
        except (dpkt.UnpackError, IndexError, struct.error):
            continue
        if isinstance(ip, dpkt.ip.IP):
            if ip.mf or ip.offset:
                continue
        elif isinstance(ip, dpkt.ip6.IP6):
            if any(isinstance(ext, dpkt.ip6.IP6FragmentHeader) for ext in ip.all_extension_headers):
                continue
        else:
            continue
        udp = ip.data
        if not isinstance(udp, dpkt.udp.UDP) or udp.ulen < 8 or len(udp.data) != udp.ulen - 8:
            continue
        if port is not None and port not in (udp.sport, udp.dport):
            continue
        flow = (str(ipaddress.ip_address(ip.src)), udp.sport, str(ipaddress.ip_address(ip.dst)), udp.dport)
        yield float(arrival), flow, udp.data


def inspect_capture(path, payload_type, port=None):
    streams = {}
    malformed = 0
    with path.open("rb") as handle:
        dump = handle.peek(2).startswith(b"#!")
        if dump and port is not None:
            raise ValueError("--port applies to pcap/pcapng only")
        records = rtpdump(handle) if dump else udp_capture(handle, port)
        for arrival, flow, raw in records:
            if len(raw) < 2 or raw[0] >> 6 != 2 or raw[1] & 127 != payload_type:
                continue
            try:
                packet = Packet.parse(raw)
            except ValueError:
                malformed += 1
                continue
            stream = streams.setdefault((flow, packet.ssrc), Stream())
            stream.push(arrival, packet)
    return {
        "payload_type": payload_type,
        "malformed_rtp": malformed,
        "streams": [
            {"flow": list(flow), "ssrc": f"0x{ssrc:08x}", **stream.summary()}
            for (flow, ssrc), stream in sorted(streams.items())
        ],
    }
