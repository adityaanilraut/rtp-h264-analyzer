from collections import Counter
from dataclasses import dataclass, field
import struct

CLOCK_RATE = 90_000
REORDER_WINDOW = 4096


@dataclass(frozen=True)
class Packet:
    pt: int
    sequence: int
    timestamp: int
    ssrc: int
    payload: bytes

    @classmethod
    def parse(cls, raw):
        if len(raw) < 12 or raw[0] >> 6 != 2:
            raise ValueError("invalid RTP header")
        flags, marker_pt, sequence, timestamp, ssrc = struct.unpack_from("!BBHII", raw)
        start = 12 + 4 * (flags & 15)
        end = len(raw)
        if flags & 0x10:
            if start + 4 > end:
                raise ValueError("truncated RTP extension")
            words = struct.unpack_from("!H", raw, start + 2)[0]
            start += 4 + 4 * words
        if flags & 0x20:
            if raw[-1] == 0:
                raise ValueError("invalid RTP padding")
            end -= raw[-1]
        if end <= start:
            raise ValueError("empty or truncated RTP payload")
        return cls(marker_pt & 127, sequence, timestamp, ssrc, raw[start:end])


def signed_delta(value, bits):
    half = 1 << (bits - 1)
    return (value + half) % (2 * half) - half


@dataclass
class Fragment:
    timestamp: int
    sequence: int
    nal: bytearray


class Depacketizer:
    """Return complete NAL units in capture order and count malformed payloads."""

    def __init__(self):
        self.fragment = None
        self.invalid = 0
        self.incomplete = 0
        self.unsupported = 0

    def finish(self):
        if self.fragment is not None:
            self.incomplete += 1
            self.fragment = None

    def push(self, packet):
        payload = packet.payload
        nal_type = payload[0] & 31
        if nal_type != 28:
            self.finish()
        if payload[0] & 0x80:
            self.finish()
            self.invalid += 1
            return []
        if 1 <= nal_type <= 23:
            return [payload]
        if nal_type == 24:
            return self._stap(payload)
        if nal_type == 28:
            return self._fu(packet)
        self.unsupported += 1
        return []

    def _stap(self, payload):
        offset, units = 1, []
        while offset + 2 <= len(payload):
            size = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2
            nal = payload[offset:offset + size]
            if not nal or len(nal) != size or nal[0] & 0x80 or not 1 <= nal[0] & 31 <= 23:
                break
            units.append(nal)
            offset += size
        else:
            if units and offset == len(payload):
                return units
        self.invalid += 1
        return []

    def _fu(self, packet):
        payload = packet.payload
        if len(payload) < 2:
            self.finish()
            self.invalid += 1
            return []
        flags = payload[1]
        start, end = flags & 0x80, flags & 0x40
        header = (payload[0] & 0xe0) | (flags & 31)
        if (start and end) or not 1 <= flags & 31 <= 23:
            self.finish()
            self.invalid += 1
            return []
        if start:
            self.finish()
            self.fragment = Fragment(packet.timestamp, packet.sequence, bytearray([header]) + payload[2:])
            return []
        fragment = self.fragment
        if (fragment is None or fragment.timestamp != packet.timestamp or
                packet.sequence != (fragment.sequence + 1) % 65536 or fragment.nal[0] != header):
            if fragment is not None:
                self.finish()
            else:
                self.incomplete += 1
            return []
        if len(fragment.nal) + len(payload) - 2 > 16 * 1024 * 1024:
            self.finish()
            self.invalid += 1
            return []
        fragment.sequence = packet.sequence
        fragment.nal.extend(payload[2:])
        if end:
            self.fragment = None
            return [bytes(fragment.nal)]
        return []


@dataclass
class Stream:
    first: int | None = None
    highest: int | None = None
    unique: int = 0
    duplicates: int = 0
    reordered: int = 0
    too_old: int = 0
    seen: set[int] = field(default_factory=set)
    jitter: float = 0.0
    previous: tuple[float, int] | None = None
    depacketizer: Depacketizer = field(default_factory=Depacketizer)
    nals: Counter = field(default_factory=Counter)
    idr_frames: int = 0
    idr_without_parameter_sets: int = 0
    last_idr_ts: int | None = None

    def push(self, arrival, packet):
        seq = packet.sequence
        if self.highest is None:
            self.first = self.highest = seq
        else:
            seq = self.highest + signed_delta(seq - self.highest, 16)
        if seq < max(self.first, self.highest - REORDER_WINDOW):
            self.too_old += 1
            return
        if seq in self.seen:
            self.duplicates += 1
            return
        if seq < self.highest:
            self.reordered += 1
        self.highest = max(self.highest, seq)
        self.seen.add(seq)
        if len(self.seen) > REORDER_WINDOW * 2:
            self.seen = {n for n in self.seen if n >= self.highest - REORDER_WINDOW}
        self.unique += 1

        if self.previous is not None:
            previous_arrival, previous_ts = self.previous
            spacing = (arrival - previous_arrival) * CLOCK_RATE
            media_spacing = signed_delta(packet.timestamp - previous_ts, 32)
            self.jitter += (abs(spacing - media_spacing) - self.jitter) / 16
        self.previous = arrival, packet.timestamp

        # A late packet can close a sequence gap without disrupting the current FU-A.
        if seq != self.highest:
            return
        for nal in self.depacketizer.push(packet):
            kind = nal[0] & 31
            self.nals[kind] += 1
            if kind == 5 and packet.timestamp != self.last_idr_ts:
                self.last_idr_ts = packet.timestamp
                self.idr_frames += 1
                if not self.nals[7] or not self.nals[8]:
                    self.idr_without_parameter_sets += 1

    def summary(self):
        self.depacketizer.finish()
        return {
            "packets": self.unique,
            "missing_packets": self.highest - self.first + 1 - self.unique,
            "duplicates": self.duplicates,
            "reordered": self.reordered,
            "outside_sequence_window": self.too_old,
            "jitter_ms": round(self.jitter * 1000 / CLOCK_RATE, 3),
            "sps": self.nals[7],
            "pps": self.nals[8],
            "idr_frames": self.idr_frames,
            "idr_without_prior_sps_pps": self.idr_without_parameter_sets,
            "nal_types": dict(sorted(self.nals.items())),
            "invalid_payloads": self.depacketizer.invalid,
            "incomplete_fragments": self.depacketizer.incomplete,
            "unsupported_payloads": self.depacketizer.unsupported,
        }
