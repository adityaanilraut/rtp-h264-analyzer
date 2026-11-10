from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest

from examples.make_capture import write
from rtp_inspector.capture import inspect_capture
from rtp_inspector.rtp import Depacketizer, Packet, Stream
from rtp_inspector.sdp import validate


class RTPTests(unittest.TestCase):
    def test_header_extension_csrc_and_padding(self):
        raw = (struct.pack("!BBHII", 0xb1, 0xe0, 17, 3000, 42) + bytes(4) +
               b"\xbe\xde\x00\x01" + bytes(4) + b"\x65\xaa\x00\x02")
        self.assertEqual(Packet.parse(raw), Packet(96, 17, 3000, 42, b"\x65\xaa"))
        with self.assertRaises(ValueError):
            Packet.parse(raw[:-1] + b"\xff")

    def test_reassembles_fragment_across_sequence_wrap(self):
        depacketizer = Depacketizer()
        self.assertEqual(depacketizer.push(Packet(96, 65535, 90, 1, b"\x7c\x85\xaa")), [])
        self.assertEqual(depacketizer.push(Packet(96, 0, 90, 1, b"\x7c\x45\xbb")), [b"\x65\xaa\xbb"])
        self.assertEqual(depacketizer.incomplete, 0)

    def test_broken_fragment_and_invalid_aggregation_do_not_emit_nals(self):
        depacketizer = Depacketizer()
        depacketizer.push(Packet(96, 1, 90, 1, b"\x7c\x85\xaa"))
        self.assertEqual(depacketizer.push(Packet(96, 3, 90, 1, b"\x7c\x45\xbb")), [])
        self.assertEqual(depacketizer.incomplete, 1)
        self.assertEqual(depacketizer.push(Packet(96, 4, 90, 1, b"\x78\x00\x01\x67\x00\x03\x68")), [])
        self.assertEqual(depacketizer.invalid, 1)

    def test_late_packet_closes_gap_and_duplicate_does_not_advance_stats(self):
        stream = Stream()
        for i, seq in enumerate([65535, 1, 0, 0]):
            stream.push(i * 0.01, Packet(96, seq, i * 900, 1, b"\x61\x01"))
        stats = stream.summary()
        self.assertEqual((stats["packets"], stats["missing_packets"], stats["reordered"], stats["duplicates"]), (3, 0, 1, 1))

    def test_all_capture_formats(self):
        with TemporaryDirectory() as directory:
            for suffix in (".pcap", ".pcapng", ".rtpdump"):
                with self.subTest(suffix=suffix):
                    path = Path(directory) / ("sample" + suffix)
                    write(path)
                    stream, = inspect_capture(path, 96)["streams"]
                    self.assertEqual([stream[k] for k in ("packets", "missing_packets", "sps", "pps", "idr_frames")],
                                     [5, 1, 1, 1, 1])
                    self.assertEqual(stream["jitter_ms"], 2.897)
                    if suffix != ".rtpdump":
                        self.assertEqual(inspect_capture(path, 96, port=1234)["streams"], [])


class SDPTests(unittest.TestCase):
    base = "v=0\nm=video 9 UDP/TLS/RTP/SAVPF 96 97\na=rtpmap:96 H264/90000\na=rtpmap:97 VP8/90000\n"

    def test_parses_profile_mode_and_paused_alternative(self):
        result = validate(self.base + "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\n"
                          "a=rid:h send pt=96,97\na=rid:m send\na=rid:l send\na=simulcast:send h,~m;l\n")
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["video"][0]["h264"][0]["profile"], "constrained-baseline")
        self.assertEqual(result["video"][0]["simulcast"], {"send": [["h", "~m"], ["l"]]})

    def test_reports_bad_profile_mode_and_rid_reference(self):
        result = validate(self.base + "a=fmtp:96 profile-level-id=xyz;packetization-mode=3\n"
                          "a=rid:h send pt=95\na=simulcast:send h;l\n")
        self.assertFalse(result["valid"])
        self.assertEqual(len(result["errors"]), 4)

    def test_rid_declarations_are_scoped_by_media_and_direction(self):
        result = validate(self.base + "a=rid:l recv\n" + self.base[self.base.index("m="):]
                          + "a=simulcast:send l\n")
        self.assertFalse(result["valid"])
        self.assertIn("undeclared RID", result["errors"][0])

    def test_saved_browser_offers(self):
        paths = sorted((Path(__file__).resolve().parents[1] / "examples" / "offers").glob("*.sdp"))
        self.assertGreaterEqual(len(paths), 3)
        for path in paths:
            with self.subTest(browser=path.stem):
                result = validate(path.read_text())
                self.assertTrue(result["valid"], result)
                self.assertTrue(result["video"][0]["h264"], result)


if __name__ == "__main__":
    unittest.main()
