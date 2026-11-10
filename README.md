# RTP/H.264 Packet Analyzer & SDP Validator

A Python CLI for inspecting clear H.264 RTP in packet captures and checking the codec and simulcast fields in WebRTC SDP offers. It reports transport gaps separately from malformed or incomplete H.264 payloads.

## Quick start

Use Python 3.10 or newer.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

python examples/make_capture.py /tmp/sample.pcap
python -m rtp_inspector rtp /tmp/sample.pcap --payload-type 96 --port 5004
python -m rtp_inspector sdp examples/offers/*.sdp
python -m unittest discover -s tests -v
```

Use the H.264 payload type from the stream's SDP. For pcap and pcapng, `--port` matches either UDP port. The CLI returns 1 for SDP errors or zero matching RTP streams, and 2 for usage or file errors.

## How it works

- **Capture reader** extracts UDP from classic pcap and single-interface pcapng, or reads RTP records from an rtpdump file. Streams are grouped by directional UDP flow and SSRC.
- **RTP analysis** extends 16-bit sequence numbers across wraparound, tracks gaps and duplicates, and estimates RFC 3550 jitter using the H.264 90 kHz clock. Late packets within the sequence window can close gaps.
- **H.264 depacketization** handles single NAL units, STAP-A aggregation, and consecutive FU-A fragments. It counts SPS and PPS NALs and unique IDR timestamps and flags IDRs observed before in-band parameter sets.
- **SDP validation** checks H.264 clock rate, profile-level-id, packetization mode, and level asymmetry. It validates media-scoped RID payload restrictions and simulcast references, including alternatives and paused RIDs.

## Results

The synthetic capture deliberately omits one packet and crosses the sequence number wrap boundary. All three file formats produced **5 RTP packets, 1 gap, 2.897 ms final jitter, 1 SPS, 1 PPS, and 1 reassembled IDR**. [Capture output](results/sample-rtp.json)

| Recorded offer | H.264 payload mappings | Send RIDs | Validation errors |
| --- | ---: | --- | ---: |
| Chromium 158.0.8127.18 | 6 | l, m, h | 0 |
| Firefox 159.0 | 2 | l, m, h | 0 |
| Safari 27.2 | 4 | l, m, h | 0 |
| Playwright WebKit 27.2 | 4 | l, m, h | 0 |

The offers were generated on macOS using installed Safari and the three Playwright engines. The capture page removes ICE credentials and DTLS fingerprints. To reproduce a Safari offer, serve `examples` with `python3 -m http.server 8000 --bind 127.0.0.1 --directory examples`, open `http://localhost:8000/capture-offer.html` in Safari, and save the generated text as an SDP file. [Saved offers](examples/offers) · [Validation output](results/browser-offers.json)

## Scope

The analyzer expects clear RTP. WebRTC wire captures carry encrypted SRTP and require decrypted RTP exported at the endpoint. Packet loss estimates cover the observed sequence range. Late packets update sequence statistics, while FU-A reconstruction uses arrival order and drops incomplete units. The SDP checks focus on H.264 and simulcast attributes rather than the full SDP grammar.

[RFC 3550](https://www.rfc-editor.org/rfc/rfc3550) · [RFC 6184](https://www.rfc-editor.org/rfc/rfc6184) · [RFC 7742](https://www.rfc-editor.org/rfc/rfc7742) · [RFC 8851](https://www.rfc-editor.org/rfc/rfc8851) · [RFC 8853](https://www.rfc-editor.org/rfc/rfc8853)
