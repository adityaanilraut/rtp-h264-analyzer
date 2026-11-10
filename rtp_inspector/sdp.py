from dataclasses import dataclass, field
import re

RID = re.compile(r"[A-Za-z0-9_-]+")
DIRECTIONS = {"sendonly", "recvonly", "sendrecv", "inactive"}
LEVELS = {9, 10, 11, 12, 13, 20, 21, 22, 30, 31, 32, 40, 41, 42, 50, 51, 52, 60, 61, 62}
PROFILES = (
    (0x42, 0x4f, 0x40, "constrained-baseline"),
    (0x4d, 0x8f, 0x80, "constrained-baseline"),
    (0x58, 0xcf, 0xc0, "constrained-baseline"),
    (0x42, 0x4f, 0x00, "baseline"),
    (0x58, 0xcf, 0x80, "baseline"),
    (0x4d, 0xaf, 0x00, "main"),
    (0x64, 0xff, 0x0c, "constrained-high"),
    (0x64, 0xff, 0x00, "high"),
    (0xf4, 0xff, 0x00, "predictive-high-444"),
)


@dataclass
class Media:
    index: int
    kind: str
    port: str
    formats: list[str]
    attributes: list[str] = field(default_factory=list)


def parameters(value):
    parsed = {}
    for item in value.split(";"):
        if not item.strip():
            continue
        key, sep, val = item.partition("=")
        key = key.strip().lower()
        if not sep or not key or not val.strip() or key in parsed:
            raise ValueError(f"invalid or duplicate parameter {item.strip()!r}")
        parsed[key] = val.strip()
    return parsed


def parse(text):
    session, media, issues = [], [], []
    current = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if len(line) < 2 or line[1] != "=":
            issues.append(f"line {number}: expected a field of the form x=value")
        elif line.startswith("m="):
            parts = line[2:].split()
            if len(parts) < 4 or not parts[1].split("/")[0].isdigit():
                issues.append(f"line {number}: invalid media section")
                current = Media(len(media), "invalid", "0", [])
            else:
                current = Media(len(media), parts[0], parts[1].split("/")[0], parts[3:])
            media.append(current)
        elif current is None:
            session.append(line)
        elif line.startswith("a="):
            current.attributes.append(line[2:])
    if "v=0" not in session or not media:
        issues.append("expected an SDP session with v=0 and at least one media section")
    return session, media, issues


def validate_video(media, session_direction, error, warn):
    mappings, fmtps, rids = {}, {}, {}
    simulcast = []
    direction = session_direction
    mid = str(media.index)
    for attribute in media.attributes:
        name, _, value = attribute.partition(":")
        if name in DIRECTIONS:
            direction = name
        elif name == "mid":
            mid = value
        elif name in ("rtpmap", "fmtp"):
            fields = value.split(None, 1)
            if len(fields) != 2:
                error(f"invalid {name}: {value!r}")
                continue
            pt, detail = fields
            target = mappings if name == "rtpmap" else fmtps
            if pt in target:
                error(f"duplicate {name} for payload {pt}")
            if pt not in media.formats:
                error(f"{name} references unoffered payload {pt}")
            target[pt] = detail
        elif name == "rid":
            fields = value.split(None, 2)
            if len(fields) < 2 or not RID.fullmatch(fields[0]) or fields[1] not in ("send", "recv"):
                error(f"invalid rid: {value!r}")
                continue
            rid, flow = fields[:2]
            key = (flow, rid)
            if key in rids:
                error(f"duplicate {flow} RID {rid}")
            rids[key] = rid_payloads(fields[2] if len(fields) == 3 else "", media.formats, error)
        elif name == "simulcast":
            simulcast.append(value)

    h264 = []
    for pt, mapping in mappings.items():
        codec = mapping.lower().split("/")
        if codec[0] != "h264":
            continue
        if codec != ["h264", "90000"]:
            error(f"H.264 payload {pt} must use a 90000 Hz RTP clock")
        try:
            options = parameters(fmtps.get(pt, ""))
        except ValueError as exc:
            error(f"payload {pt}: {exc}")
            continue
        mode = options.get("packetization-mode", "0")
        if mode not in ("0", "1", "2"):
            error(f"payload {pt}: invalid packetization-mode {mode!r}")
        elif mode == "2":
            warn(f"payload {pt}: interleaved mode 2 is outside this analyzer's packetization support")
        if "level-asymmetry-allowed" in options and options["level-asymmetry-allowed"] not in ("0", "1"):
            error(f"payload {pt}: level-asymmetry-allowed must be 0 or 1")
        profile_id = options.get("profile-level-id")
        profile = decode_profile(profile_id, pt, error, warn)
        h264.append({"pt": pt, "packetization_mode": mode, "profile_level_id": profile_id, **profile})

    groups = {}
    if len(simulcast) > 1:
        error("duplicate simulcast attribute")
    if simulcast:
        groups = simulcast_groups(simulcast[0], rids, error)
    for flow in {flow for flow, _ in rids} | groups.keys():
        if direction == "inactive" or (flow == "send" and direction == "recvonly") or (flow == "recv" and direction == "sendonly"):
            error(f"{flow} RID/simulcast conflicts with {direction} media")
    return {
        "mid": mid, "direction": direction, "h264": h264,
        "rids": [{"id": rid, "direction": flow, "payload_types": pts} for (flow, rid), pts in rids.items()],
        "simulcast": groups,
    }


def rid_payloads(value, formats, error):
    pts = []
    seen = set()
    for restriction in value.split(";") if value else []:
        name, sep, detail = restriction.strip().partition("=")
        if not name or name in seen:
            error(f"empty or duplicate RID restriction {name!r}")
        seen.add(name)
        if name == "pt":
            pts = detail.split(",") if sep else []
            if not pts or len(pts) != len(set(pts)) or any(pt not in formats for pt in pts):
                error(f"invalid or unoffered RID payload types {detail!r}")
    return pts


def decode_profile(value, pt, error, warn):
    if value is None:
        warn(f"payload {pt}: missing profile-level-id required for WebRTC H.264")
        return {}
    if not re.fullmatch(r"[0-9a-fA-F]{6}", value):
        error(f"payload {pt}: profile-level-id must be six hexadecimal digits")
        return {}
    profile_idc, iop, level = bytes.fromhex(value)
    if not profile_idc or iop & 3 or level not in LEVELS:
        error(f"payload {pt}: invalid profile-level-id components {value}")
    profile = next((label for ident, mask, bits, label in PROFILES if ident == profile_idc and iop & mask == bits), None)
    if profile is None:
        warn(f"payload {pt}: profile {value} is outside the recognized WebRTC profiles")
    return {"profile": profile, "level_idc": level}


def simulcast_groups(value, rids, error):
    parts = value.split()
    groups = {}
    if len(parts) not in (2, 4):
        error(f"invalid simulcast direction/list: {value!r}")
        return groups
    for flow, layers in zip(parts[::2], parts[1::2]):
        if flow not in ("send", "recv") or flow in groups:
            error(f"invalid or duplicate simulcast direction {flow!r}")
            continue
        seen = set()
        groups[flow] = [layer.split(",") for layer in layers.split(";")]
        for group in groups[flow]:
            for token in group:
                rid = token.removeprefix("~")
                if not RID.fullmatch(rid) or (flow, rid) not in rids:
                    error(f"{flow} simulcast references undeclared RID {rid!r}")
                if rid in seen:
                    error(f"duplicate {flow} simulcast RID {rid!r}")
                seen.add(rid)
    return groups


def validate(text):
    session, media, errors = parse(text)
    warnings, videos = [], []
    session_direction = next((line[2:] for line in session if line[2:] in DIRECTIONS and line.startswith("a=")), "sendrecv")
    for section in media:
        if section.kind != "video" or section.port == "0":
            continue

        def error(message):
            errors.append(f"m[{section.index}]: {message}")

        def warn(message):
            warnings.append(f"m[{section.index}]: {message}")

        videos.append(validate_video(section, session_direction, error, warn))
    if not any(video["h264"] for video in videos):
        warnings.append("no active video section offers H.264")
    return {"valid": not errors, "video": videos, "errors": errors, "warnings": warnings}
