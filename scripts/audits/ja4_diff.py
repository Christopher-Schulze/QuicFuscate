#!/usr/bin/env python3
"""JA4 fingerprint + field-level diff for TLS ClientHello captures (TODO-1009).

Parses a TLS record containing a ClientHello (hex string or file) and emits:
  - the JA4 fingerprint (FoxIO format: t<ver><sni><ccnt><ecnt><alpn>_<chash>_<ehash>)
  - the raw field lists JA4 hashes over, so synthetic hellos can be diffed
    field-by-field against real browser captures.

Usage:
  ja4_diff.py <hex-file-or-literal> [<more>...]
  cat hellos.txt | ja4_diff.py -

No third-party deps. GREASE values are detected and excluded exactly like the
JA4 spec requires (0x?A?A pattern, both nibbles equal).
"""

import hashlib
import sys

GREASE = {0x0A0A + i * 0x1010 for i in range(16)}  # 0x0A0A,0x1A1A,...,0xFAFA

TLS_VERSION = {
    0x0300: "s3",
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
}


def u16(b, o):
    return (b[o] << 8) | b[o + 1]


class Reader:
    def __init__(self, buf):
        self.b = buf
        self.o = 0

    def take(self, n):
        if self.o + n > len(self.b):
            raise ValueError(f"truncated: need {n} at {self.o}, len {len(self.b)}")
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return u16(self.b, self._adv(2))

    def _adv(self, n):
        o = self.o
        self.take(n)
        return o


def parse_client_hello(record: bytes) -> dict:
    if len(record) < 6 or record[0] != 0x16 or record[5] != 0x01:
        raise ValueError("not a TLS handshake record containing ClientHello")
    r = Reader(record[5:])
    r.u8()                     # handshake type
    r.take(3)                  # handshake length
    version = r.u16()
    r.take(32)                 # random
    sid_len = r.u8()
    r.take(sid_len)
    cs_len = r.u16()
    ciphers = [u16(r.b, r.o + i) for i in range(0, cs_len, 2)]
    r.take(cs_len)
    comp_len = r.u8()
    r.take(comp_len)

    extensions = []
    sni_is_ip = False
    alpn = ""
    sigalgs = []
    groups = []
    keyshares = []
    supported_versions = []
    has_ech = False
    has_alps = False
    has_cert_comp = False

    if r.o < len(r.b):
        ext_total = r.u16()
        ext_end = r.o + ext_total
        while r.o < ext_end:
            etype = r.u16()
            elen = r.u16()
            edata = r.take(elen)
            extensions.append(etype)
            if etype == 0x0000 and len(edata) >= 5:      # server_name
                name_type = edata[2]
                sni_is_ip = name_type != 0
            elif etype == 0x0010 and len(edata) >= 3:    # ALPN
                plen = (edata[0] << 8) | edata[1]
                if plen >= 2:
                    first = edata[2:2 + edata[2] + 1]
                    proto = first[1:].decode("ascii", "replace")
                    alpn = proto
            elif etype == 0x000D:                        # signature_algorithms
                sigalgs = [u16(edata, 2 + i) for i in range(0, len(edata) - 2, 2)]
            elif etype == 0x000A:                        # supported_groups
                groups = [u16(edata, 2 + i) for i in range(0, len(edata) - 2, 2)]
            elif etype == 0x0033 and len(edata) >= 4:    # key_share
                klen = u16(edata, 0)
                ko = 2
                while ko < klen + 2 and ko + 4 <= len(edata):
                    keyshares.append(u16(edata, ko))
                    esz = u16(edata, ko + 2)
                    ko += 4 + esz
            elif etype == 0x002B:                        # supported_versions
                supported_versions = list(edata[1:])
                supported_versions = [
                    u16(edata, 1 + i) for i in range(0, len(edata) - 1, 2)
                ]
            elif etype == 0xFE0D:
                has_ech = True
            elif etype == 0x4469:                        # application_settings (ALPS)
                has_alps = True
            elif etype == 0x001B:
                has_cert_comp = True

    return {
        "version": version,
        "ciphers": ciphers,
        "extensions": extensions,
        "sni_is_ip": sni_is_ip,
        "alpn": alpn,
        "sigalgs": sigalgs,
        "groups": groups,
        "keyshares": keyshares,
        "supported_versions": supported_versions,
        "has_ech": has_ech,
        "has_alps": has_alps,
        "has_cert_comp": has_cert_comp,
    }


def hexlist(vals):
    return ",".join(f"{v:04x}" for v in vals)


def ja4(h: dict) -> str:
    vers = h["supported_versions"]
    top = max(v for v in vers if v not in GREASE) if vers else h["version"]
    vcode = TLS_VERSION.get(top, "00")
    sni = "i" if h["sni_is_ip"] else "d"
    ciphers = [c for c in h["ciphers"] if c not in GREASE]
    # JA4 spec: extension list is hashed sorted, GREASE excluded, but SNI and
    # ALPN count toward both the count and the hash.
    exts = [e for e in h["extensions"] if e not in GREASE]
    alpn = (h["alpn"][:1] + h["alpn"][-1:]) if h["alpn"] else "00"
    a = f"t{vcode}{sni}{len(ciphers):02d}{len(exts):02d}{alpn[:2]:<2}"
    b = hashlib.sha256(hexlist(sorted(ciphers)).encode()).hexdigest()[:12]
    ext_str = hexlist(sorted(exts)) + "_" + hexlist(h["sigalgs"])
    c = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
    return f"{a}_{b}_{c}"


def describe(name, h: dict):
    print(f"=== {name} ===")
    print(f"  ja4:        {ja4(h)}")
    print(f"  ciphers:    {hexlist(h['ciphers'])}")
    print(f"  extensions: {hexlist(h['extensions'])}")
    print(f"  groups:     {hexlist(h['groups'])}")
    print(f"  keyshares:  {hexlist(h['keyshares'])}")
    print(f"  sigalgs:    {hexlist(h['sigalgs'])}")
    print(f"  versions:   {hexlist(h['supported_versions'])}")
    print(f"  alpn:       {h['alpn']!r}  sni_ip={h['sni_is_ip']}"
          f"  ech={h['has_ech']} alps={h['has_alps']} cert_comp={h['has_cert_comp']}")


def load(arg):
    if arg == "-":
        return [l.split() for l in sys.stdin if l.strip()]
    try:
        with open(arg) as f:
            text = f.read()
    except OSError:
        text = arg
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(line.split())
    return out


def main():
    for arg in sys.argv[1:]:
        for parts in load(arg):
            if parts and parts[0] == "PERSONA_HELLO":
                name, hexs = parts[1], parts[2]
            elif len(parts) == 1:
                name, hexs = arg, parts[0]
            else:
                continue
            describe(name, parse_client_hello(bytes.fromhex(hexs)))


if __name__ == "__main__":
    main()
