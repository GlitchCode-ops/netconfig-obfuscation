"""The four configuration-transformation methods compared in the LLM study.

  M1 original      -- no transformation (upper bound on utility, zero privacy)
  M2 naive         -- occurrence-level masking (DLP-style, no cross-ref model)
  M3 global_pseudo -- deterministic pseudonymisation, SINGLE global scope,
                      NO prefix-length preservation, NO host-offset retention,
                      NO least-common-scope elevation. Isolates *determinism*
                      from *topology preservation*: references resolve, but
                      subnet containment and point-to-point alignment are lost.
  M4 full          -- the full obfuscation pipeline.

M3 is the strongest straightforward alternative: consistent renaming without
any address-structure preservation.
"""
import hashlib
import hmac
import ipaddress
import random
import re

from pipeline import parse_config, run_pipeline
from validate import IP_RE, STRUCTURAL

TOKEN_RE = re.compile(
    r"\b(CUST-[A-Z0-9-]+|PL-[A-Z0-9-]+|RM-[A-Z0-9-]+-IN|[a-z]+\d*-"
    r"(?:core|edge|agg|leaf)-\d+)\b")


# ------------------------------------------------------------------ M2 naive
def t_naive(configs, devices=None, seed=99):
    """Fresh token / fresh random address per OCCURRENCE (no consistency)."""
    rng = random.Random(seed)
    out, n = {}, [0]

    def new_ip(m):
        s = m.group(0)
        if STRUCTURAL.match(s):
            return s
        return str(ipaddress.ip_address(rng.randint(0x0A000001, 0x0AFFFFFE)))

    def new_tok(m):
        n[0] += 1
        return f"MASK_{n[0]:05d}"

    # Device names use a stable digest so runs are reproducible.
    # Record the device-name mapping in the reverse map. The model is
    # still shown only the masked name (the baseline is not weakened); the
    # mapping exists so the harness can ask every method about the SAME
    # physical device, which is required for a controlled comparison.
    rev = {}
    for d, t in sorted(configs.items()):
        t = IP_RE.sub(new_ip, t)
        t = TOKEN_RE.sub(new_tok, t)
        t = re.sub(r"(snmp-server community )\S+", r"\1MASKED", t)
        t = re.sub(r"(secret 5 )\S+", r"\1MASKED", t)
        t = re.sub(r"(crypto isakmp key )\S+", r"\1MASKED", t)
        key = "DEV_%06d" % (int(hashlib.sha256(d.encode()).hexdigest()[:8], 16)
                            % 10**6)
        out[key] = t
        rev[key] = d
    return out, rev


# ---------------------------------------------------- M3 global pseudonymisation
class GlobalPseudonymiser:
    """One global scope; every distinct value gets a stable opaque token.
    Addresses become opaque /32-style tokens drawn from a flat pool with NO
    prefix or offset structure preserved."""

    def __init__(self, secret=b"global-pseudo-secret"):
        self.secret = secret
        self.map = {}
        self.rev = {}
        self._used_ip = set()

    def _dig(self, kind, v):
        return hmac.new(self.secret, f"{kind}:{v}".encode(),
                        hashlib.sha256).digest()

    def tok(self, kind, v, prefix):
        k = (kind, v)
        if k in self.map:
            return self.map[k]
        d = self._dig(kind, v)
        b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        cand = prefix + "_" + "".join(b32[b % 32] for b in d[:6])
        self.map[k] = cand
        self.rev[cand] = v
        return cand

    def ip(self, v):
        """Deterministic but structure-free: the whole 32-bit address is
        derived from the digest, so two addresses in one /24 land anywhere."""
        k = ("ip", v)
        if k in self.map:
            return self.map[k]
        d = int.from_bytes(self._dig("ip", v)[:4], "big")
        base = int(ipaddress.ip_address("10.0.0.0"))
        for probe in range(1 << 20):
            cand_int = base + ((d + probe) % (1 << 24))
            cand = str(ipaddress.ip_address(cand_int))
            if cand not in self._used_ip:
                self._used_ip.add(cand)
                self.map[k] = cand
                self.rev[cand] = v
                return cand
        raise RuntimeError("pool exhausted")

    def asn(self, v):
        k = ("asn", v)
        if k in self.map:
            return self.map[k]
        d = int.from_bytes(self._dig("asn", v)[:4], "big")
        cand = str(64512 + d % 1023)
        self.map[k] = cand
        self.rev[cand] = v
        return cand


def t_global_pseudo(configs, devices=None):
    """Model-driven so references stay consistent, but no topology structure.
    Two-pass: build the name map across the WHOLE bundle first, so a hostname
    appearing in another device's interface description is also rewritten."""
    gp = GlobalPseudonymiser()
    models = {d: parse_config(d, t) for d, t in configs.items()}

    names = {}
    aclnums = {}
    for d, m in models.items():
        if m["hostname"]:
            names[m["hostname"]] = gp.tok("host", m["hostname"], "HN")
            mt = re.match(r"^([a-z]+\d*)[-_]", m["hostname"], re.I)
            if mt:
                names.setdefault(mt.group(1),
                                 gp.tok("site", mt.group(1), "SITE"))
        for v in m["vrfs"]:
            names[v["name"]] = gp.tok("vrf", v["name"], "VRF")
        for p in m["prefix_lists"]:
            names[p] = gp.tok("pl", p, "PL")
        for r in m["route_maps"]:
            names[r] = gp.tok("rm", r, "RM")
        for k in m["acls"]:
            aclnums.setdefault(str(k), None)
    # global ACL renumbering, disjoint from every original id
    originals = set(aclnums)
    used = set()
    for k in sorted(originals):
        dd = int.from_bytes(gp._dig("aclnum", k)[:4], "big")
        lo, hi = (100, 199) if 100 <= int(k) <= 199 else (1, 99)
        for probe in range(hi - lo + 1):
            cand = str(lo + (dd + probe) % (hi - lo + 1))
            if cand not in originals and cand not in used:
                used.add(cand)
                aclnums[k] = cand
                gp.rev[cand] = k
                break

    out = {}
    for d, m in models.items():
        txt = configs[d]
        for orig, new in sorted(names.items(), key=lambda x: -len(x[0])):
            txt = re.sub(rf"(?<![\w-]){re.escape(orig)}(?![\w-])", new, txt)

        def sub_ip(mm):
            s = mm.group(0)
            return s if STRUCTURAL.match(s) else gp.ip(s)
        txt = IP_RE.sub(sub_ip, txt)

        def sub_asn(mm):
            return mm.group(1) + gp.asn(mm.group(2))
        txt = re.sub(r"(router bgp )(\d+)", sub_asn, txt)
        txt = re.sub(r"(remote-as )(\d+)", sub_asn, txt)
        txt = re.sub(r"(rd )(\d+)(?=:)", sub_asn, txt)
        txt = re.sub(r"(route-target (?:export|import) )(\d+)(?=:)", sub_asn, txt)
        # ACL ids: definition sites and interface access-groups
        txt = re.sub(r"(access-list )(\d+)",
                     lambda mm: mm.group(1) + aclnums.get(mm.group(2), mm.group(2)),
                     txt)
        txt = re.sub(r"(ip access-group )(\d+)",
                     lambda mm: mm.group(1) + aclnums.get(mm.group(2), mm.group(2)),
                     txt)
        txt = re.sub(r"(snmp-server community )\S+", r"\1<REDACTED-SNMP>", txt)
        txt = re.sub(r"(secret 5 )\S+", r"\1<REDACTED-SECRET>", txt)
        txt = re.sub(r"(crypto isakmp key )\S+", r"\1<REDACTED-ISAKMP>", txt)
        out[names.get(m["hostname"], d)] = txt
    return out, gp.rev


# ------------------------------------------------------------------- M4 full
def t_full(configs, devices, site_of, secret=b"session-secret-0001"):
    models, obf_models, obf_text, g_o, g_b, ob = run_pipeline(
        configs, secret, site_of)
    rev = {}
    for r in ob.vault_records:
        rev[r["obfuscated_value"]] = r["original_value"]
    return obf_text, rev, ob


METHODS = ("original", "naive", "global_pseudo", "full")


def apply_method(method, configs, devices, site_of):
    """Returns (text_bundle, reverse_map, obfuscator_or_None)."""
    if method == "original":
        return dict(configs), {}, None
    if method == "naive":
        t, rev = t_naive(configs, devices)
        return t, rev, None
    if method == "global_pseudo":
        t, rev = t_global_pseudo(configs, devices)
        return t, rev, None
    if method == "full":
        return t_full(configs, devices, site_of)
    raise ValueError(method)
