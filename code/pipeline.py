"""Topology-preserving obfuscation pipeline (prototype).

Implements, for the supported Cisco IOS subset:
  - parsing and normalization into a typed entity model
  - topology graph construction (NetworkX)
  - scope-derived HMAC-SHA256 mapping with a prefix-preserving,
    offset-retaining address allocator
  - semantic role preservation for hostnames and descriptions
  - a session-scoped AES-256-GCM vault for reversible mappings

Rendering back to IOS text is model-driven (no raw search-and-replace).
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re

import networkx as nx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------------------------------------------- parsing

R_HOSTNAME = re.compile(r"^hostname\s+(\S+)")
R_VRF = re.compile(r"^ip vrf (\S+)")
R_RD = re.compile(r"^\s+rd\s+(\S+)")
R_RT = re.compile(r"^\s+route-target (export|import)\s+(\S+)")
R_IFACE = re.compile(r"^interface (\S+)")
R_IF_IP = re.compile(r"^\s+ip address (\S+) (\S+)")
R_IF_DESC = re.compile(r"^\s+description (.+)$")
R_IF_VRF = re.compile(r"^\s+ip vrf forwarding (\S+)")
R_IF_ACL = re.compile(r"^\s+ip access-group (\S+) (in|out)")
R_ACL_NUM = re.compile(r"^access-list (\d+) (permit|deny)\s+(.*)$")
R_PL = re.compile(r"^ip prefix-list (\S+) seq (\d+) (permit|deny) (\S+)")
R_RM = re.compile(r"^route-map (\S+) (permit|deny) (\d+)")
R_RM_MATCH_PL = re.compile(r"^\s+match ip address prefix-list (\S+)")
R_RM_SET = re.compile(r"^\s+set (.+)$")
R_OSPF = re.compile(r"^router ospf (\d+)")
R_OSPF_RID = re.compile(r"^\s+router-id (\S+)")
R_OSPF_NET = re.compile(r"^\s+network (\S+) (\S+) area (\S+)")
R_BGP = re.compile(r"^router bgp (\d+)")
R_BGP_RID = re.compile(r"^\s+bgp router-id (\S+)")
R_BGP_NEI = re.compile(r"^\s+neighbor (\S+) remote-as (\d+)")
R_BGP_NEI_RM = re.compile(r"^\s+neighbor (\S+) route-map (\S+) (in|out)")
R_SECRET = re.compile(r"^(enable secret|username \S+ secret)\s+\d+\s+(\S+)")
R_SNMP = re.compile(r"^snmp-server community (\S+)\s+(RO|RW)")
R_ISAKMP = re.compile(r"^crypto isakmp key (\S+) address (\S+)")
R_IP_IN_ACE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_config(device_id, text):
    """Parse an IOS config (evaluation subset) into a typed entity model."""
    m = {"device_id": device_id, "hostname": None, "vrfs": [], "interfaces": [],
         "acls": {}, "prefix_lists": {}, "route_maps": {}, "ospf": None,
         "bgp": None, "secrets": [], "unknown_lines": []}
    cur = None  # (kind, obj)
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.strip() in ("!", "end"):
            if line.strip() in ("!", "end"):
                cur = None
            continue
        if (g := R_HOSTNAME.match(line)):
            m["hostname"] = g.group(1); cur = None; continue
        if (g := R_VRF.match(line)):
            v = {"name": g.group(1), "rd": None, "rt_export": [], "rt_import": [],
                 "line": lineno}
            m["vrfs"].append(v); cur = ("vrf", v); continue
        if cur and cur[0] == "vrf":
            if (g := R_RD.match(line)):
                cur[1]["rd"] = g.group(1); continue
            if (g := R_RT.match(line)):
                cur[1][f"rt_{g.group(1)}"].append(g.group(2)); continue
        if (g := R_IFACE.match(line)):
            i = {"name": g.group(1), "ip": None, "mask": None, "desc": None,
                 "vrf": None, "acl_in": None, "acl_out": None, "line": lineno}
            m["interfaces"].append(i); cur = ("if", i); continue
        if cur and cur[0] == "if":
            if (g := R_IF_IP.match(line)):
                cur[1]["ip"], cur[1]["mask"] = g.group(1), g.group(2); continue
            if (g := R_IF_DESC.match(line)):
                cur[1]["desc"] = g.group(1); continue
            if (g := R_IF_VRF.match(line)):
                cur[1]["vrf"] = g.group(1); continue
            if (g := R_IF_ACL.match(line)):
                cur[1][f"acl_{g.group(2)}"] = g.group(1); continue
        if (g := R_ACL_NUM.match(line)):
            m["acls"].setdefault(g.group(1), []).append(
                {"action": g.group(2), "body": g.group(3)}); cur = None; continue
        if (g := R_PL.match(line)):
            m["prefix_lists"].setdefault(g.group(1), []).append(
                {"seq": int(g.group(2)), "action": g.group(3), "prefix": g.group(4)})
            cur = None; continue
        if (g := R_RM.match(line)):
            cl = {"action": g.group(2), "seq": int(g.group(3)),
                  "match_pl": None, "set": None}
            m["route_maps"].setdefault(g.group(1), []).append(cl)
            cur = ("rm", cl); continue
        if cur and cur[0] == "rm":
            if (g := R_RM_MATCH_PL.match(line)):
                cur[1]["match_pl"] = g.group(1); continue
            if (g := R_RM_SET.match(line)):
                cur[1]["set"] = g.group(1); continue
        if (g := R_OSPF.match(line)):
            m["ospf"] = {"pid": g.group(1), "rid": None, "networks": []}
            cur = ("ospf", m["ospf"]); continue
        if cur and cur[0] == "ospf":
            if (g := R_OSPF_RID.match(line)):
                cur[1]["rid"] = g.group(1); continue
            if (g := R_OSPF_NET.match(line)):
                cur[1]["networks"].append(
                    {"net": g.group(1), "wc": g.group(2), "area": g.group(3)}); continue
        if (g := R_BGP.match(line)):
            m["bgp"] = {"asn": g.group(1), "rid": None, "neighbors": {}}
            cur = ("bgp", m["bgp"]); continue
        if cur and cur[0] == "bgp":
            if (g := R_BGP_RID.match(line)):
                cur[1]["rid"] = g.group(1); continue
            if (g := R_BGP_NEI.match(line)):
                cur[1]["neighbors"].setdefault(
                    g.group(1), {"remote_as": g.group(2), "rm": []})
                cur[1]["neighbors"][g.group(1)]["remote_as"] = g.group(2); continue
            if (g := R_BGP_NEI_RM.match(line)):
                cur[1]["neighbors"].setdefault(g.group(1), {"remote_as": None, "rm": []})
                cur[1]["neighbors"][g.group(1)]["rm"].append(
                    (g.group(2), g.group(3))); continue
        if (g := R_SECRET.match(line)):
            m["secrets"].append({"kind": g.group(1), "value": g.group(2),
                                 "raw": line}); cur = None; continue
        if (g := R_SNMP.match(line)):
            m["secrets"].append({"kind": "snmp community", "value": g.group(1),
                                 "mode": g.group(2), "raw": line}); cur = None; continue
        if (g := R_ISAKMP.match(line)):
            m["secrets"].append({"kind": "isakmp key", "value": g.group(1),
                                 "peer": g.group(2), "raw": line}); cur = None; continue
        if line.startswith("version"):
            m["version"] = line.split()[1]; continue
        m["unknown_lines"].append({"lineno": lineno, "text": line})
    return m


# ------------------------------------------------------------ topology graph

def build_graph(models):
    """Config-derived topology graph across all parsed device models."""
    G = nx.Graph()
    subnet_members = {}
    for m in models:
        dev = m["device_id"]
        G.add_node(dev, type="Device")
        for v in m["vrfs"]:
            G.add_node(f"{dev}:VRF:{v['name']}", type="VRF")
            G.add_edge(dev, f"{dev}:VRF:{v['name']}", type="HAS_VRF")
        for i in m["interfaces"]:
            nid = f"{dev}:IF:{i['name']}"
            G.add_node(nid, type="Interface")
            G.add_edge(dev, nid, type="HAS_INTERFACE")
            if i["vrf"]:
                G.add_edge(nid, f"{dev}:VRF:{i['vrf']}", type="IN_VRF")
            if i["ip"]:
                net = ipaddress.ip_interface(f"{i['ip']}/{i['mask']}").network
                vctx = i["vrf"] or "global"  # VRF-qualified subnet identity
                sid = f"SUBNET:{vctx}:{net.with_prefixlen}"
                G.add_node(sid, type="Subnet")
                G.add_edge(nid, sid, type="IN_SUBNET")
                subnet_members.setdefault(sid, []).append((dev, nid))
        if m["bgp"]:
            for peer in m["bgp"]["neighbors"]:
                pid = f"PEER:{peer}"
                G.add_node(pid, type="PeerIP")
                G.add_edge(dev, pid, type="PEERS_BGP")
    # L3 point-to-point adjacency inference. Rule: an L3_ADJACENT_TO edge
    # is added iff a (VRF-context, subnet) has prefix length /30 or /31,
    # exactly two member interfaces, and they are on different devices.
    for sid, members in subnet_members.items():
        if (sid.endswith("/30") or sid.endswith("/31")) and len(members) == 2:
            (d1, n1), (d2, n2) = members
            if d1 != d2:
                G.add_edge(n1, n2, type="L3_ADJACENT_TO")
    return G


# ----------------------------------------------------------- obfuscation

B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _tok(digest, n=6):
    return "".join(B32[b % 32] for b in digest[:n])


class Obfuscator:
    """Deterministic scope+salt HMAC-SHA256 mapping engine."""

    SYNTH_POOLS = [ipaddress.ip_network("10.0.0.0/8"),
                   ipaddress.ip_network("172.16.0.0/12"),
                   ipaddress.ip_network("192.168.0.0/16")]

    def __init__(self, session_secret: bytes, original_models,
                 subnet_scope_override=None, lcs_enabled=True,
                 retain_offset=True, vrf_context_enabled=True,
                 full_rdrt=False):
        self.secret = session_secret
        # Optional full RD/RT remapping: the numeric suffix is remapped
        # under tenant scope as well as the ASN component.
        self.full_rdrt = full_rdrt
        self.map = {}          # (scope, etype, ctx, key) -> synthetic value
        self.vault_records = []
        # switches used by the ablation study
        self.lcs_enabled = lcs_enabled
        self.retain_offset = retain_offset
        # Routing context participates in subnet/address identity, per
        # Eq.(1) context(v). Disable only for comparison: identical prefixes
        # in different VRFs within one scope would then share a mapping.
        self.vrf_context_enabled = vrf_context_enabled
        # least-common-scope rule: subnets shared across sites are elevated
        # to the tenant scope so both ends map identically
        self.subnet_scope_override = subnet_scope_override or {}
        # everything the synthetic space must avoid
        self.orig_subnets = set()
        self.orig_rdrt_suffixes = set()
        self.alloc_rdrt_suffixes = set()
        self.orig_asns = set()
        self.orig_names = set()
        for m in original_models:
            if m["bgp"]:
                self.orig_asns.add(m["bgp"]["asn"])
                for n in m["bgp"]["neighbors"].values():
                    if n["remote_as"]:
                        self.orig_asns.add(n["remote_as"])
            for v in m["vrfs"]:
                self.orig_names.add(v["name"])
                for x in [v["rd"]] + v["rt_export"] + v["rt_import"]:
                    if x and ":" in x:
                        self.orig_rdrt_suffixes.add(x.partition(":")[2])
            for i in m["interfaces"]:
                if i["ip"]:
                    self.orig_subnets.add(
                        ipaddress.ip_interface(f"{i['ip']}/{i['mask']}").network)
            self.orig_names.update(m["prefix_lists"])
            self.orig_names.update(m["route_maps"])
        self.orig_aclnums = set()
        for m in original_models:
            self.orig_aclnums.update(str(k) for k in m["acls"])
        self.alloc_subnets = set()
        self.alloc_asns = set()
        self.alloc_names = set()

    # -- primitives ---------------------------------------------------
    def _digest(self, scope, etype, key):
        salt = hmac.new(self.secret, f"scope:{scope}".encode(),
                        hashlib.sha256).digest()
        return hmac.new(salt, f"{etype}:{key}".encode(), hashlib.sha256).digest()

    def _record(self, scope, etype, orig, obf, context=""):
        self.vault_records.append({"scope": scope, "entity_type": etype,
                                   "context": str(context),
                                   "original_value": str(orig),
                                   "obfuscated_value": str(obf)})

    # -- subnets / addresses ------------------------------------------
    def map_subnet(self, scope, net: ipaddress.IPv4Network, vrf="global"):
        if self.lcs_enabled:
            scope = self.subnet_scope_override.get(f"{vrf}|{net}", scope)
        ctx = vrf if self.vrf_context_enabled else "global"
        k = (scope, "subnet", ctx, str(net))
        if k in self.map:
            return self.map[k]
        d = int.from_bytes(
            self._digest(scope, "subnet", f"{ctx}|{net}")[:8], "big")
        plen = net.prefixlen
        for pool in self.SYNTH_POOLS:
            if plen < pool.prefixlen:
                continue
            n_slots = 2 ** (plen - pool.prefixlen)
            idx = d % n_slots
            for probe in range(n_slots):
                cand_int = int(pool.network_address) + \
                    (((idx + probe) % n_slots) << (32 - plen))
                cand = ipaddress.ip_network((cand_int, plen))
                if cand in self.alloc_subnets:
                    continue
                if any(cand.overlaps(o) for o in self.orig_subnets):
                    continue
                if any(cand.overlaps(a) for a in self.alloc_subnets):
                    continue
                self.alloc_subnets.add(cand)
                self.map[k] = cand
                self._record(scope, "subnet", net, cand, context=ctx)
                return cand
        raise RuntimeError("synthetic pool exhausted")

    def map_ip(self, scope, ip, mask=None, prefixlen=None, vrf="global"):
        if prefixlen is None:
            prefixlen = ipaddress.ip_interface(f"{ip}/{mask}").network.prefixlen
        iface = ipaddress.ip_interface(f"{ip}/{prefixlen}")
        net = iface.network
        synth_net = self.map_subnet(scope, net, vrf=vrf)
        if self.retain_offset:
            offset = int(iface.ip) - int(net.network_address)
        else:  # ablation: digest-derived offset within usable host range
            span = max(net.num_addresses - 2, 1)
            d = int.from_bytes(self._digest(scope, "off", ip)[:4], "big")
            offset = 1 + d % span
        synth_ip = ipaddress.ip_address(int(synth_net.network_address) + offset)
        ctx = vrf if self.vrf_context_enabled else "global"
        self._record(scope, "ip", ip, synth_ip, context=ctx)
        return str(synth_ip), synth_net

    # -- ASNs -----------------------------------------------------------
    def map_asn(self, scope, asn):
        if self.lcs_enabled:
            scope = "tenant"  # ASNs referenced across sites: least common scope
        k = (scope, "asn", asn)
        if k in self.map:
            return self.map[k]
        d = int.from_bytes(self._digest(scope, "asn", asn)[:4], "big")
        for probe in range(1023):
            cand = str(64512 + (d + probe) % 1023)
            if cand not in self.orig_asns and cand not in self.alloc_asns:
                self.alloc_asns.add(cand)
                self.map[k] = cand
                self._record(scope, "asn", asn, cand)
                return cand
        raise RuntimeError("ASN space exhausted")

    def map_rd(self, scope, rd):
        asn, _, num = rd.partition(":")
        if self.full_rdrt and num.isdigit():
            num = self.map_rdrt_suffix(num)
        return f"{self.map_asn(scope, asn)}:{num}"

    def map_rdrt_suffix(self, num):
        """Remap an RD/RT numeric suffix under tenant scope, keeping its digit
        width. Tenant scope makes every occurrence of a suffix map identically,
        so matching import and export targets remain consistent across
        devices. Candidates never equal an original suffix in the bundle."""
        k = ("tenant", "rdrt-suffix", num)
        if k in self.map:
            return self.map[k]
        width = len(num)
        lo = 0 if width == 1 else 10 ** (width - 1)
        span = 10 ** width - lo
        d = int.from_bytes(self._digest("tenant", "rdrt-suffix", num)[:8], "big")
        for probe in range(span):
            cand = str(lo + (d + probe) % span)
            if (cand not in self.orig_rdrt_suffixes
                    and cand not in self.alloc_rdrt_suffixes):
                self.alloc_rdrt_suffixes.add(cand)
                self.map[k] = cand
                self._record("tenant", "rdrt-suffix", num, cand)
                return cand
        raise RuntimeError("RD/RT suffix space exhausted")

    # -- names ------------------------------------------------------------
    def map_name(self, scope, etype, name, prefix):
        k = (scope, etype, name)
        if k in self.map:
            return self.map[k]
        dig = self._digest(scope, etype, name)
        for probe in range(64):
            cand = f"{prefix}_{_tok(dig[probe:] + dig, 6)}"
            if cand not in self.orig_names and cand not in self.alloc_names:
                self.alloc_names.add(cand)
                self.map[k] = cand
                self._record(scope, etype, name, cand)
                return cand
        raise RuntimeError("name space exhausted")

    # -- numbered ACL ids ----------------------------------------------
    def map_aclnum(self, scope, num):
        k = (scope, "aclnum", num)
        if k in self.map:
            return self.map[k]
        d = int.from_bytes(self._digest(scope, "aclnum", num)[:4], "big")
        lo, hi = (100, 199) if 100 <= int(num) <= 199 else (1, 99)
        for probe in range(hi - lo + 1):
            cand = str(lo + (d + probe) % (hi - lo + 1))
            # Reject any candidate equal to any original ACL id in the
            # bundle, not merely the id being replaced.
            if (cand not in self.orig_aclnums
                    and (scope, "aclnum-used", cand) not in self.map):
                self.map[(scope, "aclnum-used", cand)] = True
                self.map[k] = cand
                self._record(scope, "aclnum", num, cand)
                return cand
        raise RuntimeError("ACL number space exhausted")

    # -- hostnames + SRP ---------------------------------------------------
    R_HOST = re.compile(r"^([a-z]+)[-_](core|edge|agg|leaf|gw|spine)[-_]?(\d+)$",
                        re.I)

    def map_hostname(self, name):
        k = ("global", "hostname", name)
        if k in self.map:
            return self.map[k]
        g = self.R_HOST.match(name)
        if g:  # semantic role preservation
            site_tok = self.map_name("global", "site", g.group(1).lower(), "SITE")
            obf = f"{g.group(2).upper()}_{site_tok}_{g.group(3)}"
        else:
            obf = f"HN_{_tok(self._digest('global', 'hostname', name))}"
        self.map[k] = obf
        self._record("global", "hostname", name, obf)
        return obf


PLACEHOLDER = "<REDACTED-SECRET-%s>"


def _is_ip(tok):
    try:
        ipaddress.ip_address(tok)
        return True
    except ValueError:
        return False


def ace_prefixlen_from_wildcard(wc, default=32):
    """ACE address granularity comes from its wildcard mask, not a
    fixed /24. 0.0.0.255 -> /24, 0.0.255.255 -> /16, 0.0.0.0 -> /32."""
    try:
        parts = [int(x) for x in wc.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        nm = 0
        for p in parts:
            nm = (nm << 8) | (255 - p)
        return ipaddress.ip_network(
            f"0.0.0.0/{ipaddress.ip_address(nm)}").prefixlen
    except (ValueError, ipaddress.AddressValueError):
        return None


def infer_subnet_vrf(net, model):
    """Resolve the routing context of a prefix from the interface that
    owns it, so a prefix referenced by an interface, a prefix-list and an ACL
    all receive the SAME synthetic value."""
    for i in model.get("interfaces", []):
        if not i.get("ip") or not i.get("mask"):
            continue
        try:
            inet = ipaddress.ip_interface(f"{i['ip']}/{i['mask']}").network
        except ValueError:
            continue
        if inet == net or net.subnet_of(inet) or inet.subnet_of(net):
            return i.get("vrf") or "global"
    return "global"


def infer_peer_context(peer_ip, model, default_plen=32):
    """Derive a BGP/ISAKMP peer address's prefix length and routing
    context from the most specific interface subnet on the same device that
    contains it. Falls back to /32 global when no interface covers it, which
    is the conservative choice (peer becomes its own subnet)."""
    try:
        pa = ipaddress.ip_address(peer_ip)
    except ValueError:
        return default_plen, "global"
    best, best_vrf = None, "global"
    for i in model.get("interfaces", []):
        if not i.get("ip") or not i.get("mask"):
            continue
        try:
            net = ipaddress.ip_interface(f"{i['ip']}/{i['mask']}").network
        except ValueError:
            continue
        if pa in net and (best is None or net.prefixlen > best.prefixlen):
            best, best_vrf = net, (i.get("vrf") or "global")
    if best is None:
        return default_plen, "global"
    return best.prefixlen, best_vrf


def rewrite_ace_body(body, ob, scope, model=None):
    """Token-aware ACE rewriting: 'host X' -> /32; 'A wildcard' -> derived
    prefix length; bare address -> /32. Structural literals untouched."""
    toks = body.split()
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t == "host" and i + 1 < len(toks) and _is_ip(toks[i + 1]):
            new_ip, _ = ob.map_ip(scope, toks[i + 1], prefixlen=32)
            out += ["host", new_ip]
            i += 2
            continue
        if _is_ip(t) and i + 1 < len(toks) and _is_ip(toks[i + 1]):
            plen = ace_prefixlen_from_wildcard(toks[i + 1])
            if plen is not None:
                net = ipaddress.ip_network(f"{t}/{plen}", strict=False)
                _v = infer_subnet_vrf(net, model) if model else "global"
                new_net = ob.map_subnet(scope, net, vrf=_v)
                out += [str(new_net.network_address), toks[i + 1]]
                i += 2
                continue
        if _is_ip(t):
            new_ip, _ = ob.map_ip(scope, t, prefixlen=32)
            out.append(new_ip)
            i += 1
            continue
        out.append(t)
        i += 1
    return " ".join(out)


def obfuscate_model(m, ob: Obfuscator, site_scope):
    """Return an obfuscated copy of a parsed model (model-level rewriting)."""
    o = json.loads(json.dumps(m))  # deep copy
    o["hostname"] = ob.map_hostname(m["hostname"])
    o["device_id"] = o["hostname"]
    name_scope = site_scope  # names scoped per site in this policy

    vrf_map, pl_map, rm_map, acl_map = {}, {}, {}, {}
    for v in o["vrfs"]:
        vrf_map[v["name"]] = ob.map_name(name_scope, "vrf", v["name"], "VRF")
        v["name"] = vrf_map[v["name"]]
        if v["rd"]:
            v["rd"] = ob.map_rd(site_scope, v["rd"])
        v["rt_export"] = [ob.map_rd(site_scope, x) for x in v["rt_export"]]
        v["rt_import"] = [ob.map_rd(site_scope, x) for x in v["rt_import"]]
    for name in list(o["prefix_lists"]):
        pl_map[name] = ob.map_name(name_scope, "prefix-list", name, "PL")
        o["prefix_lists"][pl_map[name]] = o["prefix_lists"].pop(name)
    for name in list(o["route_maps"]):
        rm_map[name] = ob.map_name(name_scope, "route-map", name, "RM")
        o["route_maps"][rm_map[name]] = o["route_maps"].pop(name)
        for cl in o["route_maps"][rm_map[name]]:
            if cl["match_pl"]:
                cl["match_pl"] = pl_map.get(cl["match_pl"], cl["match_pl"])
    # numbered ACLs permute within their class (100-199), so renaming
    # in place can clobber a not-yet-renamed original; build the full
    # mapping first, then rebuild the dict atomically
    for num in o["acls"]:
        acl_map[num] = ob.map_aclnum(name_scope, num)
    o["acls"] = {acl_map[num]: aces for num, aces in o["acls"].items()}
    for aces in o["acls"].values():
        for ace in aces:
            # prefix length derived from the wildcard mask
            ace["body"] = rewrite_ace_body(ace["body"], ob, site_scope,
                                           model=m)
    for pl in o["prefix_lists"].values():
        for e in pl:
            net = ipaddress.ip_network(e["prefix"])
            e["prefix"] = ob.map_subnet(
                site_scope, net,
                vrf=infer_subnet_vrf(net, m)).with_prefixlen
    for i in o["interfaces"]:
        vctx = i["vrf"] or "global"  # original VRF name = identity context
        if i["vrf"]:
            i["vrf"] = vrf_map[i["vrf"]]
        for side in ("acl_in", "acl_out"):
            if i[side]:
                i[side] = acl_map.get(i[side], i[side])
        if i["ip"]:
            i["ip"], _ = ob.map_ip(site_scope, i["ip"], mask=i["mask"],
                                   vrf=vctx)
        if i["desc"]:
            i["desc"] = redact_desc(i["desc"], ob)
    if o["ospf"]:
        if o["ospf"]["rid"]:
            o["ospf"]["rid"], _ = ob.map_ip(site_scope, o["ospf"]["rid"],
                                            prefixlen=32)
        for n in o["ospf"]["networks"]:
            wc_bits = 32 - bin(int(ipaddress.ip_address(n["wc"]))).count("1")
            _onet = ipaddress.ip_network((n["net"], wc_bits))
            new_net = ob.map_subnet(site_scope, _onet,
                                    vrf=infer_subnet_vrf(_onet, m))
            n["net"] = str(new_net.network_address)
    if o["bgp"]:
        o["bgp"]["asn"] = ob.map_asn(site_scope, o["bgp"]["asn"])
        if o["bgp"]["rid"]:
            o["bgp"]["rid"], _ = ob.map_ip(site_scope, o["bgp"]["rid"],
                                           prefixlen=32)
        nbrs = {}
        for ip, n in o["bgp"]["neighbors"].items():
            # prefix length and VRF derived from the covering
            # interface subnet
            _plen, _pvrf = infer_peer_context(ip, m)
            new_ip, _ = ob.map_ip(site_scope, ip, prefixlen=_plen, vrf=_pvrf)
            if n["remote_as"]:
                n["remote_as"] = ob.map_asn(site_scope, n["remote_as"])
            n["rm"] = [(rm_map.get(r, r), d) for r, d in n["rm"]]
            nbrs[new_ip] = n
        o["bgp"]["neighbors"] = nbrs
    new_secrets = []
    for s in o["secrets"]:
        kind = s["kind"].upper().replace(" ", "-")
        s2 = dict(s)
        s2["value"] = PLACEHOLDER % kind  # non-reversible placeholder
        if "peer" in s2:
            _plen, _pvrf = infer_peer_context(s2["peer"], m)
            s2["peer"], _ = ob.map_ip(site_scope, s2["peer"],
                                      prefixlen=_plen, vrf=_pvrf)
        new_secrets.append(s2)
    o["secrets"] = new_secrets
    return o


def redact_desc(desc, ob: Obfuscator):
    """Rewrite hostnames appearing in descriptions; drop other free text."""
    words = []
    for w in desc.split():
        if Obfuscator.R_HOST.match(w):
            words.append(ob.map_hostname(w))
        elif re.fullmatch(r"[A-Za-z]+[0-9/.]*", w) and w.lower() in (
                "to", "lan", "mgmt", "loopback", "peer", "uplink"):
            words.append(w)
        else:
            words.append("LINK")
    return " ".join(dict.fromkeys(words))  # dedupe, keep order


# --------------------------------------------------------------- rendering

def render_model(m):
    out = [f"version {m.get('version', '15.2')}", f"hostname {m['hostname']}", "!"]
    for s in m["secrets"]:
        if s["kind"] == "snmp community":
            out.append(f"snmp-server community {s['value']} {s['mode']}")
        elif s["kind"] == "isakmp key":
            out.append(f"crypto isakmp key {s['value']} address {s['peer']}")
        else:
            out.append(f"{s['kind']} 5 {s['value']}")
    out.append("!")
    for v in m["vrfs"]:
        out.append(f"ip vrf {v['name']}")
        if v["rd"]:
            out.append(f" rd {v['rd']}")
        for x in v["rt_export"]:
            out.append(f" route-target export {x}")
        for x in v["rt_import"]:
            out.append(f" route-target import {x}")
        out.append("!")
    for i in m["interfaces"]:
        out.append(f"interface {i['name']}")
        if i["desc"]:
            out.append(f" description {i['desc']}")
        if i["vrf"]:
            out.append(f" ip vrf forwarding {i['vrf']}")
        if i["ip"]:
            out.append(f" ip address {i['ip']} {i['mask']}")
        if i["acl_in"]:
            out.append(f" ip access-group {i['acl_in']} in")
        if i["acl_out"]:
            out.append(f" ip access-group {i['acl_out']} out")
        out.append("!")
    for num, aces in m["acls"].items():
        for a in aces:
            out.append(f"access-list {num} {a['action']} {a['body']}")
    out.append("!")
    for name, entries in m["prefix_lists"].items():
        for e in entries:
            out.append(f"ip prefix-list {name} seq {e['seq']} {e['action']} {e['prefix']}")
    out.append("!")
    for name, clauses in m["route_maps"].items():
        for cl in clauses:
            out.append(f"route-map {name} {cl['action']} {cl['seq']}")
            if cl["match_pl"]:
                out.append(f" match ip address prefix-list {cl['match_pl']}")
            if cl["set"]:
                out.append(f" set {cl['set']}")
        out.append("!")
    if m["ospf"]:
        out.append(f"router ospf {m['ospf']['pid']}")
        if m["ospf"]["rid"]:
            out.append(f" router-id {m['ospf']['rid']}")
        for n in m["ospf"]["networks"]:
            out.append(f" network {n['net']} {n['wc']} area {n['area']}")
        out.append("!")
    if m["bgp"]:
        out.append(f"router bgp {m['bgp']['asn']}")
        if m["bgp"]["rid"]:
            out.append(f" bgp router-id {m['bgp']['rid']}")
        for ip, n in m["bgp"]["neighbors"].items():
            if n["remote_as"]:
                out.append(f" neighbor {ip} remote-as {n['remote_as']}")
            for rm, d in n["rm"]:
                out.append(f" neighbor {ip} route-map {rm} {d}")
        out.append("!")
    out.append("end")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ vault

class Vault:
    """AES-256-GCM encrypted, session-scoped mapping store."""

    def __init__(self, tenant, session, key: bytes = None):
        self.tenant, self.session = tenant, session
        self.key = key or AESGCM.generate_key(bit_length=256)

    def store(self, records, path):
        aes = AESGCM(self.key)
        with open(path, "wb") as f:
            for r in records:
                r = dict(r, tenant_id=self.tenant, session_id=self.session)
                pt = json.dumps(r, sort_keys=True).encode()
                nonce = os.urandom(12)
                ct = aes.encrypt(nonce, pt, self.session.encode())
                f.write(base64.b64encode(nonce + ct) + b"\n")

    def load(self, path):
        aes = AESGCM(self.key)
        out = []
        with open(path, "rb") as f:
            for line in f:
                raw = base64.b64decode(line.strip())
                out.append(json.loads(
                    aes.decrypt(raw[:12], raw[12:], self.session.encode())))
        return out


def run_pipeline(configs: dict, session_secret: bytes, site_of: dict,
                 lcs_enabled=True, retain_offset=True,
                 vrf_context_enabled=True, full_rdrt=False):
    """Full pipeline over a bundle of configs. Returns everything needed
    for validation."""
    models = {d: parse_config(d, t) for d, t in configs.items()}
    g_orig = build_graph(list(models.values()))
    # pre-pass: which sites see each subnet? (interface nets + BGP peer /30s)
    seen = {}
    for d, m in models.items():
        site = f"site:{site_of[d]}"
        for i in m["interfaces"]:
            if i["ip"]:
                net = ipaddress.ip_interface(f"{i['ip']}/{i['mask']}").network
                vctx = i["vrf"] or "global"
                seen.setdefault(f"{vctx}|{net}", set()).add(site)
        if m["bgp"]:
            for peer in m["bgp"]["neighbors"]:
                net = ipaddress.ip_interface(f"{peer}/30").network
                seen.setdefault(f"global|{net}", set()).add(site)
    override = {k: "tenant" for k, sites in seen.items() if len(sites) > 1}
    ob = Obfuscator(session_secret, list(models.values()),
                    subnet_scope_override=override,
                    lcs_enabled=lcs_enabled, retain_offset=retain_offset,
                    vrf_context_enabled=vrf_context_enabled,
                    full_rdrt=full_rdrt)
    obf_models, node_map = {}, {}
    for d, m in models.items():
        om = obfuscate_model(m, ob, site_scope=f"site:{site_of[d]}")
        obf_models[om["device_id"]] = om
        node_map[d] = om["device_id"]
    obf_text = {d: render_model(m) for d, m in obf_models.items()}
    g_obf = build_graph(list(obf_models.values()))
    return models, obf_models, obf_text, g_orig, g_obf, ob
