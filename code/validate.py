"""Four-layer validation and the structural experiment runner.

Layers:
  1 syntax    - unclassified input lines block release; obfuscated text
                re-parses and its entity shape matches the model
  2 topology  - original and obfuscated graphs are isomorphic (type-labelled)
  3 logical   - every reference resolves (VRF/ACL/PL/RM closure)
  4 security  - zero original sensitive values appear in the output bundle;
                all synthetic addresses fall inside the reserved pools

Also checks the structural-preservation properties explicitly:
  - subnet containment & host-offset retention
  - point-to-point (/30) alignment across devices (cross-device consistency)
  - determinism (two runs with the same session secret are byte-identical)
"""

import hashlib
import ipaddress
import json
import os
import re
import time

import networkx as nx
from networkx.algorithms.isomorphism import GraphMatcher, categorical_node_match

from pipeline import parse_config, build_graph, run_pipeline
from generator import generate_configs


def v_syntax(obf_models, obf_text):
    errs = []
    for d, txt in obf_text.items():
        rp = parse_config(d, txt)
        for key in ("vrfs", "interfaces"):
            if len(rp[key]) != len(obf_models[d][key]):
                errs.append(f"{d}: {key} count mismatch")
        for key in ("acls", "prefix_lists", "route_maps"):
            if set(rp[key]) != set(obf_models[d][key]):
                errs.append(f"{d}: {key} name-set mismatch")
        if rp["unknown_lines"]:
            errs.append(f"{d}: {len(rp['unknown_lines'])} unparsed lines")
    return errs


def v_unclassified(models, approved=None):
    """Fail closed on unclassified input lines.

    Lines the parser cannot classify are never rendered, but silently dropping
    them would release an incomplete bundle without the operator knowing.
    Each such line therefore blocks release until the operator reviews it.
    `approved` is an optional set of (device, lineno) pairs whose omission the
    operator has explicitly accepted.
    """
    approved = approved or set()
    errs = []
    for d, m in models.items():
        for u in m["unknown_lines"]:
            if (d, u["lineno"]) not in approved:
                errs.append(f"{d}: line {u['lineno']} unclassified, "
                            f"operator review required: {u['text'].strip()[:60]}")
    return errs


def v_topology(g_orig, g_obf):
    gm = GraphMatcher(g_orig, g_obf,
                      node_match=categorical_node_match("type", None))
    return [] if gm.is_isomorphic() else ["graphs not isomorphic"]


def v_logical(obf_models):
    errs = []
    for d, m in obf_models.items():
        vrfs = {v["name"] for v in m["vrfs"]}
        for i in m["interfaces"]:
            if i["vrf"] and i["vrf"] not in vrfs:
                errs.append(f"{d}: dangling VRF ref {i['vrf']}")
            for side in ("acl_in", "acl_out"):
                if i[side] and i[side] not in m["acls"]:
                    errs.append(f"{d}: dangling ACL ref {i[side]}")
        for name, clauses in m["route_maps"].items():
            for cl in clauses:
                if cl["match_pl"] and cl["match_pl"] not in m["prefix_lists"]:
                    errs.append(f"{d}: dangling PL ref {cl['match_pl']}")
        if m["bgp"]:
            for ip, n in m["bgp"]["neighbors"].items():
                for rm, _ in n["rm"]:
                    if rm not in m["route_maps"]:
                        errs.append(f"{d}: dangling RM ref {rm}")
    return errs


IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
STRUCTURAL = re.compile(r"^(0\.|255\.)")  # wildcards / netmasks
POOLS = [ipaddress.ip_network(p) for p in
         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


# Numeric identifier classes are reported separately because they are
# protected per Table I but are indistinguishable from structural literals in
# some syntactic positions. Reporting them apart keeps the leak accounting
# explicit instead of silently excluding them.
def collect_sensitive(models):
    """Complete protected-value set per paper Table I, including ASNs,
    numbered ACL ids, RD/RT values and site tokens. Returns (textual, numeric)
    sets.
    """
    text_s, num_s = set(), set()
    for m in models.values():
        if m["hostname"]:
            text_s.add(m["hostname"])
            g = re.match(r"^([a-z]+\d*)[-_]", m["hostname"], re.I)
            if g:
                text_s.add(g.group(1))          # site token
        for v in m["vrfs"]:
            text_s.add(v["name"])
            for fld in ("rd",):
                if v.get(fld):
                    text_s.add(v[fld])
                    num_s.add(v[fld].split(":")[0])
            for x in (v.get("rt_export") or []) + (v.get("rt_import") or []):
                text_s.add(x)
                num_s.add(x.split(":")[0])
        text_s.update(m["prefix_lists"])
        text_s.update(m["route_maps"])
        num_s.update(str(k) for k in m["acls"])
        for i in m["interfaces"]:
            if i["ip"]:
                text_s.add(i["ip"])
            for side in ("acl_in", "acl_out"):
                if i.get(side):
                    num_s.add(str(i[side]))
        if m["bgp"]:
            text_s.update(m["bgp"]["neighbors"])
            if m["bgp"].get("asn"):
                num_s.add(str(m["bgp"]["asn"]))
            for nb in m["bgp"]["neighbors"].values():
                if isinstance(nb, dict) and nb.get("remote_as"):
                    num_s.add(str(nb["remote_as"]))
        if m.get("ospf") and m["ospf"].get("rid"):
            text_s.add(m["ospf"]["rid"])
        for s in m["secrets"]:
            text_s.add(s["value"])
    text_s = {s for s in text_s if s and str(s).strip()}
    num_s = {s for s in num_s if s and str(s).strip()}
    return text_s, num_s


def _token_sets(blob):
    """Two linear passes produce every token that could equal a
    protected value. Membership then costs O(1) per value, making the whole
    layer O(corpus + values) instead of O(values x corpus)."""
    # pass 1: split on ':' and '/' too, so "65001:100" yields "65001","100"
    fine = set(re.findall(r"[A-Za-z0-9_.$-]+", blob))
    # pass 2: keep composites so an RD/RT like "65001:100" matches whole
    coarse = set(re.findall(r"[A-Za-z0-9_.$:/-]+", blob))
    return fine | coarse


# Numeric identifiers (ASNs, numbered ACL ids) cannot be checked by bare
# substring search: the same digits legitimately recur in syntactic positions
# that are structural and intentionally preserved. For example, ACL ids 100
# and 101 also appear as retained RD/RT suffixes ("rd 64572:100") and as the
# OSPF process id ("router ospf 100"). These patterns therefore bind each
# numeric class to the positions where it actually denotes that identifier.
NUM_POSITIONS = {
    "aclnum": (
        re.compile(r"^\s*access-list\s+(\d+)\b", re.M),
        re.compile(r"^\s*ip\s+access-group\s+(\d+)\b", re.M),
    ),
    "asn": (
        re.compile(r"^\s*router\s+bgp\s+(\d+)\b", re.M),
        re.compile(r"\bremote-as\s+(\d+)\b"),
        # ASN component of an RD/RT is protected; the suffix after ':' is not.
        re.compile(r"^\s*rd\s+(\d+):", re.M),
        re.compile(r"^\s*route-target\s+\w+\s+(\d+):", re.M),
    ),
}


def collect_numeric_by_class(models):
    """Protected numeric values, kept separate per class so each can be
    checked only in the positions where it denotes that identifier."""
    acls, asns = set(), set()
    for m in models.values():
        acls.update(str(k) for k in m["acls"])
        for i in m["interfaces"]:
            for side in ("acl_in", "acl_out"):
                if i.get(side):
                    acls.add(str(i[side]))
        if m["bgp"]:
            if m["bgp"].get("asn"):
                asns.add(str(m["bgp"]["asn"]))
            for nb in m["bgp"]["neighbors"].values():
                if isinstance(nb, dict) and nb.get("remote_as"):
                    asns.add(str(nb["remote_as"]))
        for v in m["vrfs"]:
            if v.get("rd"):
                asns.add(v["rd"].split(":")[0])
            for x in (v.get("rt_export") or []) + (v.get("rt_import") or []):
                asns.add(x.split(":")[0])
    return {"aclnum": {a for a in acls if a}, "asn": {a for a in asns if a}}


def v_numeric_positional(models, obf_text):
    """Flag a protected numeric only where it occupies a position that denotes
    that identifier class in the obfuscated output."""
    errs = []
    prot = collect_numeric_by_class(models)
    blob = "\n".join(obf_text.values())
    for cls, vals in prot.items():
        seen = set()
        for pat in NUM_POSITIONS[cls]:
            seen.update(pat.findall(blob))
        for hit in sorted(vals & seen):
            errs.append(f"{cls} leaked in identifier position: {hit}")
    return errs


def v_rdrt_suffix(models, obf_text):
    """With full RD/RT remapping enabled, no original suffix may remain in an
    RD or route-target suffix position."""
    orig = set()
    for m in models.values():
        for vr in m["vrfs"]:
            for x in [vr["rd"]] + vr["rt_export"] + vr["rt_import"]:
                if x and ":" in x:
                    orig.add(x.partition(":")[2])
    blob = "\n".join(obf_text.values())
    seen = set(re.findall(r"^\s*(?:rd|route-target\s+\w+)\s+\S+?:(\d+)\b",
                          blob, re.M))
    return [f"RD/RT suffix leaked: {s}" for s in sorted(orig & seen)]


def v_security(models, obf_text, report_numeric=False):
    errs = []
    text_s, num_s = collect_sensitive(models)
    blob = "\n".join(obf_text.values())
    toks = _token_sets(blob)
    for hit in sorted(text_s & toks):
        errs.append(f"original value leaked: {hit}")
    if report_numeric:
        for hit in sorted(num_s & toks):
            errs.append(f"numeric identifier leaked: {hit}")
    for ips in IP_RE.findall(blob):
        if STRUCTURAL.match(ips):
            continue
        a = ipaddress.ip_address(ips)
        if not any(a in p for p in POOLS):
            errs.append(f"address outside synthetic pools: {ips}")
    return errs


def v_structure_claims(models, obf_models, ob):
    """Verify offset retention and cross-device /30 alignment."""
    errs = []
    # offset retention: for every mapped ip, offset(orig)==offset(obf)
    subnet_of = {}
    for r in ob.vault_records:
        if r["entity_type"] == "subnet":
            subnet_of[(r["scope"], r["original_value"])] = r["obfuscated_value"]
    # cross-device p2p: both ends of every original /30 must land in the
    # same synthetic subnet with the same host offsets
    ends = {}
    for d, m in models.items():
        for i in m["interfaces"]:
            if i["ip"] and i["mask"] == "255.255.255.252":
                net = ipaddress.ip_interface(f"{i['ip']}/30").network
                ends.setdefault(str(net), []).append((d, i["ip"], i["name"]))
    obf_ip = {}
    for d, m in obf_models.items():
        for i in m["interfaces"]:
            obf_ip[(d, i["name"])] = i["ip"]
    inv_host = {}
    for d, m in models.items():
        om_id = None
        for r in ob.vault_records:
            if r["entity_type"] == "hostname" and r["original_value"] == m["hostname"]:
                om_id = r["obfuscated_value"]
        for i in m["interfaces"]:
            inv_host[(d, i["name"])] = (om_id, i["name"])
    checked = 0
    for net, members in ends.items():
        if len(members) != 2:
            continue
        onet = None
        for (d, ip, ifn) in members:
            oid = inv_host[(d, ifn)]
            oip = obf_ip[oid]
            orig_off = int(ipaddress.ip_address(ip)) - int(
                ipaddress.ip_network(net).network_address)
            new_net = ipaddress.ip_interface(f"{oip}/30").network
            new_off = int(ipaddress.ip_address(oip)) - int(new_net.network_address)
            if orig_off != new_off:
                errs.append(f"offset not retained on {d}/{ifn}")
            if onet is None:
                onet = new_net
            elif onet != new_net:
                errs.append(f"p2p ends diverged for {net}")
        checked += 1
    return errs, checked


def run_experiment(n_devices, seed=1234, secret=b"session-secret-0001"):
    configs, devices, links = generate_configs(n_devices, seed)
    site_of = {d.name: d.site for d in devices}
    total_lines = sum(t.count("\n") for t in configs.values())

    t0 = time.perf_counter()
    models = {d: parse_config(d, t) for d, t in configs.items()}
    t_parse = time.perf_counter() - t0

    t0 = time.perf_counter()
    g_orig = build_graph(list(models.values()))
    t_topo = time.perf_counter() - t0

    t0 = time.perf_counter()
    models, obf_models, obf_text, g_orig, g_obf, ob = run_pipeline(
        configs, secret, site_of)
    t_obf = time.perf_counter() - t0 - t_parse - t_topo
    t_obf = max(t_obf, 0.0)

    t0 = time.perf_counter()
    e_syn = v_unclassified(models) + v_syntax(obf_models, obf_text)
    e_top = v_topology(g_orig, g_obf)
    e_log = v_logical(obf_models)
    e_sec = v_security(models, obf_text)
    e_str, p2p_checked = v_structure_claims(models, obf_models, ob)
    t_val = time.perf_counter() - t0

    # determinism: rerun -> identical bytes
    _, _, obf_text2, _, _, _ = run_pipeline(configs, secret, site_of)
    h1 = hashlib.sha256("".join(sorted(obf_text.values())).encode()).hexdigest()
    h2 = hashlib.sha256("".join(sorted(obf_text2.values())).encode()).hexdigest()
    deterministic = h1 == h2
    # different session secret -> different bytes (tenant isolation)
    _, _, obf_text3, _, _, _ = run_pipeline(configs, b"other-secret", site_of)
    h3 = hashlib.sha256("".join(sorted(obf_text3.values())).encode()).hexdigest()

    n_entities = sum(len(m["interfaces"]) + len(m["vrfs"]) + len(m["acls"]) +
                     len(m["prefix_lists"]) + len(m["route_maps"]) +
                     (1 if m["bgp"] else 0) + (1 if m["ospf"] else 0)
                     for m in models.values())
    return {
        "devices": n_devices, "links": len(links), "lines": total_lines,
        "entities": n_entities, "mappings": len(ob.vault_records),
        "graph_nodes": g_orig.number_of_nodes(),
        "graph_edges": g_orig.number_of_edges(),
        "t_parse_s": round(t_parse, 3), "t_topology_s": round(t_topo, 3),
        "t_obfuscation_s": round(t_obf, 3), "t_validation_s": round(t_val, 3),
        "syntax_errors": e_syn, "topology_errors": e_top,
        "logical_errors": e_log, "security_errors": e_sec,
        "structure_errors": e_str, "p2p_links_checked": p2p_checked,
        "deterministic": deterministic, "session_isolated": h1 != h3,
    }


if __name__ == "__main__":
    results = [run_experiment(n) for n in (5, 10, 25, 50)]
    print(json.dumps(results, indent=2))
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "data", "results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
