"""Baseline comparison experiment.

Compares three approaches on identical workloads:
  B1  Naive masking: every sensitive occurrence replaced independently
      (fresh token / fresh random address per occurrence) -- models
      DLP-style scrubbers with no cross-reference model.
  B2  Address-only, prefix-preserving anonymization (Crypto-PAn-style):
      addresses mapped consistently at subnet granularity, but names,
      ASNs, and secrets untouched -- models applying trace-anonymization
      tooling to configuration files.
  OURS Full pipeline from pipeline.py.

Metrics per approach:
  - parseable            : output re-parses with zero unknown lines
  - refs_total/refs_ok   : reference-resolution closure
  - adj_orig/adj_kept    : /30 L3 adjacencies surviving in the graph
  - isomorphic           : type-labelled graph isomorphism vs original
  - leaked               : count of original sensitive values in output
"""

import hashlib
import ipaddress
import json
import os
import random
import re

from generator import generate_configs
from pipeline import parse_config, build_graph, run_pipeline, Obfuscator
from validate import v_security, IP_RE, STRUCTURAL

TOKEN_RE = re.compile(
    r"\b(CUST-[A-Z0-9-]+|PL-[A-Z0-9-]+|RM-[A-Z0-9-]+-IN|[a-z]+\d*-"
    r"(?:core|edge|agg|leaf)-\d+)\b")


def baseline_naive(configs, seed=99):
    """Fresh token / fresh random IP per occurrence."""
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

    for d, t in configs.items():
        t = IP_RE.sub(new_ip, t)
        t = TOKEN_RE.sub(new_tok, t)
        t = re.sub(r"(snmp-server community )\S+", r"\1MASKED", t)
        t = re.sub(r"(secret 5 )\S+", r"\1MASKED", t)
        t = re.sub(r"(crypto isakmp key )\S+", r"\1MASKED", t)
        # stable digest; Python's hash() is randomised per process
        out["DEV_%06d" % (int(hashlib.sha256(d.encode()).hexdigest()[:8], 16)
                          % 10**6)] = t
    return out


def baseline_addr_only(configs, devices):
    """Consistent, prefix-preserving subnet mapping; names/ASNs/secrets kept."""
    models = {d: parse_config(d, t) for d, t in configs.items()}
    ob = Obfuscator(b"baseline-secret", list(models.values()))
    out = {}
    for d, t in configs.items():
        def sub_ip(m):
            s = m.group(0)
            if STRUCTURAL.match(s):
                return s
            # subnet-consistent, global scope, /24 default granularity
            for plen in (30, 24, 32):
                try:
                    new, _ = ob.map_ip("tenant", s, prefixlen=plen)
                    return new
                except Exception:
                    continue
            return s
        out[d] = IP_RE.sub(sub_ip, t)
    return out


def measure(name, orig_configs, obf_configs):
    orig_models = [parse_config(d, t) for d, t in orig_configs.items()]
    obf_models = [parse_config(d, t) for d, t in obf_configs.items()]
    g_o, g_b = build_graph(orig_models), build_graph(obf_models)

    unknown = sum(len(m["unknown_lines"]) for m in obf_models)

    refs_total = refs_ok = 0
    for m in obf_models:
        vrfs = {v["name"] for v in m["vrfs"]}
        for i in m["interfaces"]:
            if i["vrf"]:
                refs_total += 1; refs_ok += i["vrf"] in vrfs
            for side in ("acl_in", "acl_out"):
                if i[side]:
                    refs_total += 1; refs_ok += i[side] in m["acls"]
        for clauses in m["route_maps"].values():
            for cl in clauses:
                if cl["match_pl"]:
                    refs_total += 1; refs_ok += cl["match_pl"] in m["prefix_lists"]
        if m["bgp"]:
            for nb in m["bgp"]["neighbors"].values():
                for rm, _ in nb["rm"]:
                    refs_total += 1; refs_ok += rm in m["route_maps"]

    def adjs(g):
        return sum(1 for _, _, d in g.edges(data=True)
                   if d.get("type") == "L3_ADJACENT_TO")
    from networkx.algorithms.isomorphism import (GraphMatcher,
                                                 categorical_node_match)
    iso = GraphMatcher(g_o, g_b,
                       node_match=categorical_node_match("type", None)
                       ).is_isomorphic()
    leaked = len(v_security({m["device_id"]: m for m in orig_models},
                            obf_configs))
    return {"approach": name, "parse_unknown_lines": unknown,
            "refs_total": refs_total, "refs_ok": refs_ok,
            "adj_orig": adjs(g_o), "adj_kept": adjs(g_b),
            "isomorphic": iso, "leaked_values": leaked}


def main(n_devices=25, seed=1234):
    configs, devices, links = generate_configs(n_devices, seed)
    site_of = {d.name: d.site for d in devices}

    b1 = baseline_naive(configs)
    b2 = baseline_addr_only(configs, devices)
    _, _, ours, _, _, _ = run_pipeline(configs, b"session-secret-0001", site_of)

    rows = [measure("naive", configs, b1),
            measure("addr-only", configs, b2),
            measure("ours", configs, ours)]
    _out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "data", "baseline_results.json")
    json.dump(rows, open(_out, "w"),
              indent=2)
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
