"""Reproduce the structural comparison (Table II) and the ablation (Table IV).

Both tables use the 25-device synthetic workload (seed 1234) and the fixed
session secret used throughout the evaluation.

Run from code/:
    python3 reproduce_structure.py
"""
import json
import os

from networkx.algorithms.isomorphism import GraphMatcher, categorical_node_match

import baselines
import transforms
import validate
from generator import generate_configs
from pipeline import run_pipeline

SEED = 1234
SECRET = b"session-secret-0001"
N_DEVICES = 25
LABEL = {"original": "Original", "naive": "Naive masking",
         "global_pseudo": "Global pseudonymization", "full": "Full pipeline"}


def structural_comparison(configs, devices, site_of):
    rows = []
    for method in transforms.METHODS:
        text, _, _ = transforms.apply_method(method, configs, devices, site_of)
        m = baselines.measure(method, configs, text)
        rows.append({"condition": LABEL[method],
                     "resolved_refs": f"{m['refs_ok']}/{m['refs_total']}",
                     "preserved_adjacencies": f"{m['adj_kept']}/{m['adj_orig']}",
                     "isomorphic": m["isomorphic"],
                     "residual_strings": m["leaked_values"]})
    return rows


def ablation(configs, site_of):
    variants = [("Full pipeline", {}),
                ("No LCS elevation", {"lcs_enabled": False}),
                ("No offset retention", {"retain_offset": False})]
    rows = []
    for name, kwargs in variants:
        models, obf_models, _, g_orig, g_obf, ob = run_pipeline(
            configs, SECRET, site_of, **kwargs)
        iso = GraphMatcher(g_orig, g_obf,
                           node_match=categorical_node_match("type", None)
                           ).is_isomorphic()
        errs, links = validate.v_structure_claims(models, obf_models, ob)
        rows.append({"variant": name, "isomorphic": iso,
                     "divergent_subnets": sum("diverged" in e for e in errs),
                     "offset_errors": f"{sum('offset' in e for e in errs)}/{2 * links}"})
    return rows


def main():
    configs, devices, _ = generate_configs(N_DEVICES, SEED)
    site_of = {d.name: d.site for d in devices}
    table2 = structural_comparison(configs, devices, site_of)
    table4 = ablation(configs, site_of)

    print(f"Table II: structural comparison ({N_DEVICES}-device workload)")
    print(f"{'Condition':26} {'Refs':>9} {'Adj.':>7} {'Iso':>5} {'Residual':>9}")
    for r in table2:
        print(f"{r['condition']:26} {r['resolved_refs']:>9} "
              f"{r['preserved_adjacencies']:>7} {('Yes' if r['isomorphic'] else 'No'):>5} "
              f"{r['residual_strings']:>9}")
    print()
    print(f"Table IV: ablation ({N_DEVICES}-device workload)")
    print(f"{'Variant':22} {'Iso':>5} {'Divergent':>10} {'Offset errors':>14}")
    for r in table4:
        print(f"{r['variant']:22} {('Yes' if r['isomorphic'] else 'No'):>5} "
              f"{r['divergent_subnets']:>10} {r['offset_errors']:>14}")

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "data", "structure_results.json")
    with open(out, "w") as f:
        json.dump({"table2": table2, "table4": table4}, f, indent=2)
    print(f"\nwrote {os.path.normpath(out)}")


if __name__ == "__main__":
    main()
