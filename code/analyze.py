"""Analysis of the LLM utility study and the return-path gate.

Safe to run at any time, including on partial data. Writes ANALYSIS.json
beside the response files and prints a report.

Reporting rules enforced here (so partial data can never be over-claimed):
  * failed calls are EXCLUDED, never scored 0
  * every cell prints its own n; cells with n < 6 are marked THIN
  * the paired original-vs-method delta is computed only over (bundle, task,
    model) triples where BOTH conditions have a usable observation
"""
import json
import os
from collections import Counter, defaultdict


_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA = (os.path.join(_HERE, "..", "data")
         if os.path.isdir(os.path.join(_HERE, "..", "data")) else "data")


def _D(name):
    return os.path.join(_DATA, name)


FILES = [(_D("llm_gemini.jsonl"), "Gemini-3.6-Flash"),
         (_D("llm_openrouter.jsonl"), "Nemotron-3-Super-120B"),
         (_D("llm_groq.jsonl"), "Llama-3.3-70B")]
METHODS = ["original", "naive", "global_pseudo", "full"]
TASKS = ["T1_fault_detection", "T2_reference_resolution", "T3_topology"]
SHORT = {"T1_fault_detection": "T1 fault", "T2_reference_resolution": "T2 refs",
         "T3_topology": "T3 topo"}


def load():
    rows = []
    for f, _ in FILES:
        if os.path.exists(f):
            rows += [json.loads(l) for l in open(f)]
    return rows


def mean(v):
    return sum(v) / len(v) if v else None



def gate_recompute():
    """Recompute return-path gate metrics with the current gate implementation
    over the archived raw full-pipeline responses. Skips silently if the raw
    archive or pipeline modules are unavailable."""
    raw = _D("raw_model_responses.jsonl")
    if not os.path.exists(raw):
        return None
    try:
        import gate as G
        import transforms, faults
        from generator import generate_configs
    except ImportError:
        return None
    bundles = [("B1", "dangling_acl", 0), ("B2", "dangling_prefix_list", 1),
               ("B3", "p30_mismatch", 0), ("B4", "remote_as_mismatch", 2),
               ("B5", "clean", 0), ("B6", "dangling_acl", 3)]
    # The raw log records every provider call, including a few repeated calls
    # for the same (provider, bundle, task). Keep the last successful response
    # per call so each one is evaluated exactly once.
    latest = {}
    for ln in open(raw):
        r = json.loads(ln)
        m = r.get("meta") or {}
        if (r.get("status") == 200 and m.get("method") == "full"
                and (r.get("text") or "").strip()):
            latest[(r.get("provider"), m.get("bundle"), m.get("task"))] = r
    rows = list(latest.values())
    allr, nn, fp = [], [], 0
    for bid, fault, idx in bundles:
        cfg, dev, _ = generate_configs(5, 1234 + idx)
        so = {d.name: d.site for d in dev}
        fy, _gt = faults.inject(cfg, fault, idx)
        txt, _rev, ob = transforms.apply_method("full", fy, dev, so)
        g = G.Gate(ob.vault_records)
        numeric = {str(r["obfuscated_value"]) for r in ob.vault_records
                   if r["entity_type"] in ("asn", "aclnum")}
        nonnum = [t for t in g.issued
                  if str(t) not in numeric and not str(t).isdigit()]
        fp += len([t for t in g.extract("\n".join(txt.values()))
                   if t not in g.issued])
        for r in rows:
            if r.get("status") != 200:
                continue
            m = r.get("meta") or {}
            if m.get("method") != "full" or m.get("bundle") != bid:
                continue
            a, _, _ = g.measure_recall(r["text"], g.issued)
            b, _, _ = g.measure_recall(r["text"], nonnum)
            if a is not None:
                allr.append(a)
            if b is not None:
                nn.append(b)
    if not allr:
        return None
    return {"n_full_responses": len(rows),
            "n_responses": len(allr),
            "recall_all": sum(allr) / len(allr),
            "recall_nonnumeric": sum(nn) / len(nn),
            "perfect": "%d/%d" % (sum(1 for x in nn if x == 1.0), len(nn)),
            "false_positives": fp}


def main():
    rows = load()
    ok = [r for r in rows if r.get("call_ok")]
    out = {"usable": len(ok), "excluded": len(rows) - len(ok)}

    print("=" * 72)
    print("LLM UTILITY EXPERIMENT - FINAL ANALYSIS")
    print("=" * 72)
    print(f"usable observations : {len(ok)} / 216")
    print(f"excluded            : {len(rows) - len(ok)}")
    print(f"  reasons           : {dict(Counter(r['overall_result'] for r in rows if not r.get('call_ok')))}")
    print(f"by model            : {dict(Counter(r['tested_model'] for r in ok))}")

    # ---- per-cell correctness -------------------------------------------
    cell = defaultdict(list)
    for r in ok:
        cell[(r["transformation_method"], r["task_id"])].append(
            r["correctness_score"])
    print()
    print("MEAN CORRECTNESS (0-2), n in brackets, * = THIN (n<6)")
    print(f"{'method':16}" + "".join(f"{SHORT[t]:>18}" for t in TASKS))
    grid = {}
    for m in METHODS:
        line = f"{m:16}"
        for t in TASKS:
            v = cell[(m, t)]
            grid[f"{m}|{t}"] = {"n": len(v), "mean": mean(v)}
            if v:
                mark = "*" if len(v) < 6 else " "
                line += f"{mean(v):>13.2f}[{len(v)}]{mark}"
            else:
                line += f"{'-':>18}"
        print(line)
    out["cells"] = grid

    # ---- pooled by method ----------------------------------------------
    print()
    print("POOLED BY METHOD")
    pooled = {}
    for m in METHODS:
        v = [r["correctness_score"] for r in ok
             if r["transformation_method"] == m]
        idv = [r["identifier_accuracy_score"] for r in ok
               if r["transformation_method"] == m]
        hall = sum(1 for r in ok
                   if r["transformation_method"] == m and r.get("hallucination"))
        pooled[m] = {"n": len(v), "correctness": mean(v),
                     "identifier_accuracy": mean(idv),
                     "hallucination_rate": (hall / len(v)) if v else None}
        if v:
            print(f"  {m:16} n={len(v):3d} correctness={mean(v):.2f} "
                  f"ident_acc={mean(idv):.2f} hallucination={100*hall/len(v):.0f}%")
    out["pooled_by_method"] = pooled

    # ---- PAIRED comparison (the headline claim) -------------------------
    # Only triples where original AND the method both have a usable score.
    by_key = {}
    for r in ok:
        by_key[(r["bundle_id"], r["task_id"], r["tested_model"],
                r["transformation_method"])] = r["correctness_score"]
    print()
    print("PAIRED DELTA vs ORIGINAL (same bundle+task+model in both arms)")
    paired = {}
    for m in ["naive", "global_pseudo", "full"]:
        deltas = []
        for (b, t, mod, meth), sc in by_key.items():
            if meth != m:
                continue
            o = by_key.get((b, t, mod, "original"))
            if o is not None:
                deltas.append(sc - o)
            
        n_eq = sum(1 for d in deltas if d == 0)
        paired[m] = {"pairs": len(deltas), "mean_delta": mean(deltas),
                     "n_identical": n_eq,
                     "pct_identical": (100.0 * n_eq / len(deltas)) if deltas else None}
        if deltas:
            print(f"  {m:16} pairs={len(deltas):3d} mean_delta={mean(deltas):+.2f} "
                  f"identical_to_original={n_eq}/{len(deltas)} "
                  f"({100*n_eq/len(deltas):.0f}%)")
    out["paired_vs_original"] = paired

    # ---- per-task paired delta for `full` (topology is the key cell) ----
    print()
    print("PAIRED DELTA vs ORIGINAL, per task, method=full")
    per_task = {}
    for t in TASKS:
        d = []
        for (b, tt, mod, meth), sc in by_key.items():
            if meth == "full" and tt == t:
                o = by_key.get((b, tt, mod, "original"))
                if o is not None:
                    d.append(sc - o)
        per_task[t] = {"pairs": len(d), "mean_delta": mean(d)}
        if d:
            print(f"  {SHORT[t]:12} pairs={len(d):3d} mean_delta={mean(d):+.2f}")
    out["full_per_task_delta"] = per_task

    # ---- return-path gate on real prose --------------------------------
    gate_stats = gate_recompute()
    if gate_stats:
        out["gate"] = gate_stats
        print()
        print("RETURN-PATH GATE ON FULL-PIPELINE MODEL PROSE")
        print(f"  full-pipeline responses      : {gate_stats['n_full_responses']}")
        print(f"  responses with identifiers   : {gate_stats['n_responses']}")
        print(f"  recall, all identifier classes: {gate_stats['recall_all']:.3f}")
        print(f"  recall, excluding bare numerics: {gate_stats['recall_nonnumeric']:.3f}")
        print(f"  responses with perfect non-numeric recall: {gate_stats['perfect']}")
        print(f"  false positives on released output: {gate_stats['false_positives']}")

    # ---- format compliance / fallback usage ----------------------------
    fc = sum(1 for r in ok if r.get("format_compliant"))
    out["format_compliant"] = fc
    print()
    print(f"format-compliant responses: {fc} / {len(ok)}")

    json.dump(out, open(_D("ANALYSIS.json"), "w"), indent=1)
    print()
    print("wrote", _D("ANALYSIS.json"))


if __name__ == "__main__":
    main()
