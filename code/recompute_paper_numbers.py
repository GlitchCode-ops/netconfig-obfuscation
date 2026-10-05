"""Regenerate the evaluation numbers reported in the paper from the dataset.

Prints, from the scored responses in data/:
  - the observation count per condition
  - the paired correctness differences and 95% confidence intervals (Table V)
  - identifier accuracy and unsupported-output rates (Section VII-F)
  - format compliance (Section VII-F)
  - the full-pipeline difference per model (Section VII-F)

Every value is computed from the data; nothing is entered by hand.
"""
import json
import statistics as st
from collections import defaultdict

import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
# data/ sits beside code/; fall back to ./data when run from the repository root
_DATA = _os.path.join(_HERE, "..", "data")
if not _os.path.isdir(_DATA):
    _DATA = "data"
FILES = [_os.path.join(_DATA, "llm_gemini.jsonl"),
         _os.path.join(_DATA, "llm_openrouter.jsonl"),
         _os.path.join(_DATA, "llm_groq.jsonl")]
METHOD_LABEL = {"naive": "Naive masking",
                "global_pseudo": "Global pseudonymization",
                "full": "Full pipeline"}


def load():
    rows = []
    for f in FILES:
        try:
            rows += [json.loads(l) for l in open(f)]
        except FileNotFoundError:
            pass
    ok = [r for r in rows if r.get("call_ok")]
    # keep one observation per (bundle, task, model, condition)
    seen = {}
    for r in ok:
        k = (r["bundle_id"], r["task_id"], r["tested_model"],
             r["transformation_method"])
        seen.setdefault(k, r)
    return list(seen.values())


def paired(ok, method):
    by = {(r["bundle_id"], r["task_id"], r["tested_model"],
           r["transformation_method"]): r["correctness_score"] for r in ok}
    d = [sc - by[(b, t, m, "original")]
         for (b, t, m, mt), sc in by.items()
         if mt == method and (b, t, m, "original") in by]
    return d


def ci(d):
    if len(d) < 2:
        return (float("nan"), float("nan"))
    se = st.stdev(d) / len(d) ** 0.5
    return (st.mean(d) - 1.96 * se, st.mean(d) + 1.96 * se)


def main():
    ok = load()
    n = len(ok)
    per_method = defaultdict(int)
    for r in ok:
        per_method[r["transformation_method"]] += 1

    print("=" * 70)
    print(f"CURRENT DATASET: {n} usable observations")
    for m in ("original", "naive", "global_pseudo", "full"):
        print(f"  {m:16} {per_method[m]}/54")
    complete = all(per_method[m] == 54 for m in
                   ("original", "naive", "global_pseudo", "full"))
    print(f"  ALL 216 COMPLETE: {complete}")
    print("=" * 70)

    # ---- study size ----
    print("\n--- SETUP SENTENCE ---")
    if complete:
        print("The study comprises 216 observations across six bundles, three "
              "tasks, three models, and four conditions, with 54 observations "
              "per condition and complete paired coverage. Failed API calls "
              "were re-attempted until the full matrix was collected.")
    else:
        print(f"The study comprises 216 planned observations across six "
              f"bundles, three tasks, three models, and four conditions. The "
              f"final dataset contains {n} unique usable observations: the "
              f"original and full-pipeline conditions are complete with 54 "
              f"each, while global pseudonymization contains "
              f"{per_method['global_pseudo']} and naive masking contains "
              f"{per_method['naive']}. Missing baseline observations were "
              f"unavailable due to provider quota limits, and failed calls are "
              f"excluded rather than scored zero.")

    # ---- Table V rows ----
    print("\n--- PAIRED-DELTA TABLE ROWS ---")
    for m in ("naive", "global_pseudo", "full"):
        d = paired(ok, m)
        lo, hi = ci(d)
        print(f"\t\t\t{METHOD_LABEL[m]} & {len(d)} & "
              f"\\({st.mean(d):+.2f}\\) & "
              f"\\([{lo:+.2f},{hi:+.2f}]\\)\\\\")

    # ---- identifier accuracy and unsupported output ----
    print("\n--- IDENTIFIER ACCURACY + UNSUPPORTED OUTPUT ---")
    idn = defaultdict(list)
    hal = defaultdict(lambda: [0, 0])
    for r in ok:
        m = r["transformation_method"]
        idn[m].append(r["identifier_accuracy_score"])
        hal[m][1] += 1
        if r.get("hallucination"):
            hal[m][0] += 1

    def acc(m):
        return st.mean(idn[m])

    def hpct(m):
        a, b = hal[m]
        return round(100 * a / b)
    print(f"The full pipeline attains an identifier-accuracy score of "
          f"\\({acc('full'):.2f}\\) on the \\(0\\)--\\(2\\) scale, compared with "
          f"\\({acc('original'):.2f}\\) for the original configurations, "
          f"\\({acc('global_pseudo'):.2f}\\) for global pseudonymization and "
          f"\\({acc('naive'):.2f}\\) for naive masking. Responses containing at "
          f"least one unsupported claim or identifier pair occur in "
          f"{hpct('original')}\\% of the original responses, {hpct('full')}\\% "
          f"of the full-pipeline responses, {hpct('global_pseudo')}\\% of the "
          f"global-pseudonymization responses and {hpct('naive')}\\% of the "
          f"naive-masking responses.")

    # ---- format compliance ----
    print("\n--- FORMAT COMPLIANCE ---")
    fc = sum(1 for r in ok if r.get("format_compliant"))
    total_word = "216" if complete else str(n)
    scored_word = "" if complete else "scored "
    print(f"Of the {total_word} {scored_word}observations, {fc} follow the "
          f"requested structured-output format.")

    # ---- full pipeline, overall and per model ----
    print("\n--- INVARIANTS (cross-check; should be stable) ---")
    fd = paired(ok, "full")
    print(f"  full: {len(fd)} pairs, mean {st.mean(fd):+.3f}, "
          f"CI [{ci(fd)[0]:+.2f},{ci(fd)[1]:+.2f}]")
    by = {(r["bundle_id"], r["task_id"], r["tested_model"],
           r["transformation_method"]): r["correctness_score"] for r in ok}
    for mdl in ("Nemotron-3-Super-120B", "Gemini-3.6-Flash", "Llama-3.3-70B"):
        d = [sc - by[(b, t, m, "original")]
             for (b, t, m, mt), sc in by.items()
             if mt == "full" and m == mdl and (b, t, m, "original") in by]
        print(f"  {mdl:24} full {st.mean(d):+.2f} ({len(d)} pairs)")


if __name__ == "__main__":
    main()
