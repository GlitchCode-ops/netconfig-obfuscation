"""LLM utility + return-path study.

Design notes
------------
* Scoring is PROGRAMMATIC against injected ground truth. No LLM judge is used
  for the primary numbers, so every score is deterministic and reproducible.
* For obfuscating methods the model's answer is de-obfuscated through the
  method's reverse map BEFORE scoring. Utility and return-path integrity are
  therefore measured on the same responses.
* Identifier-shaped tokens in a response that are NOT in the issued set are
  recorded as fabricated.
"""
import argparse
import itertools
import json
import os
import re
import sys
import time

import faults
import gate
import llm
import transforms
from generator import generate_configs

ID_RE = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"
    r"|(?:VRF|PL|RM|HN|SITE|ACL|MASK)_[A-Z0-9]{4,8}"
    r"|(?:CORE|EDGE|AGG|LEAF)_SITE_[A-Z2-7]{6}_\d+"
    r"|[a-z]+\d*-(?:core|edge|agg|leaf)-\d+"
    r"|CUST-[A-Z0-9-]+|PL-[A-Z0-9-]+|RM-[A-Z0-9-]+-IN"
    r"|DEV_\d+)\b")

BUNDLES = [("B1", "dangling_acl", 0), ("B2", "dangling_prefix_list", 1),
           ("B3", "p30_mismatch", 0), ("B4", "remote_as_mismatch", 2),
           ("B5", "clean", 0), ("B6", "dangling_acl", 3)]

MODELS = [("gemini", "gemini-3.6-flash", "Gemini-3.6-Flash"),
          ("groq", "llama-3.3-70b-versatile", "Llama-3.3-70B"),
          ("openrouter", "nvidia/nemotron-3-super-120b-a12b:free",
           "Nemotron-3-Super-120B")]


def deobf(tok, rev):
    return rev.get(tok, tok)


def norm_dev(s, rev):
    s = s.strip().strip(".,;:`*'\"")
    return deobf(s, rev)


def parse_kv(text, key):
    m = re.search(rf"^\s*{key}\s*:\s*(.+)$", text, re.I | re.M)
    return m.group(1).strip() if m else ""


def parse_pairs(text):
    out = []
    for m in re.finditer(r"^\s*PAIR\s*:\s*(\S+)\s+(\S+)", text, re.I | re.M):
        out.append((m.group(1).strip(), m.group(2).strip()))
    return out


def _gate_for(rev):
    """Build the gate from a method's reverse map. Using the same Gate
    class for every obfuscating method keeps the return-path measurement
    comparable across methods, and gives all of them the derived-surface-form
    handling (bare network / broadcast address of a mapped subnet) whose
    absence otherwise produces false 'fabricated' verdicts."""
    recs = [{"obfuscated_value": k, "original_value": v,
             "entity_type": "subnet" if "/" in str(k) else "ip"}
            for k, v in rev.items()]
    return gate.Gate(recs)


def gate_metrics(text, rev, method):
    """Return-path measurement on real model responses.

    extraction_recall is the fraction of issued identifiers actually present
    in the response that the extractor recovers.
    """
    if method == "original":
        return {"ids_found": 0, "ids_resolved": 0, "ids_fabricated": 0,
                "extraction_recall": None, "recall_hit": 0, "recall_present": 0}
    g = _gate_for(rev)
    ok, fab = g.check(text)
    recall, hit, present = g.measure_recall(text, g.issued)
    return {"ids_found": len(ok) + len(fab), "ids_resolved": len(ok),
            "ids_fabricated": len(fab),
            "fabricated_examples": sorted(fab)[:5],
            "extraction_recall": (round(recall, 3) if recall is not None
                                  else None),
            "recall_hit": hit, "recall_present": present}


def score(task, text, gt, rev, method, bundle_devices):
    """Deterministic scoring -> the rubric fields."""
    g = gate_metrics(text, rev, method)
    res = {"correctness_score": 0, "identifier_accuracy_score": 0,
           "completeness_score": 0, "hallucination": False,
           "unissued_identifier": bool(g["ids_fabricated"]),
           "answerable": True, "brief_reason": ""}

    if task == "T1_fault_detection":
        f_pred = parse_kv(text, "FAULT").lower()
        d_pred_raw = parse_kv(text, "DEVICE")
        # If a reasoning model never emitted the tags, recover the
        # answer from prose and FLAG it, so tag-compliant and recovered answers
        # can be reported separately rather than silently mixed.
        res["answer_via_fallback"] = False
        if not f_pred:
            import faults as _f
            hits = [ft for ft in _f.FAULT_TYPES if ft in text.lower()]
            if len(hits) == 1:
                f_pred = hits[0]
                res["answer_via_fallback"] = True
        if not d_pred_raw:
            for d in bundle_devices:
                if d and d in text:
                    d_pred_raw = d
                    res["answer_via_fallback"] = True
                    break
        d_pred = norm_dev(d_pred_raw, rev)
        f_true = gt["fault"]
        f_true_norm = "none" if f_true == "clean" else f_true
        fault_ok = f_true_norm in f_pred or (f_true_norm == "none"
                                            and f_pred in ("none", "n/a", ""))
        dev_ok = (not gt["devices"] and d_pred.lower() in ("none", "", "n/a")) \
            or (gt["devices"] and d_pred in gt["devices"])
        res["correctness_score"] = 2 if (fault_ok and dev_ok) else (
            1 if fault_ok or dev_ok else 0)
        res["identifier_accuracy_score"] = 2 if dev_ok else (
            1 if d_pred_raw and d_pred != d_pred_raw else 0)
        res["completeness_score"] = 2 if (f_pred and d_pred_raw) else (
            1 if f_pred or d_pred_raw else 0)
        if f_true == "clean" and f_pred not in ("none", "n/a", ""):
            res["hallucination"] = True
        if d_pred_raw and d_pred not in bundle_devices and \
                d_pred.lower() not in ("none", "", "n/a"):
            res["hallucination"] = True
        res["brief_reason"] = f"pred fault={f_pred!r} dev={d_pred!r}; true={f_true_norm}/{gt['devices']}"

    elif task == "T2_reference_resolution":
        pred = {(norm_dev(a, rev), norm_dev(b, rev)) for a, b in parse_pairs(text)}
        true = {tuple(x) for x in gt["vrf_acl_pairs"]}
        inter = pred & true
        res["correctness_score"] = 2 if pred == true else (1 if inter else 0)
        res["completeness_score"] = 2 if len(inter) == len(true) else (
            1 if inter else 0)
        toks = [t for pr in parse_pairs(text) for t in pr]
        good = sum(1 for t in toks if norm_dev(t, rev) in
                   {x for p in true for x in p})
        res["identifier_accuracy_score"] = 2 if toks and good == len(toks) else (
            1 if good else 0)
        if pred - true:
            res["hallucination"] = True
        res["brief_reason"] = f"pred={sorted(pred)} true={sorted(true)}"

    elif task == "T3_topology":
        pred = {tuple(sorted((norm_dev(a, rev), norm_dev(b, rev))))
                for a, b in parse_pairs(text)}
        true = {tuple(x) for x in gt["adjacent_pairs"]}
        inter = pred & true
        res["correctness_score"] = 2 if pred == true else (1 if inter else 0)
        res["completeness_score"] = 2 if len(inter) == len(true) else (
            1 if inter else 0)
        allnames = {x for p in true for x in p}
        toks = [t for pr in parse_pairs(text) for t in pr]
        good = sum(1 for t in toks if norm_dev(t, rev) in allnames)
        res["identifier_accuracy_score"] = 2 if toks and good == len(toks) else (
            1 if good else 0)
        if pred - true:
            res["hallucination"] = True
        res["brief_reason"] = (f"pred={len(pred)} true={len(true)} "
                              f"correct={len(inter)} spurious={len(pred-true)}")

    tot = (res["correctness_score"] + res["identifier_accuracy_score"]
           + res["completeness_score"])
    res["overall_result"] = ("Correct" if tot == 6 else
                             "Partially Correct" if tot >= 2 else "Incorrect")
    res.update({f"gate_{k}": v for k, v in g.items()})
    return res


def build_cases(n_devices=5):
    cases = []
    for bid, fault, idx in BUNDLES:
        base, devices, links = generate_configs(n_devices, 1234 + idx)
        site_of = {d.name: d.site for d in devices}
        faulty, ground = faults.inject(base, fault, idx)
        # The T2 ground truth is computed for sorted(faulty)[0] in
        # ORIGINAL names. Resolve that same physical device to the name it
        # carries inside each transformed bundle, so every method is asked
        # about the identical device.
        gt_target = sorted(faulty)[0]
        for method in transforms.METHODS:
            text, rev, ob = transforms.apply_method(
                method, faulty, devices, site_of)
            fwd = {orig: obf for obf, orig in rev.items()}
            tgt = fwd.get(gt_target, gt_target)
            if tgt not in text:
                # fall back to reverse-mapping each bundle key
                for k in text:
                    if rev.get(k, k) == gt_target:
                        tgt = k
                        break
            for task in faults.TASKS:
                gt = faults.task_ground_truth(task, faulty, ground)
                prompt = faults.build_prompt(task, text, target_device=tgt)
                cases.append({"bundle_id": bid, "fault": fault, "task": task,
                              "method": method, "prompt": prompt, "gt": gt,
                              "rev": rev,
                              "bundle_devices": sorted(faulty)})
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="gemini")
    ap.add_argument("--bundles", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="data/llm_results.jsonl")
    ap.add_argument("--priority", action="store_true",
                    help="schedule full + original pairs first, then "
                         "global_pseudo, then naive")
    args = ap.parse_args()

    want = set(args.models.split(","))
    models = [m for m in MODELS if m[0] in want]
    cases = build_cases()
    if args.bundles:
        keep = set(args.bundles.split(","))
        cases = [c for c in cases if c["bundle_id"] in keep]

    # Only a successful call counts as done, so an interrupted run resumes
    # and retries every failed call.
    done, failed_rows = set(), 0
    if os.path.exists(args.out):
        for ln in open(args.out):
            r = json.loads(ln)
            key = (r["bundle_id"], r["task_id"], r["transformation_method"],
                   r["tested_model"])
            if r.get("call_ok"):
                done.add(key)
            else:
                failed_rows += 1
    if failed_rows:
        print(f"note: {failed_rows} previously-failed rows will be retried")

    todo = [(c, m) for m in models for c in cases
            if (c["bundle_id"], c["task"], c["method"], m[2]) not in done]
    if args.priority:
        # Under a daily quota, collect the paired `full`/`original`
        # comparison first and the baselines last.
        rank = {"full": 0, "original": 1, "global_pseudo": 2, "naive": 3}
        todo.sort(key=lambda x: (rank.get(x[0]["method"], 9),
                                 x[0]["bundle_id"], x[0]["task"]))
    if args.limit:
        todo = todo[:args.limit]
    print(f"{len(todo)} calls to make ({len(done)} already done)")

    for k, (c, (prov, model, label)) in enumerate(todo, 1):
        # Reasoning-style models spend many tokens before emitting the
        # required tags; a generous budget avoids truncated answers.
        r = llm.call(prov, model, c["prompt"], max_tokens=8000, meta={
            "bundle": c["bundle_id"], "task": c["task"], "method": c["method"]})
        call_ok = (r["status"] == 200 and bool(r["text"].strip()))
        # Format compliance is tracked separately from correctness so the two
        # are never conflated in the reported means.
        fmt_ok = bool(re.search(r"^\s*(FAULT|DEVICE|PAIR)\s*:", r["text"],
                                re.I | re.M)) if call_ok else None
        if call_ok:
            sc = score(c["task"], r["text"], c["gt"], c["rev"], c["method"],
                       c["bundle_devices"])
        else:
            # A transport/quota failure is not evidence about the model's
            # ability. Scoring it 0 would silently bias every mean downward,
            # so failed calls are excluded instead.
            sc = {"correctness_score": None,
                  "identifier_accuracy_score": None,
                  "completeness_score": None, "hallucination": None,
                  "unissued_identifier": None, "answerable": None,
                  "overall_result": "ExcludedCallFailed",
                  "brief_reason": f"call failed status={r['status']}"}
        sc["call_ok"] = call_ok
        sc["format_compliant"] = fmt_ok
        row = {"bundle_id": c["bundle_id"], "task_id": c["task"],
               "task_type": c["task"], "tested_model": label,
               "transformation_method": c["method"], "fault": c["fault"],
               **sc,
               "provider": prov, "model_reported": r["model_reported"],
               "status": r["status"], "error": r["error"],
               "latency_s": r["latency_s"], "usage": r["usage"],
               "retries": r["retries"], "response_chars": len(r["text"])}
        with open(args.out, "a") as f:
            f.write(json.dumps(row) + "\n")
        print(f"[{k}/{len(todo)}] {label:22s} {c['bundle_id']} {c['task'][:4]} "
              f"{c['method']:14s} -> {row['overall_result']:18s} "
              f"c{sc['correctness_score']} i{sc['identifier_accuracy_score']} "
              f"m{sc['completeness_score']} "
              f"{'HALL' if sc['hallucination'] else ''}"
              f"{' ERR:' + str(r['status']) if r['error'] else ''}",
              flush=True)


if __name__ == "__main__":
    main()
