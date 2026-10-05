# Topology-Preserving Obfuscation of Network Configurations for LLM Analysis

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)

Code, data and results for the IEEE TPS 2026 paper *Topology-Preserving Obfuscation of Network Configurations for LLM Analysis* by Giannis Tziakouris and Nadhem Al-Fardan.

Network operators increasingly want to ask large language models about their router configurations, but those configurations contain addresses, ASNs, customer names and credentials that cannot leave the organization. Masking each value independently breaks the references between configurations, and consistent pseudonyms still destroy the subnet relationships that define the topology.

This repository implements a deterministic pipeline that replaces protected values while preserving what an LLM needs for analysis:

- **Scope-derived keyed mapping.** HMAC-SHA256 pseudonyms per device, site or tenant scope keep every reference consistent within a session and unlinkable across sessions.
- **Least-common-scope rule.** Subnets shared between sites are mapped under the tenant scope, so inter-site links survive.
- **Prefix- and host-offset-preserving addresses.** Prefix lengths, subnet membership and point-to-point adjacencies are kept.
- **Fail-closed validation.** Syntax, topology, reference-integrity and residual-value checks must pass before a bundle is released, and unclassified input lines block release.
- **Controlled reversibility.** Reversible mappings stay in an AES-256-GCM encrypted session vault; credentials are irreversibly redacted.
- **Return-path gate.** Identifiers in model responses are resolved only if they were issued in the current session.

> [!NOTE]
> This is a research prototype. It supports a defined Cisco IOS XE subset and has been evaluated on synthetic configurations only.

## Repository structure

```
.
├── code/
│   ├── pipeline.py                  parser, topology graph, keyed mapping, address allocation, vault, renderer
│   ├── validate.py                  four-layer validation and the structural experiment runner
│   ├── gate.py                      return-path gate for identifiers in model responses
│   ├── generator.py                 seeded synthetic Cisco IOS workload generator
│   ├── transforms.py                the four evaluated conditions: original, naive, global pseudonyms, full
│   ├── faults.py                    fault injection, ground truth and task prompts
│   ├── baselines.py                 structural measurement of each condition
│   ├── reproduce_structure.py       Table II and Table IV
│   ├── run_llm.py                   LLM study driver and programmatic scorer
│   ├── llm.py                       provider client with pacing, retries and call logging
│   ├── analyze.py                   LLM study analysis and return-path gate metrics
│   ├── recompute_paper_numbers.py   values reported in Section VII-F
│   ├── test_fixes.py                regression tests
│   └── test_graph_model.py          graph-model tests
├── data/                            LLM responses (raw and scored) and analysis outputs
├── results/                         regenerated tables and a worked example
├── requirements.txt
└── LICENSE
```

## Installation

Requires Python 3.12.

```bash
git clone https://github.com/GlitchCode-ops/netconfig-obfuscation.git
cd netconfig-obfuscation
pip install -r requirements.txt
```

No API keys are needed to run the pipeline, the tests or the analysis of the archived responses.

## Quick start

Obfuscate a five-device synthetic network and inspect one device:

```python
from generator import generate_configs
from pipeline import run_pipeline

configs, devices, _ = generate_configs(5, seed=1234)
site_of = {d.name: d.site for d in devices}          # device-to-site manifest

models, obf_models, obf_text, g_orig, g_obf, obfuscator = run_pipeline(
    configs, b"session-secret-0001", site_of)

print(next(iter(obf_text.values())))
```

Run it from `code/`. `obf_text` holds the obfuscated configurations, and `obfuscator.vault_records` holds the reversible mappings. `run_pipeline` does not release anything by itself: run the checks in `validate.py` (`v_unclassified`, `v_syntax`, `v_topology`, `v_logical` and `v_security`) and release the bundle only if all of them return no errors. `results/example_input_original.txt` and `results/example_output_obfuscated.txt` show one device before and after the pipeline.

Optional arguments of `run_pipeline`:

| Argument | Default | Effect |
| --- | --- | --- |
| `full_rdrt` | `False` | Also remaps RD/RT numeric suffixes under tenant scope |
| `retain_offset` | `True` | Preserves host offsets within mapped subnets |
| `lcs_enabled` | `True` | Applies the least-common-scope rule to shared subnets |

> [!IMPORTANT]
> The fixed session secret is used only to make the synthetic evaluation reproducible. Any real use must generate a fresh, cryptographically random secret per session, for example `secrets.token_bytes(32)`.

## Reproducing the paper

All commands run from `code/` and finish in a few seconds on a single vCPU.

| Paper result | Command | Output |
| --- | --- | --- |
| Regression and graph-model tests (Section VI) | `python3 test_fixes.py` and `python3 test_graph_model.py` | `6/6 passing`, `ALL GRAPH-MODEL TESTS PASS` |
| Validation across workload sizes (Section VII-C) | `python3 validate.py` | `data/results.json` |
| Structural comparison (Table II) and ablation (Table IV) | `python3 reproduce_structure.py` | `results/structure_tables.txt`, `data/structure_results.json` |
| LLM utility (Table V, Section VII-F) and return-path gate (Table VI) | `python3 analyze.py` | `results/analysis_full.txt`, `data/ANALYSIS.json` |
| Numbers quoted in Section VII-F | `python3 recompute_paper_numbers.py` | `results/paper_numbers.txt` |

The analysis scripts read the archived responses in `data/` and recompute every metric at run time, including the gate metrics, which are derived from the raw responses with the shipped gate implementation.

## Data

| File | Contents |
| --- | --- |
| `llm_gemini.jsonl`, `llm_groq.jsonl`, `llm_openrouter.jsonl` | Every call made for Gemini-3.6-Flash, Llama-3.3-70B and Nemotron-3-Super-120B, including failed calls |
| `llm_results_scored.jsonl` | The 215 usable scored observations merged from the three provider files |
| `raw_model_responses.jsonl` | Raw provider responses, used for the return-path gate evaluation |
| `ANALYSIS.json`, `results.json`, `baseline_results.json`, `structure_results.json` | Outputs of the analysis and validation scripts |

The study design has 216 cells: 6 bundles, 3 tasks, 3 models and 4 conditions. One naive-masking call could not be completed within provider quota, so 215 observations are usable. Failed calls are excluded rather than scored as zero. Provider account identifiers in logged error messages have been redacted.

All configurations are synthetic, generated with seed `1234`. No production data is included.

## Collecting new LLM responses

Collecting new responses requires API keys for the providers you use:

```bash
cd code
export GEMINI_API_KEY=...        # Gemini-3.6-Flash
export GROQ_API_KEY=...          # Llama-3.3-70B
export OPENROUTER_API_KEY=...    # Nemotron-3-Super-120B

python3 run_llm.py --models gemini --out ../data/llm_gemini.jsonl
```

Only successful calls count as done, so an interrupted run resumes where it stopped. Calls are paced to the providers' free-tier limits and logged to `raw_responses/calls.jsonl`.

## Citation

```bibtex
@inproceedings{tziakouris2026obfuscation,
  author    = {Tziakouris, Giannis and Al-Fardan, Nadhem},
  title     = {Topology-Preserving Obfuscation of Network Configurations for {LLM} Analysis},
  booktitle = {Proc. IEEE TPS},
  year      = {2026}
}
```

## License

Released under the [Apache License 2.0](LICENSE).
