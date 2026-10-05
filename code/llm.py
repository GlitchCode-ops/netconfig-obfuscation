"""Provider-agnostic LLM client with pacing, retry and full audit logging.

Every call is appended to raw_responses/calls.jsonl with the exact model string
returned by the provider, token usage, latency and retry count, so the study is
reproducible and rate-limit events are recorded.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request

LOG = "raw_responses/calls.jsonl"

PROVIDERS = {
    "gemini": {
        "kind": "gemini",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "key_env": "GEMINI_API_KEY",
        # Free tier: 5 requests per minute.
        "min_interval": 14.0,
    },
    "groq": {
        "kind": "openai",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "key_env": "GROQ_API_KEY",
        # The free tier is limited by tokens per minute (12k); a 5-device
        # bundle prompt is about 4.8k tokens, so at most two calls per minute.
        "min_interval": 28.0,
    },
    "openrouter": {
        "kind": "openai",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_API_KEY",
        "min_interval": 3.5,
    },
}

# A retry hint above this many seconds indicates a daily or organisation-level
# cap rather than a short sliding window; retrying inside a run cannot clear it.
RETRY_GIVEUP_S = 120.0

_HINT_MS = re.compile(r"retry in ([\d.]+)\s*ms", re.I)
_HINT_S = re.compile(r"(?:retry in|try again in)\s*([\d.]+)\s*s", re.I)
_HINT_HMS = re.compile(r"try again in\s*(?:(\d+)h)?(?:(\d+)m)?([\d.]+)s", re.I)


def _retry_hint(raw, headers=None):
    """Seconds to wait, parsed from the provider's response. None if absent."""
    ra = (headers or {}).get("retry-after") if headers else None
    if ra:
        try:
            return float(ra)
        except (TypeError, ValueError):
            pass
    m = _HINT_HMS.search(raw or "")
    if m and any(m.groups()):
        h, mi, sec = m.group(1), m.group(2), m.group(3)
        return (int(h or 0) * 3600) + (int(mi or 0) * 60) + float(sec)
    m = _HINT_MS.search(raw or "")
    if m:
        return float(m.group(1)) / 1000.0
    m = _HINT_S.search(raw or "")
    if m:
        return float(m.group(1))
    return None


_last_call = {}


# Some endpoints reject the default Python-urllib user agent, so an explicit
# one is sent.
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/125.0 Safari/537.36")


def _post(url, payload, headers, timeout=180):
    headers = dict(headers)
    headers.setdefault("User-Agent", UA)
    headers.setdefault("Accept", "application/json")
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode())


def call(provider, model, prompt, max_tokens=900, meta=None, max_retries=4):
    """Returns dict(text, model_reported, usage, latency_s, status, retries,
    error). Never raises on provider failure -- failures are recorded."""
    p = PROVIDERS[provider]
    key = os.environ.get(p["key_env"], "")
    if not key:
        return {"text": "", "error": f"missing {p['key_env']}", "status": 0,
                "retries": 0, "latency_s": 0.0, "model_reported": model,
                "usage": {}}

    gap = p["min_interval"] - (time.time() - _last_call.get(provider, 0))
    if gap > 0:
        time.sleep(gap)

    err, status, retries = None, 0, 0
    text, usage, model_rep = "", {}, model
    t_start = time.time()

    for attempt in range(max_retries + 1):
        retries = attempt
        try:
            if p["kind"] == "gemini":
                url = p["url"].format(model=model)
                # Reasoning tokens are billed against maxOutputTokens on
                # gemini-3.6-flash; give it headroom so the answer is not
                # truncated to an empty completion.
                gem_budget = max(max_tokens, 3000)
                payload = {"contents": [{"parts": [{"text": prompt}]}],
                           "generationConfig": {"maxOutputTokens": gem_budget,
                                                "temperature": 0}}
                hdr = {"x-goog-api-key": key, "content-type": "application/json"}
                status, body = _post(url, payload, hdr)
                cands = body.get("candidates") or []
                parts = (cands[0].get("content", {}).get("parts", [])
                         if cands else [])
                text = "".join(x.get("text", "") for x in parts)
                um = body.get("usageMetadata", {})
                usage = {"prompt_tokens": um.get("promptTokenCount"),
                         "completion_tokens": um.get("candidatesTokenCount"),
                         "total_tokens": um.get("totalTokenCount")}
                model_rep = body.get("modelVersion", model)
            else:
                payload = {"model": model, "max_tokens": max_tokens,
                           "temperature": 0,
                           "messages": [{"role": "user", "content": prompt}]}
                hdr = {"Authorization": f"Bearer {key}",
                       "content-type": "application/json"}
                status, body = _post(p["url"], payload, hdr)
                ch = body.get("choices") or []
                text = (ch[0].get("message", {}).get("content", "")
                        if ch else "") or ""
                usage = body.get("usage", {}) or {}
                model_rep = body.get("model", model)
            err = None
            if text.strip():
                break
            err = "empty_response"
        except urllib.error.HTTPError as e:
            status = e.code
            raw = ""
            try:
                raw = e.read().decode()
                err = json.loads(raw)
            except Exception:
                err = f"HTTP {e.code}"
            if e.code in (429, 500, 502, 503, 529):
                # Honour the provider's retry hint. A hint longer than
                # RETRY_GIVEUP_S signals a daily or organisation-level cap,
                # so the failure is recorded and the run moves on.
                hint = _retry_hint(raw, e.headers)
                if hint is not None and hint > RETRY_GIVEUP_S:
                    err = {"giving_up": True, "retry_after_s": hint,
                           "body": raw[:400]}
                    break
                wait = hint if hint is not None else min(8.0, 1.5 * (attempt + 1))
                time.sleep(min(wait + 0.35, 30.0))
                continue
            break
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            time.sleep(5 * (attempt + 1))
            continue

    _last_call[provider] = time.time()
    rec = {"provider": provider, "model": model, "model_reported": model_rep,
           "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "latency_s": round(time.time() - t_start, 2), "status": status,
           "retries": retries, "usage": usage,
           "error": (str(err)[:300] if err else None),
           "prompt_chars": len(prompt), "text": text, "meta": meta or {}}
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec
