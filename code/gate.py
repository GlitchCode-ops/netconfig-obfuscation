"""Return-path output gate for identifiers appearing in model prose.

Design notes.

(a) Derived surface forms. Subnet mappings are stored in the vault as CIDR
    ("10.117.0.0/24"), but configurations also emit the bare network address
    ("10.117.0.0"), e.g. an ACE base address paired with a wildcard. The gate
    therefore indexes each subnet record under its CIDR form, its bare network
    address and its broadcast address, so legitimate values are not flagged.

(b) Tolerant extraction. Model prose lowercases tokens, abuts them against
    punctuation, wraps them in markdown, and writes addresses with CIDR
    suffixes or trailing dots. `extract` is deliberately punctuation- and
    case-tolerant, and `measure_recall` reports the fraction of identifiers
    present in a response that the extractor recovers.

The security property: resolution is an exact-match lookup over values issued
in the current session. Tolerance is applied to *finding* candidates, never to
deciding whether a candidate was issued.
"""

import ipaddress
import re

# Candidate identifier shapes. Deliberately broad: over-extraction costs a
# fabricated-flag check, whereas under-extraction silently loses coverage.
RE_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
RE_TOKEN = re.compile(
    r"\b(?:CORE|EDGE|AGG|LEAF)_SITE_[A-Za-z2-7]{4,10}_\d+\b"
    # The site token is nested inside hostname tokens
    # (SITE_AHH4NZ inside AGG_SITE_AHH4NZ_3). \b does not match between "_"
    # and a word character, so "_" is also allowed as a left boundary.
    r"|(?:(?<=^)|(?<=[^A-Za-z0-9]))(?:VRF|PL|RM|HN|SITE|ACL)_[A-Za-z2-7]{4,10}\b"
    r"|(?<=_)(?:SITE)_[A-Za-z2-7]{4,10}\b",
    re.IGNORECASE)
# Bare numerics (ASNs, numbered ACLs) are only checked on explicit
# operator-requested resolution -- they are indistinguishable from ordinary
# numbers in prose. Kept separate so this limitation stays measurable.
RE_BARE_NUM = re.compile(r"\b\d{2,6}\b")

# A single alternation cannot recover the nested site token. The
# hostname branch matches AGG_SITE_AHH4NZ_3 and re.findall resumes AFTER that
# match, so the SITE_AHH4NZ contained inside it is never emitted. A separate
# overlapping pass recovers it.
RE_SITE = re.compile(r"SITE_[A-Za-z2-7]{4,10}", re.IGNORECASE)

STRUCTURAL_PREFIX = re.compile(r"^(0\.|255\.)")


def _norm(v):
    """Strip markdown/punctuation noise a model may attach to an identifier."""
    return v.strip().strip("`*_,;:.()[]{}<>\"'").rstrip(".")


class Gate:
    def __init__(self, vault_records):
        # issued -> original. Multiple surface forms may map to one record.
        self.resolve = {}
        self.issued = set()
        self.by_type = {}
        self.derived = set()

        # Pass 1: literal vault values only. These are authoritative.
        for r in vault_records:
            self._add(str(r["obfuscated_value"]), str(r["original_value"]),
                      r.get("entity_type", ""))

        # Pass 2: derived surface forms of subnet records, added only where a
        # literal record does not already define the value. Without the strict
        # ordering a /32 loopback subnet record would shadow the bare-address
        # `ip` record and resolve to an annotated CIDR instead of the address.
        for r in vault_records:
            if r.get("entity_type") != "subnet":
                continue
            obf, orig = str(r["obfuscated_value"]), str(r["original_value"])
            if "/" not in obf:
                continue
            try:
                net = ipaddress.ip_network(obf, strict=False)
                onet = ipaddress.ip_network(orig, strict=False)
            except ValueError:
                continue
            for synth, real in ((net.network_address, onet.network_address),
                                (net.broadcast_address,
                                 onet.broadcast_address)):
                s = str(synth)
                if s not in self.resolve:
                    self._add(s, str(real), "subnet")
                    self.derived.add(s)

    def _add(self, obf, orig, et):
        self.issued.add(obf)
        self.resolve.setdefault(obf, orig)
        self.by_type.setdefault(et, set()).add(obf)

    # ---------------------------------------------------------------- extract
    def extract(self, text, include_bare_numerics=False):
        """Return candidate identifiers found in free-form model prose."""
        cands = set()
        for m in RE_IPV4.findall(text):
            v = _norm(m)
            if STRUCTURAL_PREFIX.match(v):
                continue
            cands.add(v)
            if "/" in v:                      # also try the bare address
                cands.add(v.split("/")[0])
        for m in RE_TOKEN.findall(text):
            v = _norm(m)
            cands.add(v)
            cands.add(v.upper())              # model may lowercase a token
        if include_bare_numerics:
            for m in RE_BARE_NUM.findall(text):
                cands.add(_norm(m))
        # Overlapping pass for site tokens nested in hostnames
        for h in RE_SITE.findall(text):
            if h in self.issued or h.upper() in self.issued:
                cands.add(h)
        return {c for c in cands if c}

    # ----------------------------------------------------------------- verify
    @staticmethod
    def _identity(c):
        """Surface forms of one identifier collapse to a single identity, so a
        value is never reported as both resolved and fabricated. '10.1.2.0/24'
        and '10.1.2.0' are one identifier presented two ways."""
        return c.split("/")[0].upper()

    def check(self, text, include_bare_numerics=False):
        """Exact-match verification against the session's issued values.

        Grouping by identity first is what keeps the false-positive rate
        meaningful: without it, a model writing '10.1.2.0/24' yields a
        resolved bare form AND a fabricated CIDR form for the same value.
        """
        cands = self.extract(text, include_bare_numerics)
        groups = {}
        for c in cands:
            groups.setdefault(self._identity(c), set()).add(c)
        ok, fabricated = set(), set()
        for _ident, forms in groups.items():
            issued_forms = {f for f in forms if f in self.issued}
            if issued_forms:
                ok |= issued_forms
            else:
                # report the longest surface form for diagnosis
                fabricated.add(max(forms, key=len))
        return ok, fabricated

    def deobfuscate(self, text, include_bare_numerics=False):
        """Resolve issued values in place; leave unissued values untouched and
        report them, so a caller never silently trusts a fabricated id."""
        ok, fab = self.check(text, include_bare_numerics)
        out = text
        for v in sorted(ok, key=len, reverse=True):
            # (?!\d) blocks 10.1.1.1 matching inside 10.1.1.10; (?![\w])
            # still permits a sentence-final '.' or other punctuation.
            out = re.sub(rf"(?<![\w.]){re.escape(v)}(?!\d)(?![\w])",
                         self.resolve[v], out)
        return out, ok, fab

    # ------------------------------------------------------------------ recall
    def measure_recall(self, text, truth_ids):
        """Fraction of identifiers genuinely present in `text` that `extract`
        recovers. `truth_ids` are the identifiers known to be embedded."""
        present = {t for t in truth_ids if t.lower() in text.lower()}
        if not present:
            return None, 0, 0
        found = self.extract(text)
        found_ci = {f.lower() for f in found}
        hit = {t for t in present if t.lower() in found_ci}
        return len(hit) / len(present), len(hit), len(present)
