#!/usr/bin/env python3
"""
GQLProbe — GraphQL Security Tester
PNY Trainings, API Security — Final Project, Ibrar Ahmed
Deadline: Tuesday, 25 November 2026

WHAT IT DOES
  You give it a GraphQL endpoint URL and a lab token. It sends the
  standard introspection query and records whether the full schema
  comes back, parses the schema into query/mutation fields with
  arguments, probes query depth with nested queries, tests batching
  by sending arrays of queries in one request, and replays data
  queries without a token to find fields that answer without
  authorization. Then it goes further than the PDF: introspection
  bypasses, alias / field-duplication / directive overloading,
  engine fingerprinting, BOLA/IDOR, field guessing via wordlist and
  suggestion mining, harmless mutation testing, timing comparison
  with rate-limit detection, sensitive-field flagging, complexity
  estimation, a GET/CSRF check, an argument-injection check and a
  schema snapshot + diff. Every probe has a verdict with evidence,
  and the result is saved to a report (text or JSON).

THEME — RED (chosen by the user, like PipeSentry): the banner is
red, separators and headers are red (ACCENT), highlights are orange
(ACCENT2). All colours live in class C below, so the theme changes
in one place.

THE 6 MUST-HAVE FEATURES (PDF) — all in this file:
  1. Standard introspection query, schema returned or refused
     -> probe_introspection()
  2. Schema parsed into query/mutation fields with argument names
     -> parse_schema()
  3. Depth probe, nested queries of increasing depth
     -> probe_depth()
  4. Batching probe, array of queries in one request
     -> probe_batching()
  5. Authorization probe, replay without a token
     -> probe_authz()
  6. Report saved to a file, verdict + evidence per probe
     -> build_report_text() / build_report_json()

INSTALL — the probe needs NOTHING installed (SSTIProbe pattern):
  plain Python 3 is enough: it uses requests when installed,
  otherwise the standard library (urllib). Only the LAB needs
  nothing at all (stdlib http.server):
    python run.py setup        # venv + requests, first time only
  Or skip setup entirely for the probe:
    python3 gqlprobe.py http://127.0.0.1:4000/graphql

USAGE — three ways, same tool:
  Menu (default when run with no args):
    python run.py probe
      [ 1] Probe an endpoint
      [ 2] Quick probe vulnerable lab
      [ 3] Quick probe hardened lab
      [ 4] Quick probe partial lab (suggestions on)
      [ 5] List all probes
      [ 6] Show schema fields
      [ 7] Run step tests
      [ 8] Check setup (doctor)
      [ 9] Start lab server
      [ 0] Exit
      [ ? ] Select option :

  With arguments (for scripts / demo):
    python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
    python run.py probe http://127.0.0.1:4000/graphql -o report.txt
    python run.py probe http://127.0.0.1:4000/graphql --json -o report.json
    python run.py probe http://127.0.0.1:4000/graphql --probe depth
    python run.py probe --version
    python run.py probe --no-color

LAB ONLY — only probe GraphQL APIs you own or have written
permission to test (your own lab API, your own app). Probing a real
API without permission is unauthorized access (Prevention of
Electronic Crimes Act, 2016, Pakistan).
"""

import argparse
import difflib
import json
import os
import random
import re
import socket
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime

# Zero-dependency probe (SSTIProbe pattern): requests is preferred
# when installed, otherwise the standard library (urllib).
try:
    import requests

    HAVE_REQUESTS = True
except ImportError:  # noqa: BLE001 - requests simply is not installed
    requests = None  # type: ignore[assignment]
    HAVE_REQUESTS = False

VERSION = "1.2"
AUTHOR = "CyberBoy50"
DISCLAIMER = ("DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for "
              "ethical, authorized security testing only. You are using it "
              "on your own responsibility. The authors are not responsible "
              "for how you use it, or for anything that happens because of "
              "your use. Only test systems, code, and data you own or have "
              "explicit written permission to test — testing anything else "
              "may be illegal (for example, PECA 2016 in Pakistan).")
QUIET = False
# Theme: RED (user's choice, like PipeSentry). Change ACCENT /
# ACCENT2 here and the whole tool re-themes.
THEME = "Red"

# --- Colours, TraceRecon style: one class, short names ------------------
# PipeSentry does the same, with ACCENT = red. GQLProbe copies it:
# the theme lives here and nowhere else.
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GRN = "\033[1;32m"
    YEL = "\033[1;33m"
    BLU = "\033[1;34m"
    MAG = "\033[1;35m"
    CYN = "\033[1;36m"
    WHT = "\033[1;37m"
    # Old names, kept working.
    GREEN = GRN
    YELLOW = YEL
    BLUE = BLU
    CYAN = CYN
    BOLD = BLD
    RESET = RST

    @classmethod
    def disable(cls):
        # Clear the class AND the module-level aliases (RED, ACCENT,
        # ...), otherwise --no-color would leave colours behind: the
        # aliases are bound at import time, so clearing only the class
        # does nothing. (The sibling tools only clear the class.)
        for attr in ("RST", "BLD", "DIM", "RED", "GRN", "YEL", "BLU",
                     "MAG", "CYN", "WHT", "GREEN", "YELLOW", "BLUE",
                     "CYAN", "BOLD", "RESET"):
            setattr(cls, attr, "")
        g = globals()
        for name in ("RED", "GREEN", "YELLOW", "CYAN", "BOLD", "RESET",
                     "ACCENT", "ACCENT2"):
            g[name] = ""


RED = C.RED
GREEN = C.GRN
YELLOW = C.YEL
CYAN = C.CYN
BOLD = C.BLD
RESET = C.RST
ACCENT = C.RED      # GQLProbe theme: red separators / brackets
ACCENT2 = C.YEL     # GQLProbe theme: orange highlights


def clear():
    """Clear the screen — GhostTrack / TraceRecon pattern."""
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=None, char="─", width=58):
    """A rule line, TraceRecon style: sep(C.RED, '─') / sep(C.RED, '═').
    The colour is resolved at call time (not as a default argument),
    so --no-color works: the default was bound at import time and
    would otherwise keep the old escape codes."""
    if color is None:
        color = ACCENT
    print(f"{color}{char * width}{C.RST}")


def header(title, color=None):
    """A titled section header with rule lines above and below."""
    if color is None:
        color = ACCENT
    sep(color)
    print(f"{color} {title}{C.RST}")
    sep(color)


def ok(msg):
    """[+] success line: ' [+] message' — white brackets, green plus."""
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    """[!] warning line, yellow."""
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    """[x] error line, red."""
    print(f" {C.WHT}[{C.RED}x{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def info(label, value=None, label_color=None, val_color=None):
    """One aligned field — TraceRecon style.
    Called with one argument it prints a plain [*] line. Colours are
    resolved at call time (not as default arguments), so --no-color
    works: defaults bound at import time would keep the old codes."""
    if label_color is None:
        label_color = C.WHT
    if val_color is None:
        val_color = C.GRN
    if value is None:
        print(f"{C.CYN}[*]{C.RST} {label}")
        return
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")


BANNER = r"""
  ____   ___  _     ____            _
 / ___| / _ \| |   |  _ \ _ __ ___ | |__   ___
| |  _ | | | | |   | |_) | '__/ _ \| '_ \ / _ \
| |_| || |_| | |___|  __/| | | (_) | |_) |  __/
 \____| \___/|_____|_|   |_|  \___/|_.__/ \___|

              by CyberBoy50
     GRAPHQL SECURITY TESTER  |  AUTHORIZED USE ONLY
 ==================================================
"""


def banner():
    print()
    print(f"{C.BOLD}{C.RED}{BANNER}{C.RST}", end="")
    print(f"{C.YEL}  GQLProbe — GraphQL Security Tester{C.RESET}")
    print(f"{C.DIM}  Version {VERSION}  |  Author: {AUTHOR}"
          f"  |  Theme: {THEME}{C.RESET}")
    print(f"{C.YEL}  [!] LEGAL DISCLAIMER: Only probe GraphQL APIs you own "
          f"or have{C.RESET}")
    print(f"{C.YEL}      written permission to test — your own lab API or "
          f"app.{C.RESET}")
    print(f"{C.RED}")
    print("┌" + "─" * 50 + "┐")
    print("│  LAB ONLY — never probe a real API without written     │")
    print("│  permission. Unauthorized access is an offence under   │")
    print("│  the Prevention of Electronic Crimes Act, 2016 (PK).   │")
    print("└" + "─" * 50 + "┘")
    print("┌" + "─" * 50 + "┐")
    for _line in textwrap.wrap(DISCLAIMER, width=46):
        print("│  %-46s  │" % _line)
    print("└" + "─" * 50 + "┘")
    print(f"{C.RST}", end="")


# ---------------------------------------------------------------------------
# Finding codes, severities, scoring.
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 10, "low": 5}

CHECKS = [
    ("GQ-001", "Introspection exposed", "critical"),
    ("GQ-002", "Introspection bypass", "high"),
    ("GQ-003", "No depth limit", "high"),
    ("GQ-004", "Batching enabled", "high"),
    ("GQ-005", "Alias overloading", "high"),
    ("GQ-006", "Field duplication", "medium"),
    ("GQ-007", "Directive overloading", "medium"),
    ("GQ-008", "Field returns data without auth", "high"),
    ("GQ-009", "IDOR — another user's object", "critical"),
    ("GQ-010", "Schema recoverable via guessing/suggestions", "high"),
    ("GQ-011", "Mutation without auth", "critical"),
    ("GQ-012", "Expensive query / timing", "medium"),
    ("GQ-013", "Sensitive field exposed", "high"),
    ("GQ-014", "GET-based queries (CSRF angle)", "medium"),
    ("GQ-015", "Argument injection error leak", "high"),
    ("GQ-016", "No rate limiting observed", "low"),
    ("GQ-017", "Subscriptions supported", "high"),
    ("GQ-018", "Persisted queries accepted (APQ)", "medium"),
    ("GQ-019", "File upload accepted", "high"),
]
CHECKS_BY_CODE = {c: (n, s) for c, n, s in CHECKS}

# Fields whose names mark a field as sensitive (GraphQL Security
# Tester pattern: password / secret / token / key / ...).
SENSITIVE_WORDS = ("password", "secret", "token", "key", "ssn",
                   "creditcard", "credit_card", "internal", "admin")
ROLE_MUTATION_WORDS = ("role", "permission", "admin", "delete", "grant")
# Query fields the authz probe treats as protected (must need a token).
PROTECTED_FIELDS = {"me", "admin", "user", "users"}
# The only mutations the tool will ever run (lab allow-list).
MUTATION_ALLOWLIST = {"ping", "updateProfile"}
# The standard introspection query (the one every GraphQL client sends).
INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
          defaultValue
        }
        type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type { kind name ofType { kind name ofType { kind name } } }
        defaultValue
      }
      interfaces { kind name ofType { kind name } }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { kind name ofType { kind name } }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type { kind name ofType { kind name } }
        defaultValue
      }
    }
  }
}"""

DEPTH_LADDER = [1, 2, 3, 5, 8, 10, 15, 20, 30, 50]
BATCH_SIZES = [10, 50, 100]
ALIAS_COUNT = 101          # graphql-cop rule: 101 aliases
DUP_COUNT = 50             # same field repeated 50 times
DIRECTIVE_COUNT = 10       # graphql-cop rule: 10 @aa directives
RATE_LIMIT_PROBES = 20     # rapid identical queries for the rate check


def sev_color(severity):
    return {"critical": C.RED, "high": C.RED, "medium": C.YEL,
            "low": C.CYN, "info": C.DIM}.get(severity, C.WHT)


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings):
    score = 100
    for f in findings:
        score -= SEVERITY_SCORE.get(f["severity"], 0)
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# HTTP client — requests preferred, urllib fallback (SSTIProbe pattern).
# ---------------------------------------------------------------------------

def http_request(url, method="POST", json_body=None, headers=None,
                 timeout=10):
    """One HTTP request. Returns (status, headers, body, elapsed_s,
    raw_text). body is parsed JSON or None; raw_text is the first 500
    chars of the body for error reporting. Never raises on HTTP
    errors; raises only on network failure (returned as status 0)."""
    hdrs = {"Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "GQLProbe/%s" % VERSION}
    if headers:
        hdrs.update(headers)
    data = json.dumps(json_body).encode("utf-8") if json_body is not None \
        else None
    start = time.monotonic()
    try:
        if HAVE_REQUESTS:
            resp = requests.request(method, url, data=data, headers=hdrs,
                                    timeout=timeout)
            status = resp.status_code
            raw = resp.text
            resp_headers = dict(resp.headers)
        else:
            req = urllib.request.Request(url, data=data, headers=hdrs,
                                         method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = resp.status
                    raw = resp.read().decode("utf-8", "replace")
                    resp_headers = dict(resp.headers)
            except urllib.error.HTTPError as exc:
                status = exc.code
                raw = exc.read().decode("utf-8", "replace")
                resp_headers = dict(exc.headers)
    except Exception as exc:  # noqa: BLE001 - network errors are data
        return 0, {}, None, time.monotonic() - start, "NETWORK ERROR: %s" % exc
    elapsed = time.monotonic() - start
    try:
        body = json.loads(raw) if raw.strip() else None
    except ValueError:
        body = None
    return status, resp_headers, body, elapsed, raw[:500]


def http_raw(url, method, body_bytes, headers=None, timeout=10):
    """One HTTP request with a raw body (multipart upload). Returns
    the same tuple as http_request."""
    hdrs = {"Accept": "application/json",
            "User-Agent": "GQLProbe/%s" % VERSION}
    if headers:
        hdrs.update(headers)
    start = time.monotonic()
    try:
        if HAVE_REQUESTS:
            resp = requests.request(method, url, data=body_bytes,
                                    headers=hdrs, timeout=timeout)
            status = resp.status_code
            raw = resp.text
            resp_headers = dict(resp.headers)
        else:
            req = urllib.request.Request(url, data=body_bytes,
                                         headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = resp.status
                    raw = resp.read().decode("utf-8", "replace")
                    resp_headers = dict(resp.headers)
            except urllib.error.HTTPError as exc:
                status = exc.code
                raw = exc.read().decode("utf-8", "replace")
                resp_headers = dict(exc.headers)
    except Exception as exc:  # noqa: BLE001 - network errors are data
        return 0, {}, None, time.monotonic() - start, "NETWORK ERROR: %s" % exc
    elapsed = time.monotonic() - start
    try:
        body = json.loads(raw) if raw.strip() else None
    except ValueError:
        body = None
    return status, resp_headers, body, elapsed, raw[:500]


def gql_post(url, query, variables=None, token=None, extra_headers=None,
             timeout=10):
    """POST one GraphQL operation. Returns (status, headers, body,
    elapsed, raw)."""
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if extra_headers:
        headers.update(extra_headers)
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    return http_request(url, "POST", payload, headers, timeout)


def gql_get(url, query, variables=None, token=None, timeout=10):
    """GET one GraphQL operation (?query=...&variables=...)."""
    params = {"query": query}
    if variables:
        params["variables"] = json.dumps(variables)
    full = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    return http_request(full, "GET", None, headers, timeout)


def mask_token(token):
    """The token is never printed (mask it as Bearer ***)."""
    if not token:
        return "not provided"
    return "provided (%d chars, masked)" % len(token)


def redact(value, limit=40):
    """Describe a response value without printing it: type + length.
    Real emails, tokens and secrets never land in a report."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        if len(value) > limit:
            return "string[%d chars]" % len(value)
        if "@" in value or len(value) > 12:
            return "string[%d chars]" % len(value)
        return "string(%r)" % value
    if isinstance(value, list):
        return "list[%d items]" % len(value)
    if isinstance(value, dict):
        return "object[%d keys]" % len(value)
    return type(value).__name__


def error_messages(body):
    """The 'errors' array of a GraphQL response, as plain strings."""
    if not isinstance(body, dict):
        return []
    errs = body.get("errors")
    if not isinstance(errs, list):
        return []
    out = []
    for e in errs:
        if isinstance(e, dict):
            out.append(str(e.get("message", e)))
        else:
            out.append(str(e))
    return out


def has_data(body, field=None):
    """True when the response carries real data (optionally for one
    top-level field)."""
    if not isinstance(body, dict):
        return False
    data = body.get("data")
    if not isinstance(data, dict):
        return False
    if field is None:
        return any(v is not None for v in data.values())
    return data.get(field) is not None


# ---------------------------------------------------------------------------
# Schema parsing.
# ---------------------------------------------------------------------------

def _unwrap_type(tref):
    """Introspection type ref -> (base name, kind, wrapped?)."""
    if not isinstance(tref, dict):
        return None, None
    kind = tref.get("kind")
    if kind in ("NON_NULL", "LIST"):
        return _unwrap_type(tref.get("ofType") or {})
    return tref.get("name"), kind


def parse_schema(introspection_body):
    """Parse an introspection response into the schema model:
    {query_fields, mutation_fields, subscription_fields, types,
    directives, sensitive_fields, role_mutations}."""
    schema = {"query_fields": {}, "mutation_fields": {},
              "subscription_fields": {}, "types": {}, "directives": [],
              "sensitive_fields": [], "role_mutations": []}
    if not isinstance(introspection_body, dict):
        return schema
    data = introspection_body.get("data") or {}
    sch = data.get("__schema") or {}
    types = sch.get("types") or []
    for t in types:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        fields = {}
        for f in t.get("fields") or []:
            if not isinstance(f, dict) or not f.get("name"):
                continue
            args = {}
            for a in f.get("args") or []:
                if not isinstance(a, dict) or not a.get("name"):
                    continue
                base, _kind = _unwrap_type(a.get("type") or {})
                args[a["name"]] = base
            base, _kind = _unwrap_type(f.get("type") or {})
            fields[f["name"]] = {"args": args, "type": base}
        schema["types"][t["name"]] = {"kind": t.get("kind"),
                                      "fields": fields}
    qtype = (sch.get("queryType") or {}).get("name")
    mtype = (sch.get("mutationType") or {}).get("name")
    stype = (sch.get("subscriptionType") or {}).get("name")
    if qtype in schema["types"]:
        schema["query_fields"] = schema["types"][qtype]["fields"]
    if mtype in schema["types"]:
        schema["mutation_fields"] = schema["types"][mtype]["fields"]
    if stype in schema["types"]:
        schema["subscription_fields"] = schema["types"][stype]["fields"]
    schema["directives"] = [d.get("name") for d in sch.get("directives") or []
                            if isinstance(d, dict) and d.get("name")]
    # Sensitive-field flagging (GraphQL Security Tester pattern).
    for tname, t in schema["types"].items():
        if t["kind"] != "OBJECT":
            continue
        for fname in t["fields"]:
            low = fname.lower()
            if any(w in low for w in SENSITIVE_WORDS):
                schema["sensitive_fields"].append(
                    {"type": tname, "field": fname})
    for mname in schema["mutation_fields"]:
        low = mname.lower()
        if any(w in low for w in ROLE_MUTATION_WORDS):
            schema["role_mutations"].append(mname)
    return schema


def find_cycle(schema):
    """Find a circular relation to climb for the depth probe:
    returns (root_field, root_type, cycle_field) or None.
    E.g. user -> User, User.friends -> [User].
    Roots that take an id argument (user, post) are preferred over
    bare roots like me: an id lookup works with any token, while me
    is tied to the caller's own token."""
    candidates = []
    for qfield, qinfo in schema["query_fields"].items():
        root_type = qinfo["type"]
        if root_type not in schema["types"]:
            continue
        for fname, finfo in schema["types"][root_type]["fields"].items():
            if finfo["type"] == root_type:
                candidates.append((qfield, root_type, fname))
    if not candidates:
        return None
    candidates.sort(key=lambda c: 0
                    if "id" in schema["query_fields"][c[0]]["args"] else 1)
    return candidates[0]


def query_cost(query):
    """Estimated cost of a probe query: fields x (depth+1) + aliases.
    A rough number, reported next to the server's own answer. A name
    counts as a field when the next non-space character opens a
    selection, an argument list, an alias or closes one; an alias is
    a name followed by ':' and another name (an argument like
    id: "1" does not count — the colon is followed by a string)."""
    fields = len(re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*\s*(?=[\({:}])", query))
    depth = query.count("{")
    aliases = len(re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_]", query))
    return fields * (depth + 1) + aliases


# ---------------------------------------------------------------------------
# Query builders for the probes.
# ---------------------------------------------------------------------------

def build_depth_query(schema, depth):
    """A nested query of exactly `depth` levels. Uses the schema's
    circular relation when one exists (user -> friends -> friends...),
    otherwise falls back to the circular-introspection bomb
    (__schema -> types -> fields -> type -> ofType -> ...)."""
    cycle = find_cycle(schema)
    if cycle is not None:
        root_field, _root_type, cycle_field = cycle
        # The root field needs its required argument, if any.
        args = schema["query_fields"][root_field]["args"]
        if "id" in args:
            root = '%s(id: "1")' % root_field
        else:
            root = root_field
        if depth <= 1:
            return "{ %s { id } }" % root
        # depth: root(1) + (depth-2) cycle levels + leaf id(depth).
        inner = "id"
        for _ in range(depth - 2):
            inner = "%s { %s }" % (cycle_field, inner)
        return "{ %s { %s } }" % (root, inner)
    # Fallback: introspection-type nesting. types(2) -> fields(3) ->
    # type(4) -> ofType(5) -> ofType(6) ...
    inner = "name"
    for _ in range(max(0, depth - 2)):
        inner = "ofType { %s }" % inner
    return ("{ __schema { types { fields { type { %s } } } } }"
            % inner)


# When introspection is off there is no schema to climb, so the depth
# probe tries a small set of common nested shapes instead: an object
# lookup, then a field that points back at the same kind of object.
# (root, first, repeat): root is the entry field, `first` runs once
# after it (post -> author), `repeat` nests until the leaf id.
DEPTH_SHAPES = [
    ('user(id: "1")', None, "friends"),
    ("me", None, "friends"),
    ("users", None, "friends"),
    ('post(id: "1")', "author", "friends"),
    ("posts", "author", "friends"),
]


def build_depth_query_shape(root, first, repeat, depth):
    """A nested query of `depth` levels from a (root, first, repeat)
    shape — the no-schema twin of build_depth_query, same depth
    semantics (depth 1 and 2 both send '{ root { id } }')."""
    if depth <= 1:
        return "{ %s { id } }" % root
    if first:
        inner = "id"
        for _ in range(max(0, depth - 3)):
            inner = "%s { %s }" % (repeat, inner)
        return "{ %s { %s { %s } } }" % (root, first, inner)
    inner = "id"
    for _ in range(max(0, depth - 2)):
        inner = "%s { %s }" % (repeat, inner)
    return "{ %s { %s } }" % (root, inner)


def build_alias_query(count=ALIAS_COUNT):
    """One query with `count` aliases of the same field (graphql-cop
    rule: 101 aliases, success = the 100th alias's data)."""
    parts = ["a%d: __typename" % i for i in range(count)]
    return "{ %s }" % " ".join(parts)


def build_dup_query(count=DUP_COUNT):
    """The same field repeated `count` times in one selection set."""
    return "{ %s }" % " ".join(["__typename"] * count)


def build_directive_query(count=DIRECTIVE_COUNT):
    """One field with `count` unknown directives (graphql-cop rule:
    10 @aa directives)."""
    return "{ __typename %s }" % ("@aa" * count)


def load_wordlist(path):
    """The curated field-name wordlist (one name per line)."""
    words = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
    except OSError:
        pass
    return words

# ---------------------------------------------------------------------------
# The scan — one run against one endpoint.
# ---------------------------------------------------------------------------

PROBE_NAMES = ["introspection", "bypass", "depth", "batching", "alias",
               "duplication", "directive", "authz", "idor", "guessing",
               "mutation", "timing", "fingerprint", "get", "injection",
               "sensitive", "subscription", "persisted", "upload"]


class Scan:
    """One probe run: holds the endpoint, the findings, the per-probe
    verdicts, the timings and the parsed schema."""

    def __init__(self, url, token=None, extra_headers=None, timeout=10,
                 max_depth=50, max_batch=100, max_alias=ALIAS_COUNT,
                 wordlist_path=None, mutation=None, min_severity="low",
                 fail_on="low", probes=None, skip_probes=None):
        self.url = url
        self.token = token
        self.extra_headers = extra_headers or {}
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_batch = max_batch
        self.max_alias = max_alias
        # The guessing probe needs a wordlist: default to the bundled
        # one next to this file, so the library works without the CLI
        # (the CLI used to be the only place that filled this in, and
        # a bare Scan() silently skipped guessing).
        if wordlist_path is None:
            here = os.path.dirname(os.path.abspath(__file__))
            wordlist_path = os.path.join(here, "wordlist.txt")
        self.wordlist_path = wordlist_path
        self.mutation = mutation or "ping"
        self.min_severity = min_severity
        self.fail_on = fail_on
        self.want_probes = set(probes) if probes else None
        self.skip_probes = set(skip_probes or [])
        self.findings = []
        self.probes = {}
        self.timings = {}
        self.schema = None
        self.schema_raw = None
        self.engine = "unknown"
        self.engine_evidence = []
        self.auth_query_fields = []
        self.started = datetime.now()

    # -- helpers --------------------------------------------------------
    def wanted(self, name):
        if self.want_probes is not None and name not in self.want_probes:
            return False
        return name not in self.skip_probes

    def add_finding(self, code, evidence, fix, severity=None):
        name, default_sev = CHECKS_BY_CODE[code]
        finding = {"code": code, "name": name,
                   "severity": severity or default_sev,
                   "evidence": evidence, "fix": fix}
        self.findings.append(finding)
        return finding

    def record(self, name, verdict, evidence, details=None):
        self.probes[name] = {"verdict": verdict, "evidence": evidence,
                             "details": details or {}}

    def post(self, query, variables=None, token="USE_DEFAULT",
             timeout=None):
        """POST one query. token='USE_DEFAULT' means the scan token;
        token=None means explicitly unauthenticated."""
        tok = self.token if token == "USE_DEFAULT" else token
        return gql_post(self.url, query, variables, tok,
                        self.extra_headers, timeout or self.timeout)

    def get(self, query, variables=None, token="USE_DEFAULT"):
        tok = self.token if token == "USE_DEFAULT" else token
        return gql_get(self.url, query, variables, tok, self.timeout)

    def timeit(self, name, func):
        start = time.monotonic()
        out = func()
        self.timings[name] = round(time.monotonic() - start, 3)
        return out

    # -- probe 1: introspection -----------------------------------------
    def probe_introspection(self):
        if not self.wanted("introspection"):
            return
        results = {}
        for who, tok in (("authenticated", "USE_DEFAULT"),
                         ("anonymous", None)):
            _st, _hd, body, elapsed, _raw = self.post(
                INTROSPECTION_QUERY, token=tok)
            self.timings["introspection_" + who] = round(elapsed, 3)
            exposed = False
            types = 0
            if isinstance(body, dict):
                data = body.get("data") or {}
                sch = data.get("__schema") or {}
                types = len(sch.get("types") or [])
                exposed = types > 0
            results[who] = {"exposed": exposed, "types": types,
                            "errors": error_messages(body), "body": body}
        anon = results["anonymous"]["exposed"]
        auth = results["authenticated"]["exposed"]
        if anon:
            self.add_finding(
                "GQ-001",
                "Introspection returned the full schema (%d types) with "
                "NO token — anyone on the internet can read it."
                % results["anonymous"]["types"],
                "Disable introspection in production (and block __schema "
                "and __type for anonymous users).")
            self.record("introspection", "EXPOSED (anonymous)",
                        "Full schema (%d types) without a token"
                        % results["anonymous"]["types"], results)
        elif auth:
            self.add_finding(
                "GQ-001",
                "Introspection returned the full schema (%d types) with "
                "a token, but refused it anonymously."
                % results["authenticated"]["types"],
                "Disable introspection in production, even for "
                "authenticated users, unless the schema is public.",
                severity="high")
            self.record("introspection", "EXPOSED (authenticated only)",
                        "Full schema (%d types) with a token"
                        % results["authenticated"]["types"], results)
        else:
            self.record("introspection", "DISABLED",
                        "Introspection refused with and without a token: "
                        "%s" % (results["anonymous"]["errors"][:1]
                                or ["no schema returned"]),
                        results)
        # Keep the schema whenever any run returned it.
        for who in ("authenticated", "anonymous"):
            body = results[who]["body"]
            if isinstance(body, dict) and (body.get("data") or {}).get(
                    "__schema"):
                self.schema_raw = body
                self.schema = parse_schema(body)
                break

    # -- probe 2: introspection bypasses ---------------------------------
    def probe_bypass(self):
        if not self.wanted("bypass"):
            return
        intro = self.probes.get("introspection", {})
        if "EXPOSED" in intro.get("verdict", ""):
            self.record("bypass", "NOT NEEDED",
                        "Introspection is already open — there is nothing "
                        "to bypass.", {})
            return
        worked, tried = [], []
        # (a) __type when __schema is blocked.
        _st, _hd, body, _el, _raw = self.post(
            '{ __type(name: "Query") { name } }', token=None)
        tried.append("__type")
        if isinstance(body, dict) and (body.get("data") or {}).get(
                "__type"):
            worked.append("__type")
        # (b) the same introspection over GET.
        _st, _hd, body, _el, _raw = self.get(
            "{ __schema { queryType { name } } }", token=None)
        tried.append("GET")
        if isinstance(body, dict) and (body.get("data") or {}).get(
                "__schema"):
            worked.append("GET")
        # (c) newline after __schema (the CVE-2024-37155 regex shape).
        _st, _hd, body, _el, _raw = self.post(
            "{ __schema \n { queryType { name } } }", token=None)
        tried.append("newline")
        if isinstance(body, dict) and (body.get("data") or {}).get(
                "__schema"):
            worked.append("newline")
        # (d) introspection inside a named fragment.
        _st, _hd, body, _el, _raw = self.post(
            "{ ...I } fragment I on Query "
            "{ __schema { queryType { name } } }", token=None)
        tried.append("fragment")
        if isinstance(body, dict) and (body.get("data") or {}).get(
                "__schema"):
            worked.append("fragment")
        for method in worked:
            self.add_finding(
                "GQ-002",
                "Introspection is disabled, but the %s bypass returns "
                "schema data anyway." % method,
                "Block __schema AND __type on every method (POST and "
                "GET), and match on the parsed query — never on a "
                "regex over the raw text.")
        if worked:
            self.record("bypass", "BYPASSED",
                        "Working bypasses: %s (tried: %s)"
                        % (", ".join(worked), ", ".join(tried)),
                        {"worked": worked, "tried": tried})
        else:
            self.record("bypass", "BLOCKED",
                        "All bypasses refused (tried: %s)"
                        % ", ".join(tried),
                        {"worked": [], "tried": tried})

    # -- probe 3: depth ---------------------------------------------------
    def probe_depth(self):
        if not self.wanted("depth"):
            return
        # Query builder: schema-based when introspection worked, else
        # try the common nested shapes (user -> friends, ...) and use
        # the first one that answers.
        if self.schema is not None:
            def build_query(depth):
                return build_depth_query(self.schema, depth)
        else:
            shape = None
            for root, first, repeat in DEPTH_SHAPES:
                q1 = build_depth_query_shape(root, first, repeat, 1)
                _st, _hd, body, _el, _raw = self.post(
                    q1, token="USE_DEFAULT")
                if isinstance(body, dict) \
                        and body.get("data") is not None \
                        and not error_messages(body):
                    shape = (root, first, repeat)
                    break
            if shape is None:
                self.record("depth", "SKIPPED",
                            "No schema, and no common nested shape "
                            "answered (user -> friends, me -> friends, "
                            "post -> author -> friends). Introspection is "
                            "off and the depth probe needs a field list "
                            "— re-run with --token, or probe an endpoint "
                            "that exposes its schema.", {})
                return

            def build_query(depth, shape=shape):
                return build_depth_query_shape(shape[0], shape[1],
                                               shape[2], depth)
        deepest = 0
        limit_found = None
        first_status = None
        ladder = [d for d in DEPTH_LADDER if d <= self.max_depth]
        if not ladder:
            ladder = [self.max_depth]
        for depth in ladder:
            query = build_query(depth)
            cost = query_cost(query)
            status, _hd, body, elapsed, _raw = self.post(
                query, token="USE_DEFAULT")
            self.timings["depth_%d" % depth] = round(elapsed, 3)
            if first_status is None:
                first_status = status
            if isinstance(body, dict) and (body.get("data") is not None
                                          and not error_messages(body)):
                deepest = depth
                continue
            msgs = error_messages(body)
            limit_found = msgs[0] if msgs else "refused"
            break
        # A refusal at the FIRST rung that smells of auth is not a
        # depth limit — it is a missing/weak token. Say so instead of
        # misreading it as "limited at depth 1".
        if deepest == 0 and limit_found:
            low = limit_found.lower()
            if ("uthenticat" in low or "orbidden" in low
                    or "unauthor" in low or first_status in (401, 403)):
                self.record("depth", "INCONCLUSIVE (AUTH)",
                            "The depth probe needs a token for this "
                            "endpoint: the depth-1 query was refused "
                            "with an auth error (%s). Re-run with "
                            "--token." % redact(limit_found[:80]),
                            {"deepest": 0, "limit": None,
                             "auth_blocked": True})
                return
        if deepest >= 20:
            self.add_finding(
                "GQ-003",
                "The API answered a depth-%d query (cost ~%d) and never "
                "refused — no depth limit was found up to depth %d."
                % (deepest, query_cost(build_query(deepest)), deepest),
                "Enforce a query-depth limit (5–10 is typical) before "
                "the query reaches the engine.")
            self.record("depth", "NO LIMIT",
                        "Answered up to depth %d (max tried); no refusal"
                        % deepest,
                        {"deepest": deepest, "limit": None})
        elif limit_found:
            self.record("depth", "LIMITED (max depth %d)" % deepest,
                        "Refused past depth %d: %s" % (deepest, limit_found),
                        {"deepest": deepest, "limit": limit_found})
        else:
            self.record("depth", "INCONCLUSIVE",
                        "The API stopped answering at depth %d with no "
                        "clear limit message." % deepest,
                        {"deepest": deepest})

    # -- probe 4: batching ------------------------------------------------
    def probe_batching(self):
        if not self.wanted("batching"):
            return
        best = 0
        for size in BATCH_SIZES:
            if size > self.max_batch:
                break
            batch = [{"query": "{ __typename }"}] * size
            _st, _hd, body, elapsed, _raw = http_request(
                self.url, "POST", batch,
                {"Authorization": "Bearer " + self.token} if self.token
                else {}, self.timeout)
            self.timings["batch_%d" % size] = round(elapsed, 3)
            count = len(body) if isinstance(body, list) else 0
            if count >= size:
                best = size
                continue
            break
        if best >= 10:
            self.add_finding(
                "GQ-004",
                "Array batching works: one request with %d queries "
                "returned %d responses — a rate-limit bypass and a "
                "DoS amplifier." % (best, best),
                "Disable array batching, or cap the batch size (10 is a "
                "common limit) and count batched operations against "
                "the rate limit.")
            self.record("batching", "ENABLED",
                        "One request executed %d queries" % best,
                        {"max_batch": best})
        elif best:
            self.record("batching", "LIMITED to %d" % best,
                        "Batching works up to %d queries" % best,
                        {"max_batch": best})
        else:
            self.record("batching", "DISABLED",
                        "Array batching refused (a single error object, "
                        "not an array).", {"max_batch": 0})

    # -- probe 5: alias overloading ---------------------------------------
    def probe_alias(self):
        if not self.wanted("alias"):
            return
        query = build_alias_query(self.max_alias)
        _st, _hd, body, elapsed, _raw = self.post(query,
                                                  token="USE_DEFAULT")
        self.timings["alias"] = round(elapsed, 3)
        data = (body or {}).get("data") if isinstance(body, dict) else None
        last = "a%d" % (self.max_alias - 1)
        if isinstance(data, dict) and data.get(last) is not None:
            self.add_finding(
                "GQ-005",
                "Alias overloading works: one query with %d aliases "
                "returned data for the last alias (%s) — the engine "
                "resolved %d copies of the same field."
                % (self.max_alias, last, self.max_alias),
                "Limit the number of aliases per query (and dedupe "
                "identical fields before execution).")
            self.record("alias", "NO LIMIT",
                        "%d aliases resolved" % self.max_alias,
                        {"aliases": self.max_alias,
                         "cost": query_cost(query)})
        elif error_messages(body):
            self.record("alias", "LIMITED",
                        "The alias bomb was refused: %s"
                        % error_messages(body)[:1],
                        {"aliases": self.max_alias})
        else:
            self.record("alias", "INCONCLUSIVE",
                        "No clear answer to the alias probe.",
                        {"aliases": self.max_alias})

    # -- probe 6: field duplication ---------------------------------------
    def probe_duplication(self):
        if not self.wanted("duplication"):
            return
        query = build_dup_query(DUP_COUNT)
        _st, _hd, body, elapsed, _raw = self.post(query,
                                                  token="USE_DEFAULT")
        self.timings["duplication"] = round(elapsed, 3)
        if isinstance(body, dict) and body.get("data") is not None \
                and not error_messages(body):
            self.add_finding(
                "GQ-006",
                "Field duplication accepted: the same field %d times in "
                "one selection set was executed without complaint."
                % DUP_COUNT,
                "Deduplicate identical fields before execution, and "
                "count duplicates towards the complexity limit.")
            self.record("duplication", "NO LIMIT",
                        "%d duplicate fields accepted" % DUP_COUNT,
                        {"duplicates": DUP_COUNT,
                         "cost": query_cost(query)})
        elif error_messages(body):
            self.record("duplication", "LIMITED",
                        "Duplicate fields refused: %s"
                        % error_messages(body)[:1],
                        {"duplicates": DUP_COUNT})
        else:
            self.record("duplication", "INCONCLUSIVE",
                        "No clear answer to the duplication probe.",
                        {"duplicates": DUP_COUNT})

    # -- probe 7: directive overloading -----------------------------------
    def probe_directive(self):
        if not self.wanted("directive"):
            return
        query = build_directive_query(DIRECTIVE_COUNT)
        _st, _hd, body, elapsed, _raw = self.post(query,
                                                  token="USE_DEFAULT")
        self.timings["directive"] = round(elapsed, 3)
        msgs = error_messages(body)
        if isinstance(body, dict) and body.get("data") is not None \
                and not msgs:
            self.add_finding(
                "GQ-007",
                "Directive overloading accepted: one field with %d "
                "unknown directives executed without complaint."
                % DIRECTIVE_COUNT,
                "Limit the number of directives per query, and reject "
                "unknown directives instead of ignoring them.")
            self.record("directive", "NO LIMIT",
                        "%d directives on one field accepted"
                        % DIRECTIVE_COUNT,
                        {"directives": DIRECTIVE_COUNT})
        elif len(msgs) >= DIRECTIVE_COUNT:
            self.add_finding(
                "GQ-007",
                "Directive overloading: the engine returned %d errors "
                "for %d directives — it processed every one."
                % (len(msgs), DIRECTIVE_COUNT),
                "Limit the number of directives per query.")
            self.record("directive", "NO LIMIT",
                        "%d errors for %d directives"
                        % (len(msgs), DIRECTIVE_COUNT),
                        {"directives": DIRECTIVE_COUNT})
        elif msgs:
            self.record("directive", "LIMITED",
                        "Directives refused with one error: %s" % msgs[:1],
                        {"directives": DIRECTIVE_COUNT})
        else:
            self.record("directive", "INCONCLUSIVE",
                        "No clear answer to the directive probe.",
                        {"directives": DIRECTIVE_COUNT})

    # -- probe 8: authorization -------------------------------------------
    def probe_authz(self):
        if not self.wanted("authz"):
            return
        query = ('{ me { id name email } admin '
                 'user(id: "1") { id name email } users { id } }')
        _st, _hd, auth_body, _el, _raw = self.post(query,
                                                   token="USE_DEFAULT")
        _st, _hd, anon_body, _el, _raw = self.post(query, token=None)
        leaked = []
        for field in ("me", "admin", "user", "users"):
            if has_data(anon_body, field):
                leaked.append(field)
        for field in leaked:
            sev = "high"
            self.add_finding(
                "GQ-008",
                "Field '%s' returns data with NO token: %s"
                % (field, redact((anon_body.get("data") or {}).get(field))),
                "Enforce authorization on '%s' — check the token "
                "before the resolver runs, not after." % field,
                severity=sev)
        if leaked:
            self.record("authz", "LEAKING (%s)" % ", ".join(leaked),
                        "Fields answering without a token: %s"
                        % ", ".join(leaked),
                        {"leaked": leaked})
        else:
            self.record("authz", "ENFORCED",
                        "No protected field answered without a token.",
                        {"leaked": []})
        # The field-level auth map is built at the end of run()
        # (_build_field_map): it needs the guessing probe's field
        # list when introspection is off and there is no schema.

    def _build_field_map(self):
        """Field-level auth map: every known query field, replayed
        without a token. The field list comes from the schema when
        introspection worked, else from the fields the guessing probe
        found (discovered + gated) — so the map exists on a hardened
        endpoint too, instead of being empty for want of a schema."""
        if "authz" not in self.probes:
            return
        fields = []
        if self.schema is not None:
            fields = list(self.schema["query_fields"])
        else:
            g = self.probes.get("guessing", {}).get("details") or {}
            fields = sorted(set(g.get("discovered") or [])
                            | set(g.get("gated") or []))
        auth_map = {}
        for fname in fields:
            if fname in ("__schema", "__type"):
                continue
            args = {}
            if self.schema is not None:
                args = self.schema["query_fields"].get(
                    fname, {}).get("args") or {}
            if "id" in args:
                q = '{ %s(id: "1") { __typename } }' % fname
            elif "q" in args:
                q = '{ %s(q: "lab") { __typename } }' % fname
            else:
                q = '{ %s { __typename } }' % fname
            _st, _hd, body, _el, _raw = self.post(q, token=None)
            if has_data(body, fname):
                auth_map[fname] = "answers (data)"
            elif any("uthenticat" in m or "orbidden" in m
                     for m in error_messages(body)):
                auth_map[fname] = "refused (auth)"
            elif error_messages(body):
                auth_map[fname] = "refused (%s)" % \
                    error_messages(body)[0][:60]
            else:
                auth_map[fname] = "unclear"
        self.probes["authz"]["details"]["field_map"] = auth_map

    # -- probe 9: IDOR / BOLA ----------------------------------------------
    def probe_idor(self):
        if not self.wanted("idor"):
            return
        if not self.token:
            self.record("idor", "SKIPPED",
                        "No token given — the IDOR probe needs a lab "
                        "user token (use --token lab-token-alice).", {})
            return
        # Who is this token? Ask me, then request OTHER users' objects
        # with the SAME token. The token value is never printed — the
        # evidence names only user ids (never names, emails or tokens).
        _st, _hd, body, _el, _raw = self.post(
            "{ me { id } }", token="USE_DEFAULT")
        me = (body or {}).get("data") or {}
        own = (me.get("me") or {}).get("id")
        if not own:
            self.record("idor", "INCONCLUSIVE",
                        "Could not learn the token's own user id "
                        "(me returned nothing) — the probe cannot tell "
                        "another user's object from the caller's own.",
                        {})
            return
        leaked = []
        for other in ("1", "2", "3"):
            if str(other) == str(own):
                continue
            _st, _hd, body, _el, _raw = self.post(
                '{ user(id: "%s") { id } }' % other, token="USE_DEFAULT")
            data = (body or {}).get("data") or {}
            user = data.get("user") or {}
            if user.get("id") == other:
                leaked.append("user %s" % other)
        if leaked:
            self.add_finding(
                "GQ-009",
                "IDOR: the scan token (user %s) fetched ANOTHER user's "
                "object: %s" % (own, "; ".join(leaked)),
                "Scope object access to the owner (or an admin) — "
                "check the token's user id against the requested id "
                "in the resolver.")
            self.record("idor", "LEAKING", "; ".join(leaked),
                        {"own": own, "leaked": leaked})
        else:
            self.record("idor", "CLOSED",
                        "Other users' objects were refused.",
                        {"own": own, "leaked": []})

    # -- probe 10: field guessing + suggestion mining ----------------------
    def probe_guessing(self):
        if not self.wanted("guessing"):
            return
        intro = self.probes.get("introspection", {})
        if "EXPOSED" in intro.get("verdict", ""):
            self.record("guessing", "NOT NEEDED",
                        "Introspection is open — the schema is already "
                        "known, guessing adds nothing.", {})
            return
        words = load_wordlist(self.wordlist_path) if self.wordlist_path \
            else []
        if not words:
            self.record("guessing", "SKIPPED",
                        "No wordlist found (wordlist.txt missing).", {})
            return
        discovered, gated = [], []
        # Batch the guesses 10 at a time when batching works.
        batching = self.probes.get("batching", {}).get("verdict", "")
        batch_ok = "ENABLED" in batching
        i = 0
        while i < len(words):
            chunk = words[i:i + (10 if batch_ok else 1)]
            i += len(chunk)
            if batch_ok:
                batch = [{"query": "{ %s { __typename } }" % w}
                         for w in chunk]
                _st, _hd, body, _el, _raw = http_request(
                    self.url, "POST", batch, {}, self.timeout)
                if isinstance(body, list) and len(body) == len(chunk):
                    responses = body
                else:
                    # The server did not answer per-element — fall back
                    # to one request per word for this chunk.
                    responses = []
                    for w in chunk:
                        _st, _hd, body, _el, _raw = self.post(
                            "{ %s { __typename } }" % w, token=None)
                        responses.append(body)
            else:
                responses = []
                for w in chunk:
                    _st, _hd, body, _el, _raw = self.post(
                        "{ %s { __typename } }" % w, token=None)
                    responses.append(body)
            for word, resp in zip(chunk, responses):
                if not isinstance(resp, dict):
                    continue
                data = resp.get("data") or {}
                if data.get(word) is not None:
                    discovered.append(word)
                elif any("uthenticat" in m or "orbidden" in m
                         for m in error_messages(resp)):
                    gated.append(word)
        # Suggestion mining (Clairvoyance-style): typo a field, read
        # the "Did you mean ...?" out of the error, feed it back in.
        suggested = set()
        for typo in ("usr", "emai", "postz", "serch", "admn", "usrs"):
            _st, _hd, body, _el, _raw = self.post(
                "{ %s { __typename } }" % typo, token=None)
            for msg in error_messages(body):
                for name in re.findall(r"Did you mean '([^']+)'", msg):
                    suggested.add(name)
                for name in re.findall(r'Did you mean "([^"]+)"', msg):
                    suggested.add(name)
        suggested = sorted(suggested)
        for name in suggested:
            if name not in discovered and name not in gated:
                discovered.append(name)
        if suggested:
            self.add_finding(
                "GQ-010",
                "Schema recoverable via suggestions: the server "
                "volunteers field names for typos — %s"
                % ", ".join("'%s'" % s for s in suggested),
                "Suppress field suggestions in errors "
                "(hideSchemaDetailsFromClientErrors, or the equivalent) "
                "and disable introspection together.")
        protected_data = [w for w in discovered
                          if w in PROTECTED_FIELDS]
        if protected_data:
            self.add_finding(
                "GQ-010",
                "Schema recoverable via guessing: protected fields "
                "confirmed by name — %s" % ", ".join(protected_data),
                "Field names are guessable by design; make sure the "
                "fields themselves enforce authorization (see GQ-008).")
        if suggested or protected_data:
            self.record("guessing", "RECOVERABLE",
                        "Recovered via suggestions/guessing: %s"
                        % ", ".join(sorted(set(discovered))),
                        {"discovered": sorted(set(discovered)),
                         "gated": sorted(set(gated)),
                         "suggested": suggested})
        else:
            self.record("guessing", "NOT RECOVERABLE",
                        "Guessing found %d public fields, no suggestions "
                        "leaked and no protected field confirmed."
                        % len(discovered),
                        {"discovered": sorted(set(discovered)),
                         "gated": sorted(set(gated)),
                         "suggested": []})

    # -- probe 11: mutation testing -----------------------------------------
    def probe_mutation(self):
        if not self.wanted("mutation"):
            return
        if self.mutation not in MUTATION_ALLOWLIST:
            self.record("mutation", "REFUSED",
                        "Mutation %r is not on the allow-list %s — the "
                        "tool only runs harmless lab mutations."
                        % (self.mutation, sorted(MUTATION_ALLOWLIST)), {})
            return
        results = {}
        for name, query in (
                ("ping", "mutation { ping }"),
                ("updateProfile",
                 'mutation { updateProfile(input: {bio: "lab-test"}) '
                 '{ id bio } }')):
            with_tok = self.post(query, token="USE_DEFAULT")
            without_tok = self.post(query, token=None)
            results[name] = {
                "with_token": has_data(with_tok[2]),
                "without_token": has_data(without_tok[2]),
                "with_errors": error_messages(with_tok[2]),
                "without_errors": error_messages(without_tok[2]),
            }
            if results[name]["without_token"]:
                self.add_finding(
                    "GQ-011",
                    "Mutation '%s' executes with NO token." % name,
                    "Require authentication for every mutation — "
                    "mutations change state, queries only read it.")
        executed = [n for n, r in results.items() if r["without_token"]]
        if executed:
            self.record("mutation", "EXECUTES WITHOUT AUTH",
                        "Mutations running without a token: %s"
                        % ", ".join(executed), results)
        else:
            self.record("mutation", "AUTH ENFORCED",
                        "No mutation executed without a token.",
                        results)

    # -- probe 12: timing + rate limit --------------------------------------
    def probe_timing(self):
        if not self.wanted("timing"):
            return
        def mean3(query, token="USE_DEFAULT"):
            times = []
            for _ in range(3):
                _st, _hd, _body, elapsed, _raw = self.post(
                    query, token=token)
                times.append(elapsed)
            return round(sum(times) / len(times), 3)

        base = mean3("{ __typename }")
        deep_q = None
        if self.schema is not None:
            deep_q = build_depth_query(self.schema, 5)
        deep = mean3(deep_q) if deep_q else None
        _st, _hd, _body, t1, _raw = self.post("{ __typename }")
        batch = [{"query": "{ __typename }"}] * 100
        _st, _hd, _body, t100, _raw = http_request(
            self.url, "POST", batch,
            {"Authorization": "Bearer " + self.token} if self.token else {},
            self.timeout)
        timing = {"shallow_1": base, "deep_5": deep,
                  "single": round(t1, 3), "batch_100": round(t100, 3)}
        self.timings.update({("timing_" + k): v
                             for k, v in timing.items()
                             if v is not None})
        if deep is not None and base > 0 and deep > 5 * base:
            self.add_finding(
                "GQ-012",
                "Expensive query: a depth-5 query takes %.3fs vs %.3fs "
                "for a shallow one (%.1fx slower)."
                % (deep, base, deep / base),
                "Enforce depth and complexity limits, and cap resolver "
                "work per query.")
        # Rate-limit detection: 20 identical cheap queries, as fast as
        # possible. A unique comment keeps this run's queries distinct
        # from every other probe's, so the flood guard counts only
        # these 20.
        tag = "rl-%04x" % random.randint(0, 0xFFFF)
        codes = []
        for _ in range(RATE_LIMIT_PROBES):
            _st, _hd, _body, _el, _raw = self.post(
                "# %s\n{ __typename }" % tag, token=None)
            codes.append(_st)
        first_429 = next((i + 1 for i, c in enumerate(codes)
                          if c == 429), None)
        if first_429 is not None:
            timing["rate_limit"] = "present (first 429 at request %d/20)" \
                % first_429
            self.record("timing", "RATE LIMIT PRESENT",
                        "Shallow %.3fs, deep %.3fs, 1 vs 100 batch "
                        "%.3fs vs %.3fs; rate limit kicked in at request "
                        "%d/20." % (base, deep or 0, t1, t100, first_429),
                        timing)
        else:
            self.add_finding(
                "GQ-016",
                "No rate limiting observed: 20 identical queries in a "
                "row all answered (no 429, no slowdown). Absence of "
                "evidence is not proof — but nothing throttled the "
                "flood.",
                "Add per-client rate limiting (and count batched "
                "operations against it).",
                severity="low")
            timing["rate_limit"] = "not observed in 20 rapid requests"
            self.record("timing", "NO RATE LIMIT OBSERVED",
                        "Shallow %.3fs, deep %.3fs, 1 vs 100 batch "
                        "%.3fs vs %.3fs; 20 rapid queries, no 429."
                        % (base, deep or 0, t1, t100),
                        timing)

    # -- probe 13: engine fingerprinting -------------------------------------
    # A best guess ONLY: error shapes and headers are evidence, never
    # proof — two engines can print the same message, and any server
    # can fake a header. The verdict says "unknown" when the evidence
    # does not support a name, and the evidence always says so.
    def probe_fingerprint(self):
        if not self.wanted("fingerprint"):
            return
        _st, headers, _body, _el, _raw = self.post("{ __typename }",
                                                   token=None)
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        _st, _hd, body, _el, _raw = self.post("{ usr { id } }", token=None)
        msgs = error_messages(body)
        blob = " ".join(msgs)
        evidence = []
        guess = "unknown"
        if server:
            evidence.append("Server header: %s" % server)
        if powered:
            evidence.append("X-Powered-By: %s" % powered)
        # Extensions on the error (Apollo Server / graphql-yoga carry
        # extensions.code, e.g. GRAPHQL_VALIDATION_FAILED).
        ext_code = None
        if isinstance(body, dict):
            for e in body.get("errors") or []:
                if isinstance(e, dict) and isinstance(
                        e.get("extensions"), dict):
                    ext_code = e["extensions"].get("code")
                    break
        if ext_code:
            evidence.append("error extensions.code: %s" % ext_code)
        # Error-message shapes, most specific first. Each one names a
        # FAMILY ("-like"), never a version — the shape alone cannot
        # prove which release, or even which engine, for certain.
        if "Did you mean" in blob:
            guess = "Apollo-like (field-suggestion error shape)"
            evidence.append("error shape: Apollo-style 'Did you mean'")
        elif "Cannot query field" in blob:
            guess = "Apollo-like (error shape)"
            evidence.append("error shape: 'Cannot query field ...'")
        elif "doesn't exist on type" in blob:
            guess = "graphql-ruby-like (error shape)"
            evidence.append("error shape: graphql-ruby "
                            "doesnt-exist-on-type message")
        elif "does not exist on type" in blob or (
                "The field" in blob and "does not exist" in blob):
            guess = "Hot Chocolate-like (error shape)"
            evidence.append("error shape: 'The field ... does not exist'")
        elif "Validation error" in blob:
            guess = "graphql-java-like (error shape)"
            evidence.append("error shape: 'Validation error ...'")
        elif "not found in type" in blob:
            guess = "Hasura-like (error shape)"
            evidence.append("error shape: Hasura "
                            "not-found-in-type message")
        elif ext_code == "GRAPHQL_VALIDATION_FAILED":
            guess = "Apollo-like (extensions.code)"
            evidence.append("error shape: GRAPHQL_VALIDATION_FAILED")
        elif msgs:
            evidence.append("error shape: %s" % msgs[0][:80])
        else:
            evidence.append("no usable error shape")
        if "lab" in server.lower():
            guess += " — lab build (Server header says so)"
        evidence.append("best guess only — error shapes and headers "
                        "are evidence, never proof of the engine")
        self.engine = guess
        self.engine_evidence = evidence
        self.record("fingerprint", guess, "; ".join(evidence),
                    {"server": server, "powered_by": powered,
                     "error_shape": msgs[:1],
                     "extensions_code": ext_code})

    # -- probe 14: GET support (CSRF angle) ----------------------------------
    def probe_get(self):
        if not self.wanted("get"):
            return
        status, _hd, body, _el, _raw = self.get("{ __typename }",
                                                token=None)
        # A 429 is rate limiting, not a GET block — say so instead of
        # misreading it as BLOCKED.
        if status == 429:
            self.record("get", "INCONCLUSIVE (RATE LIMITED)",
                        "The GET probe was rate-limited (HTTP 429) — "
                        "re-run it on its own to tell GET support "
                        "apart from the rate limit.", {"method": "GET"})
            return
        if isinstance(body, dict) and (body.get("data") or {}).get(
                "__typename"):
            self.add_finding(
                "GQ-014",
                "GET-based queries work: the same query runs over GET "
                "(curl '%s?query={%%20__typename%%20}'). If this API "
                "ever uses cookie auth, that is a CSRF vector."
                % self.url,
                "Accept GraphQL only over POST with a JSON body, or "
                "require a CSRF token / custom header on GET.")
            self.record("get", "WORKS",
                        "The cheapest query executes over GET.",
                        {"method": "GET"})
        else:
            self.record("get", "BLOCKED",
                        "GET queries do not execute: %s"
                        % (error_messages(body)[:1] or ["refused"]),
                        {"method": "GET"})

    # -- probe 15: argument injection (safe payloads only) --------------------
    def probe_injection(self):
        if not self.wanted("injection"):
            return
        db_words = ("syntax error", "sql", "sqlite", "postgres", "mysql",
                    "mongo", "ora-", "stack trace", "traceback",
                    "at object.", "sequelize", "prisma")
        leaked = []
        for payload in ("lab'test", '" OR "1"="1'):
            _st, _hd, body, _el, raw = self.post(
                '{ search(q: %s) { id title } }' % json.dumps(payload),
                token=None)
            blob = (raw or "").lower()
            hits = [w for w in db_words if w in blob]
            if hits:
                leaked.append("%r -> %s" % (payload, ", ".join(hits)))
        if leaked:
            self.add_finding(
                "GQ-015",
                "Argument injection error leak: %s" % "; ".join(leaked),
                "Never pass raw argument strings to the database — "
                "use parameterised queries, and return a generic "
                "error, never a database message.")
            self.record("injection", "ERROR LEAKED", "; ".join(leaked),
                        {"leaked": leaked})
        else:
            self.record("injection", "CLEAN",
                        "Quoted arguments returned clean results — no "
                        "database error leaked.", {"leaked": []})

    # -- probe 16: sensitive-field data ---------------------------------------
    def probe_sensitive(self):
        if not self.wanted("sensitive"):
            return
        # The schema flags the sensitive fields, but the leak check
        # (passwordHash without a token) runs even when introspection
        # is off — it only needs the common user shape.
        flagged = []
        role_muts = []
        if self.schema is not None:
            flagged = self.schema.get("sensitive_fields") or []
            role_muts = self.schema.get("role_mutations") or []
        # Actually query the sensitive field: does passwordHash come back?
        leaked = []
        _st, _hd, body, _el, _raw = self.post(
            '{ user(id: "1") { passwordHash } }', token=None)
        data = (body or {}).get("data") or {}
        user = data.get("user") or {}
        if user.get("passwordHash"):
            leaked.append("passwordHash returned without a token: %s"
                          % redact(user.get("passwordHash")))
            self.add_finding(
                "GQ-013",
                "Sensitive field exposed: %s" % leaked[0],
                "Never expose password hashes (or secrets/tokens) "
                "through the API — remove the field from the schema, "
                "or gate it behind an admin-only resolver.")
        detail = {"sensitive_fields": flagged,
                  "role_mutations": role_muts, "leaked": leaked}
        if leaked:
            self.record("sensitive", "EXPOSED", "; ".join(leaked), detail)
        elif flagged or role_muts:
            self.record("sensitive", "FLAGGED IN SCHEMA",
                        "%d sensitive fields and %d role-changing "
                        "mutations in the schema, none returning data "
                        "without a token."
                        % (len(flagged), len(role_muts)), detail)
        elif self.schema is None:
            self.record("sensitive", "CLEAN (NO SCHEMA)",
                        "No schema to flag (introspection is off), and "
                        "the passwordHash spot-check returned nothing "
                        "without a token. A full check needs the schema "
                        "— see the introspection probe.", detail)
        else:
            self.record("sensitive", "NONE FOUND",
                        "No sensitive field or role-changing mutation in "
                        "the schema.", detail)

    # -- probe 17: subscriptions -------------------------------------------
    # Two transports, both tried: a subscription operation over plain
    # HTTP (a server that answers it is streaming events without a
    # websocket at all), and a websocket upgrade (graphql-ws /
    # subscriptions-transport-ws). A 101 Switching Protocols answer
    # means the websocket transport is live.
    SUBSCRIPTION_FIELDS = ("postAdded", "messageAdded", "commentAdded",
                           "notificationAdded", "userJoined")

    def probe_subscription(self):
        if not self.wanted("subscription"):
            return
        http_ok, ws_ok, tried = False, [], []
        # (a) HTTP: a subscription operation, from the schema when one
        # is known, else the common event field names.
        fields = []
        if self.schema is not None:
            fields = list(self.schema.get("subscription_fields") or [])
        if not fields:
            fields = list(self.SUBSCRIPTION_FIELDS)
        for field in fields:
            query = "subscription { %s { __typename } }" % field
            _st, _hd, body, _el, _raw = self.post(query, token=None)
            tried.append(field)
            data = (body or {}).get("data") if isinstance(body, dict) \
                else None
            if isinstance(data, dict) and data.get(field) is not None:
                http_ok = True
                break
            if error_messages(body) and any(
                    "not supported" in m.lower()
                    for m in error_messages(body)):
                break
        # (b) WebSocket upgrade: a raw HTTP Upgrade request. A 101
        # means the server speaks websocket GraphQL.
        ws_status = self._ws_upgrade_status()
        if ws_status == 101:
            ws_ok = True
        if http_ok or ws_ok:
            how = []
            if http_ok:
                how.append("HTTP subscription returns event data")
            if ws_ok:
                how.append("websocket upgrade answered 101")
            self.add_finding(
                "GQ-017",
                "Subscriptions supported: %s — a live event stream "
                "is an unauthenticated push channel and a "
                "denial-of-service shape (one client, many open "
                "streams)." % "; ".join(how),
                "Disable subscriptions unless the API needs them; "
                "require authentication before the subscription is "
                "accepted, and cap concurrent subscriptions per "
                "client.")
            self.record("subscription", "SUPPORTED",
                        "; ".join(how),
                        {"http": http_ok, "websocket": ws_ok,
                         "tried": tried, "ws_status": ws_status})
        elif ws_status is None:
            self.record("subscription", "INCONCLUSIVE",
                        "HTTP subscription refused, but the websocket "
                        "check could not run (no usable URL).",
                        {"http": http_ok, "websocket": False,
                         "tried": tried, "ws_status": ws_status})
        else:
            self.record("subscription", "NOT SUPPORTED",
                        "HTTP subscription refused and the websocket "
                        "upgrade was refused (HTTP %s, not 101)."
                        % ws_status,
                        {"http": False, "websocket": False,
                         "tried": tried, "ws_status": ws_status})

    def _ws_upgrade_status(self):
        """Send a websocket Upgrade request to the endpoint and
        return the HTTP status (101 = websocket live), or None when
        the URL cannot be used for it. Stdlib only, no websocket
        library — a handshake is one HTTP request."""
        import base64
        import http.client
        parsed = urllib.parse.urlparse(self.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        headers = {"Connection": "Upgrade", "Upgrade": "websocket",
                   "Sec-WebSocket-Key": key,
                   "Sec-WebSocket-Version": "13",
                   "Sec-WebSocket-Protocol": "graphql-ws"}
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        # Honour the egress proxy when one is set (requests does this
        # for the other probes; a raw socket does not): without it the
        # direct connection can hang or fail even though the endpoint
        # is reachable, and the verdict flips between runs.
        proxy = None
        if parsed.scheme == "https":
            proxy = (os.environ.get("https_proxy")
                     or os.environ.get("HTTPS_PROXY"))
        else:
            proxy = (os.environ.get("http_proxy")
                     or os.environ.get("HTTP_PROXY"))
        no_proxy = os.environ.get("no_proxy", "") + "," \
            + os.environ.get("NO_PROXY", "")
        if proxy and parsed.hostname not in [
                h.strip() for h in no_proxy.split(",") if h.strip()]:
            pparsed = urllib.parse.urlparse(proxy)
            if pparsed.hostname:
                try:
                    if parsed.scheme == "https":
                        conn = http.client.HTTPSConnection(
                            pparsed.hostname,
                            pparsed.port or 8080, timeout=5)
                        conn.set_tunnel(parsed.hostname,
                                        parsed.port or 443)
                    else:
                        conn = http.client.HTTPConnection(
                            pparsed.hostname,
                            pparsed.port or 8080, timeout=5)
                        path = "%s://%s%s" % (
                            parsed.scheme, parsed.hostname, path)
                    conn.request("GET", path, headers=headers)
                    resp = conn.getresponse()
                    status = resp.status
                    resp.read()
                    conn.close()
                    return status
                except Exception:  # noqa: BLE001 - fall through to direct
                    pass
        try:
            conn_cls = (http.client.HTTPSConnection if parsed.scheme
                        == "https" else http.client.HTTPConnection)
            conn = conn_cls(parsed.hostname,
                            parsed.port or (443 if parsed.scheme == "https"
                                            else 80),
                            timeout=5)
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            resp.read()
            conn.close()
            return status
        except Exception:  # noqa: BLE001 - no websocket, verdict below
            return None

    # -- probe 18: persisted queries (APQ) ----------------------------------
    # Automatic Persisted Queries: the client sends only a sha256 hash
    # of the query, no query text. A server that answers
    # PersistedQueryNotFound understands APQ — it looked the hash up.
    # Sending the same hash WITH the query then registers it, and the
    # server runs the query from the hash alone afterwards.
    def probe_persisted(self):
        if not self.wanted("persisted"):
            return
        import hashlib
        query = "{ __typename }"
        digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
        payload = {"operationName": None, "variables": {},
                   "extensions": {"persistedQuery": {"version": 1,
                                                      "sha256Hash": digest}}}
        _st, _hd, body, _el, _raw = http_request(
            self.url, "POST", payload,
            {"Authorization": "Bearer " + self.token} if self.token
            else {}, self.timeout)
        msgs = error_messages(body)
        blob = " ".join(msgs).lower()
        ext_code = None
        if isinstance(body, dict):
            for e in body.get("errors") or []:
                if isinstance(e, dict) and isinstance(
                        e.get("extensions"), dict):
                    ext_code = e["extensions"].get("code")
                    break
        not_found = ("persistedquerynotfound" in blob
                     or ext_code == "PERSISTED_QUERY_NOT_FOUND")
        if not not_found:
            if "not supported" in blob or _st in (400, 404, 405):
                self.record("persisted", "NOT SUPPORTED",
                            "The hash-only request was refused (%s) — "
                            "the server does not speak APQ."
                            % (msgs[:1] or ["HTTP %d" % _st]),
                            {"hash_only": msgs[:1], "status": _st})
            else:
                self.record("persisted", "INCONCLUSIVE",
                            "The hash-only request gave no clear APQ "
                            "answer (%s)."
                            % (msgs[:1] or ["HTTP %d" % _st]),
                            {"hash_only": msgs[:1], "status": _st})
            return
        # Step 2: the same hash WITH the query — registers it.
        payload2 = dict(payload)
        payload2["query"] = query
        _st2, _hd2, body2, _el2, _raw2 = http_request(
            self.url, "POST", payload2,
            {"Authorization": "Bearer " + self.token} if self.token
            else {}, self.timeout)
        registered = has_data(body2)
        self.add_finding(
            "GQ-018",
            "Persisted queries accepted (APQ): the hash-only request "
            "was answered PersistedQueryNotFound (the server looked "
            "the hash up)%s — clients can run queries by hash alone, "
            "which bypasses any inspection that reads the query text."
            % (" and the hash+query request registered and executed"
               if registered else ""),
            "Disable APQ unless clients need it; if it is needed, "
            "allow only hashes registered at deploy time, and apply "
            "the same depth / complexity / auth checks to persisted "
            "queries as to plain ones.")
        self.record("persisted", "SUPPORTED",
                    "Hash-only request: PersistedQueryNotFound; "
                    "hash+query request: %s."
                    % ("executed (registered)" if registered
                       else "refused"),
                    {"registered": registered})

    # -- probe 19: multipart file upload -------------------------------------
    # graphql-multipart-request-spec: operations + map + file parts.
    # The file is a small harmless text file; the probe only asks
    # whether the server accepts it, never what it does with it.
    UPLOAD_CONTENT = b"GQLProbe lab upload test\n"

    def probe_upload(self):
        if not self.wanted("upload"):
            return
        boundary = "----GQLProbeUpload%d" % random.randint(0, 0xFFFFFF)
        operations = json.dumps({
            "query": "mutation($file: Upload!) { uploadFile(file: $file)"
                     " { filename size } }",
            "variables": {"file": None}})
        mapping = json.dumps({"0": ["variables.file"]})
        body = b""
        for name, content, ctype, fname in (
                ("operations", operations.encode("utf-8"),
                 "application/json", None),
                ("map", mapping.encode("utf-8"), "application/json", None),
                ("0", self.UPLOAD_CONTENT, "text/plain", "lab-test.txt")):
            body += ("--%s\r\n" % boundary).encode("utf-8")
            disp = 'Content-Disposition: form-data; name="%s"' % name
            if fname:
                disp += '; filename="%s"' % fname
            body += (disp + "\r\n").encode("utf-8")
            body += ("Content-Type: %s\r\n\r\n" % ctype).encode("utf-8")
            body += content + b"\r\n"
        body += ("--%s--\r\n" % boundary).encode("utf-8")
        headers = {"Content-Type":
                   "multipart/form-data; boundary=%s" % boundary}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        _st, _hd, resp_body, _el, _raw = http_raw(
            self.url, "POST", body, headers, self.timeout)
        data = (resp_body or {}).get("data") if isinstance(resp_body,
                                                           dict) else None
        uploaded = (data or {}).get("uploadFile")
        msgs = error_messages(resp_body)
        blob = " ".join(msgs).lower()
        if isinstance(uploaded, dict):
            self.add_finding(
                "GQ-019",
                "File upload accepted: the multipart upload executed "
                "and returned %s — an upload endpoint is a classic "
                "attack surface (stored content, parsing, size)."
                % redact(uploaded),
                "Disable file uploads unless the API needs them; "
                "validate the file type and size server-side, store "
                "uploads outside the web root, and require "
                "authentication for the upload mutation.")
            self.record("upload", "ACCEPTED",
                        "Multipart upload executed: %s" % redact(uploaded),
                        {"filename": uploaded.get("filename"),
                         "size": uploaded.get("size")})
        elif "not supported" in blob or "upload" in blob:
            self.record("upload", "NOT SUPPORTED",
                        "The multipart upload was refused: %s"
                        % (msgs[:1] or ["HTTP %d" % _st]),
                        {"errors": msgs[:1]})
        else:
            self.record("upload", "INCONCLUSIVE",
                        "No upload mutation answered (%s) — the lab "
                        "uploadFile mutation is not in this schema, so "
                        "the probe cannot tell whether uploads are "
                        "supported here."
                        % (msgs[:1] or ["HTTP %d" % _st]),
                        {"errors": msgs[:1]})

    # -- orchestration --------------------------------------------------------
    def run(self):
        """Run every wanted probe, in workflow order (introspection
        first, then the DoS set, then authz, then the rest; timing
        last, because its rate-limit check trips the flood guard)."""
        self.probe_introspection()
        self.probe_bypass()
        self.probe_depth()
        self.probe_batching()
        self.probe_alias()
        self.probe_duplication()
        self.probe_directive()
        self.probe_authz()
        self.probe_idor()
        self.probe_guessing()
        self.probe_mutation()
        self.probe_fingerprint()
        self.probe_get()
        self.probe_injection()
        self.probe_sensitive()
        self.probe_subscription()
        self.probe_persisted()
        self.probe_upload()
        self.probe_timing()
        self._build_field_map()
        return self

    def score(self):
        return score_findings(self.findings)

    def grade(self):
        return grade_for(self.score())

    def counts(self):
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            if f["severity"] in out:
                out[f["severity"]] += 1
        return out

# ---------------------------------------------------------------------------
# Reports.
# ---------------------------------------------------------------------------

def _findings_by_severity(findings, min_severity):
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings
            if SEVERITY_ORDER.get(f["severity"], 0) >= floor]


def build_report_text(scan, min_severity="low"):
    """The text report — findings first, then per-probe verdicts."""
    lines = []
    lines.append("GQLProbe v%s — GraphQL Security Tester" % VERSION)
    lines.append("by %s — AUTHORIZED USE ONLY" % AUTHOR)
    lines.append("=" * 58)
    lines.append(DISCLAIMER)
    lines.append("")
    lines.append("Endpoint: %s" % scan.url)
    lines.append("Probed: %s" % scan.started.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Token: %s" % mask_token(scan.token))
    lines.append("Engine: %s" % scan.engine)
    counts = scan.counts()
    lines.append("Score: %d/100 (grade %s) | Findings: %d "
                 "(%d critical, %d high, %d medium, %d low)"
                 % (scan.score(), scan.grade(), len(scan.findings),
                    counts["critical"], counts["high"], counts["medium"],
                    counts["low"]))
    lines.append("")
    findings = _findings_by_severity(scan.findings, min_severity)
    lines.append("Findings (%d)" % len(findings))
    lines.append("-" * 58)
    if not findings:
        lines.append("  No findings at severity %s or above." % min_severity)
    for f in findings:
        lines.append("  [%s] [%s] %s"
                     % (f["severity"].upper(), f["code"], f["name"]))
        lines.append("      Evidence: %s" % f["evidence"])
        lines.append("      Fix: %s" % f["fix"])
    lines.append("")
    lines.append("Probes (%d)" % len(scan.probes))
    lines.append("-" * 58)
    for name in PROBE_NAMES:
        if name not in scan.probes:
            continue
        p = scan.probes[name]
        lines.append("  %-14s %s" % (name, p["verdict"]))
        lines.append("      %s" % p["evidence"])
    lines.append("")
    if scan.schema is not None:
        lines.append("Schema (from introspection)")
        lines.append("-" * 58)
        lines.append("  Query fields (%d): %s"
                     % (len(scan.schema["query_fields"]),
                        ", ".join(sorted(scan.schema["query_fields"]))))
        lines.append("  Mutation fields (%d): %s"
                     % (len(scan.schema["mutation_fields"]),
                        ", ".join(sorted(scan.schema["mutation_fields"]))))
        lines.append("  Types (%d): %s"
                     % (len(scan.schema["types"]),
                        ", ".join(sorted(scan.schema["types"]))))
        sens = scan.schema.get("sensitive_fields") or []
        if sens:
            lines.append("  Sensitive fields: %s"
                         % ", ".join("%s.%s" % (s["type"], s["field"])
                                     for s in sens))
        roles = scan.schema.get("role_mutations") or []
        if roles:
            lines.append("  Role-changing mutations: %s" % ", ".join(roles))
        lines.append("")
    auth_map = (scan.probes.get("authz", {}).get("details") or {}).get(
        "field_map")
    if auth_map:
        lines.append("Field-level auth map (unauthenticated)")
        lines.append("-" * 58)
        for field in sorted(auth_map):
            lines.append("  %-14s %s" % (field, auth_map[field]))
        lines.append("")
    if scan.timings:
        lines.append("Timing (seconds)")
        lines.append("-" * 58)
        for key in sorted(scan.timings):
            lines.append("  %-22s %.3f" % (key, scan.timings[key]))
        lines.append("")
    lines.append("Rule for use: only probe GraphQL APIs you own or have "
                 "written permission to test.")
    return "\n".join(lines) + "\n"


def build_report_json(scan, min_severity="low"):
    """The JSON report — the same data, machine-readable."""
    findings = _findings_by_severity(scan.findings, min_severity)
    return {
        "tool": "GQLProbe", "version": VERSION, "author": AUTHOR,
        "disclaimer": DISCLAIMER,
        "endpoint": scan.url,
        "probed": scan.started.strftime("%Y-%m-%d %H:%M:%S"),
        "token_provided": bool(scan.token),
        "engine": scan.engine,
        "engine_evidence": scan.engine_evidence,
        "score": scan.score(), "grade": scan.grade(),
        "counts": scan.counts(),
        "findings": findings,
        "probes": scan.probes,
        "timings": scan.timings,
        "schema": ({
            "query_fields": sorted(scan.schema["query_fields"]),
            "mutation_fields": sorted(scan.schema["mutation_fields"]),
            "types": sorted(scan.schema["types"]),
            "sensitive_fields": scan.schema.get("sensitive_fields") or [],
            "role_mutations": scan.schema.get("role_mutations") or [],
        } if scan.schema else None),
        "schema_raw": scan.schema_raw,
    }


def write_report(scan, output, as_json, min_severity="low"):
    if as_json:
        text = json.dumps(build_report_json(scan, min_severity), indent=2)
    else:
        text = build_report_text(scan, min_severity)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(text)
    return output


def schema_snapshot(scan):
    """A small schema snapshot for --snapshot / --diff."""
    if scan.schema is None:
        return None
    return {
        "endpoint": scan.url,
        "taken": scan.started.strftime("%Y-%m-%d %H:%M:%S"),
        "query_fields": {k: sorted(v["args"])
                         for k, v in scan.schema["query_fields"].items()},
        "mutation_fields": {k: sorted(v["args"])
                            for k, v in
                            scan.schema["mutation_fields"].items()},
        "types": sorted(scan.schema["types"]),
    }


def schema_diff(old, new):
    """Compare two snapshots: added / removed / changed fields."""
    diff = {"added": [], "removed": [], "changed": []}
    for section in ("query_fields", "mutation_fields"):
        old_f = old.get(section, {})
        new_f = new.get(section, {})
        for name in sorted(set(new_f) - set(old_f)):
            diff["added"].append("%s.%s" % (section, name))
        for name in sorted(set(old_f) - set(new_f)):
            diff["removed"].append("%s.%s" % (section, name))
        for name in sorted(set(old_f) & set(new_f)):
            if sorted(old_f[name]) != sorted(new_f[name]):
                diff["changed"].append(
                    "%s.%s args %s -> %s" % (section, name,
                                             old_f[name], new_f[name]))
    for name in sorted(set(new.get("types", [])) - set(old.get("types", []))):
        diff["added"].append("type.%s" % name)
    for name in sorted(set(old.get("types", [])) - set(new.get("types", []))):
        diff["removed"].append("type.%s" % name)
    return diff


# ---------------------------------------------------------------------------
# Lab server starter (menu quick probes + run.py lab).
# ---------------------------------------------------------------------------

def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_lab(config, port=None):
    """Start lab_api.py as a subprocess. Returns (proc, url)."""
    here = os.path.dirname(os.path.abspath(__file__))
    port = port or free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(here, "lab_api.py"),
         "--config", config, "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = "http://127.0.0.1:%d/graphql" % port
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            status, _hd, body, _el, _raw = http_request(
                url, "POST", {"query": "{ __typename }"}, {}, 2)
            if status == 200 and isinstance(body, dict):
                return proc, url
        except Exception:  # noqa: BLE001 - server not up yet
            pass
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("Lab server (%s) did not start on port %d"
                       % (config, port))


def stop_lab(proc):
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def print_config(scan, output, as_json, min_severity, snapshot=None,
                 diff=None):
    """The Gobuster-style SCAN config block, printed before a run."""
    sep(ACCENT, "═")
    print(f"{ACCENT} GQLProbe v{VERSION} — GraphQL Security Tester{C.RST}")
    sep(ACCENT, "═")
    info("Endpoint", scan.url)
    info("Token", mask_token(scan.token))
    info("Probes", ", ".join(PROBE_NAMES) if scan.want_probes is None
         else ", ".join(sorted(scan.want_probes)))
    info("Max depth", str(scan.max_depth))
    info("Max batch", str(scan.max_batch))
    info("Output", output + (" (JSON)" if as_json else " (text)"))
    info("Min severity", min_severity)
    if snapshot:
        info("Snapshot", snapshot)
    if diff:
        info("Diff against", diff)
    for _line in textwrap.wrap(DISCLAIMER, width=56):
        print(f"{C.YEL}  {_line}{C.RST}")
    sep(ACCENT, "─")


def print_results(scan, min_severity="low"):
    counts = scan.counts()
    header("RESULTS — score %d/100 (grade %s)"
           % (scan.score(), scan.grade()))
    for name in PROBE_NAMES:
        if name not in scan.probes:
            continue
        p = scan.probes[name]
        verdict = p["verdict"]
        # Explicit sets, good checked FIRST — substring tests lie
        # ("NOT RECOVERABLE" contains "RECOVERABLE").
        bad = ("EXPOSED", "BYPASSED", "NO LIMIT", "ENABLED", "LEAKING",
               "RECOVERABLE", "EXECUTES", "WORKS", "ERROR LEAKED",
               "FLAGGED IN SCHEMA", "SUPPORTED", "ACCEPTED")
        good = ("DISABLED", "BLOCKED", "ENFORCED", "CLOSED", "LIMITED",
                "NOT RECOVERABLE", "AUTH ENFORCED", "CLEAN",
                "NONE FOUND", "RATE LIMIT PRESENT", "CLEAN (NO SCHEMA)",
                "NOT SUPPORTED")
        if any(verdict == g or verdict.startswith(g + " ")
               or verdict.startswith(g + " (") for g in good):
            mark = f"{C.GRN}+{C.RST}"
        elif any(b in verdict for b in bad):
            mark = f"{C.RED}!{C.RST}"
        else:
            mark = f"{C.YEL}?{C.RST}"
        print(f" [{mark}] {name:<14} {verdict}")
    findings = _findings_by_severity(scan.findings, min_severity)
    print()
    print(f" Findings: {len(findings)} ({counts['critical']} critical, "
          f"{counts['high']} high, {counts['medium']} medium, "
          f"{counts['low']} low)")
    for f in findings:
        print(f"  {sev_color(f['severity'])}[{f['severity'].upper()}] "
              f"[{f['code']}] {f['name']}{C.RST}")
        print(f"      {f['evidence']}")


def do_scan(scan, output, as_json, min_severity, snapshot_path=None,
            diff_path=None):
    """Run the scan, print results, write the report. Returns the
    exit code (0 clean, 1 findings, 2 error)."""
    if not QUIET:
        print_config(scan, output, as_json, min_severity,
                     snapshot_path, diff_path)
    try:
        scan.run()
    except Exception as exc:  # noqa: BLE001 - a failed run is exit 2
        err("Scan failed: %s" % exc)
        return 2
    if not QUIET:
        print_results(scan, min_severity)
    # Snapshot / diff.
    snap = schema_snapshot(scan)
    if snapshot_path and snap is not None:
        with open(snapshot_path, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, indent=2)
        ok("Schema snapshot saved to %s" % snapshot_path)
    if diff_path:
        try:
            with open(diff_path, "r", encoding="utf-8") as fh:
                old = json.load(fh)
            diff = schema_diff(old, snap or {})
            print()
            header("SCHEMA DIFF vs %s" % diff_path)
            if not diff["added"] and not diff["removed"] \
                    and not diff["changed"]:
                ok("No schema changes.")
            for kind in ("added", "removed", "changed"):
                for item in diff[kind]:
                    print(f"  {kind:<8} {item}")
        except OSError as exc:
            err("Could not read diff file: %s" % exc)
    if scan.schema_raw is not None and snapshot_path is None:
        pass
    try:
        write_report(scan, output, as_json, min_severity)
        ok("Report saved to %s" % output)
    except OSError as exc:
        err("Could not write report: %s" % exc)
        return 2
    # Exit code: 1 when a finding meets the fail-on threshold.
    floor = SEVERITY_ORDER.get(scan.fail_on, 0)
    if scan.fail_on == "none":
        return 0
    for f in scan.findings:
        if SEVERITY_ORDER.get(f["severity"], 0) >= floor:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Doctor, menu, CLI.
# ---------------------------------------------------------------------------

def doctor():
    """Check the setup: Python, requests, the lab server, a free port."""
    banner()
    header("DOCTOR — setup check")
    checks = []
    checks.append(("Python %s" % sys.version.split()[0], True))
    checks.append(("requests %s" % (
        __import__("requests").__version__ if HAVE_REQUESTS else "missing "
        "(urllib fallback will be used)"), True))
    here = os.path.dirname(os.path.abspath(__file__))
    lab_ok = os.path.isfile(os.path.join(here, "lab_api.py"))
    checks.append(("lab_api.py present", lab_ok))
    wl_ok = os.path.isfile(os.path.join(here, "wordlist.txt"))
    checks.append(("wordlist.txt present", wl_ok))
    try:
        port = free_port()
        checks.append(("free port available (%d)" % port, True))
    except OSError:
        checks.append(("free port available", False))
    # Can the lab server actually start?
    try:
        proc, url = start_lab("vulnerable")
        stop_lab(proc)
        checks.append(("lab server starts (vulnerable)", True))
    except Exception as exc:  # noqa: BLE001 - doctor reports, not raises
        checks.append(("lab server starts (%s)" % exc, False))
    bad = 0
    for label, good in checks:
        if good:
            ok(label)
        else:
            err(label)
            bad += 1
    if bad:
        err("Doctor: %d problem(s)" % bad)
        return 1
    ok("Doctor: all good")
    return 0


def menu_loop():
    """The numbered menu (default when run with no arguments)."""
    while True:
        clear()
        banner()
        header("MENU")
        print(f" {ACCENT}[1]{C.RST} Probe an endpoint")
        print(f" {ACCENT}[2]{C.RST} Quick probe vulnerable lab")
        print(f" {ACCENT}[3]{C.RST} Quick probe hardened lab")
        print(f" {ACCENT}[4]{C.RST} Quick probe partial lab "
              f"(suggestions on)")
        print(f" {ACCENT}[5]{C.RST} List all probes")
        print(f" {ACCENT}[6]{C.RST} Show schema fields")
        print(f" {ACCENT}[7]{C.RST} Run step tests")
        print(f" {ACCENT}[8]{C.RST} Check setup (doctor)")
        print(f" {ACCENT}[9]{C.RST} Start lab server")
        print(f" {ACCENT}[0]{C.RST} Exit")
        sep()
        choice = input(f"{ACCENT}[?]{C.RST} Select option: ").strip()
        if choice == "0":
            print("Bye.")
            return 0
        if choice == "1":
            url = input(f"{ACCENT}[?]{C.RST} ENTER ENDPOINT URL: ").strip()
            if not url:
                err("No URL given.")
                input("Press Enter...")
                continue
            token = input(f"{ACCENT}[?]{C.RST} ENTER TOKEN "
                          f"(Enter = none): ").strip() or None
            out = input(f"{ACCENT}[?]{C.RST} OUTPUT FILE "
                        f"[gqlprobe_report.txt]: ").strip() \
                or "gqlprobe_report.txt"
            scan = Scan(url, token=token)
            rc = do_scan(scan, out, False, "low")
            print("Exit code: %d" % rc)
            input("Press Enter...")
        elif choice in ("2", "3", "4"):
            config = {"2": "vulnerable", "3": "hardened",
                      "4": "partial"}[choice]
            try:
                proc, url = start_lab(config)
            except RuntimeError as exc:
                err(str(exc))
                input("Press Enter...")
                continue
            try:
                token = "lab-token-alice"
                out = "sample_report_%s.txt" % config
                scan = Scan(url, token=token)
                rc = do_scan(scan, out, False, "low")
                print("Exit code: %d" % rc)
            finally:
                stop_lab(proc)
            input("Press Enter...")
        elif choice == "5":
            header("PROBES")
            for code, name, sev in CHECKS:
                print(f"  {code}  {name:<44} {sev}")
            input("Press Enter...")
        elif choice == "6":
            url = input(f"{ACCENT}[?]{C.RST} ENTER ENDPOINT URL: ").strip()
            if not url:
                err("No URL given.")
                input("Press Enter...")
                continue
            token = input(f"{ACCENT}[?]{C.RST} ENTER TOKEN "
                          f"(Enter = none): ").strip() or None
            _st, _hd, body, _el, _raw = gql_post(
                url, INTROSPECTION_QUERY, None, token, {}, 10)
            schema = parse_schema(body)
            if not schema["query_fields"]:
                err("No schema returned (introspection may be disabled).")
            else:
                header("SCHEMA FIELDS")
                print(" Query: %s"
                      % ", ".join(sorted(schema["query_fields"])))
                print(" Mutation: %s"
                      % ", ".join(sorted(schema["mutation_fields"])))
                print(" Types: %s" % ", ".join(sorted(schema["types"])))
            input("Press Enter...")
        elif choice == "7":
            import test_gqlprobe
            rc = test_gqlprobe.main()
            print("Tests exit code: %d" % rc)
            input("Press Enter...")
        elif choice == "8":
            rc = doctor()
            print("Doctor exit code: %d" % rc)
            input("Press Enter...")
        elif choice == "9":
            config = input(f"{ACCENT}[?]{C.RST} CONFIG "
                           f"[vulnerable|hardened|partial]: ").strip() \
                or "vulnerable"
            if config not in ("vulnerable", "hardened", "partial"):
                err("Unknown config: %s" % config)
                input("Press Enter...")
                continue
            port = input(f"{ACCENT}[?]{C.RST} PORT [4000]: ").strip() \
                or "4000"
            here = os.path.dirname(os.path.abspath(__file__))
            print("Starting the lab server — press Ctrl-C to stop.")
            try:
                subprocess.run([sys.executable,
                                os.path.join(here, "lab_api.py"),
                                "--config", config, "--port", port])
            except KeyboardInterrupt:
                print("\nStopped.")
            input("Press Enter...")
        else:
            err("Unknown option: %s" % choice)
            input("Press Enter...")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="GQLProbe — GraphQL security tester "
                    "(AUTHORIZED USE ONLY: lab APIs you own).")
    p.add_argument("url", nargs="?", help="GraphQL endpoint URL")
    p.add_argument("--token", default=None,
                   help="Bearer token for the lab API")
    p.add_argument("--header", action="append", default=[],
                   help='Extra header, "Name: Value" (repeatable)')
    p.add_argument("-o", "--output", default="gqlprobe_report.txt",
                   help="Report file (default: gqlprobe_report.txt)")
    p.add_argument("--json", action="store_true",
                   help="Write the report as JSON")
    p.add_argument("--schema-out", default=None,
                   help="Also save the raw schema JSON to this file")
    p.add_argument("--snapshot", default=None,
                   help="Save a schema snapshot to this file")
    p.add_argument("--diff", default=None,
                   help="Compare the schema against a snapshot file")
    p.add_argument("--wordlist", default=None,
                   help="Field-name wordlist for the guessing probe")
    p.add_argument("--mutation", default="ping",
                   help="Harmless lab mutation to test "
                        "(allow-list: ping, updateProfile)")
    p.add_argument("--max-depth", type=int, default=50)
    p.add_argument("--max-batch", type=int, default=100)
    p.add_argument("--max-alias", type=int, default=ALIAS_COUNT)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--min-severity", default="low",
                   choices=["critical", "high", "medium", "low"])
    p.add_argument("--fail-on", default="low",
                   choices=["critical", "high", "medium", "low", "none"])
    p.add_argument("--probe", action="append", default=None,
                   help="Run only this probe (repeatable)")
    p.add_argument("--skip-probe", action="append", default=None,
                   help="Skip this probe (repeatable)")
    p.add_argument("--list-probes", action="store_true")
    p.add_argument("--list-fields", action="store_true")
    p.add_argument("--check", action="store_true",
                   help="Doctor: check the setup")
    p.add_argument("--skip-check", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--batch", action="store_true",
                   help="Never ask, use defaults")
    p.add_argument("-i", "--interactive", "--menu", action="store_true",
                   dest="menu", help="Open the numbered menu")
    p.add_argument("--version", action="store_true")
    p.add_argument("--no-color", action="store_true")
    return p


def main(argv=None):
    global QUIET
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color:
        C.disable()
    if args.version:
        print("GQLProbe %s by %s (theme: %s)" % (VERSION, AUTHOR, THEME))
        return 0
    if args.quiet:
        QUIET = True
    if args.list_probes:
        for code, name, sev in CHECKS:
            print(f"  {code}  {name:<44} {sev}")
        return 0
    if args.check:
        return doctor()
    if args.menu or (not args.url and not args.batch):
        if args.url:
            pass
        return menu_loop()
    if not args.url:
        parser.print_usage()
        print("gqlprobe.py: error: an endpoint URL is required "
              "(or run with no arguments for the menu)")
        return 2
    extra_headers = {}
    for h in args.header:
        if ":" in h:
            key, val = h.split(":", 1)
            extra_headers[key.strip()] = val.strip()
    here = os.path.dirname(os.path.abspath(__file__))
    wordlist = args.wordlist or os.path.join(here, "wordlist.txt")
    scan = Scan(args.url, token=args.token,
                extra_headers=extra_headers, timeout=args.timeout,
                max_depth=args.max_depth, max_batch=args.max_batch,
                max_alias=args.max_alias, wordlist_path=wordlist,
                mutation=args.mutation, min_severity=args.min_severity,
                fail_on=args.fail_on, probes=args.probe,
                skip_probes=args.skip_probe)
    rc = do_scan(scan, args.output, args.json, args.min_severity,
                 snapshot_path=args.snapshot, diff_path=args.diff)
    if args.schema_out and scan.schema_raw is not None:
        try:
            with open(args.schema_out, "w", encoding="utf-8") as fh:
                json.dump(scan.schema_raw, fh, indent=2)
            ok("Schema saved to %s" % args.schema_out)
        except OSError as exc:
            err("Could not write schema: %s" % exc)
            return 2
    if args.list_fields and scan.schema is not None:
        print("Query: %s" % ", ".join(sorted(scan.schema["query_fields"])))
        print("Mutation: %s"
              % ", ".join(sorted(scan.schema["mutation_fields"])))
    return rc


if __name__ == "__main__":
    sys.exit(main())
