#!/usr/bin/env python3
"""GQLProbe step tests — one function per PDF step (Steps 1-7) plus
Step 8 for the stretch items and the beyond-PDF extras.

Every test touches ONLY the lab API (lab_api.py, stdlib only) on a
free localhost port. The lab server is started by the tests and shut
down afterwards. No test ever touches a real endpoint.

Run:  python3 test_gqlprobe.py        (or: python run.py test)
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gqlprobe  # noqa: E402
import lab_api  # noqa: E402

TOTAL = 0
PASSED = 0
FAILURES = []


def check(cond, label):
    """One check: count it, print it, remember failures."""
    global TOTAL, PASSED
    TOTAL += 1
    if cond:
        PASSED += 1
        print("  [+] %s" % label)
    else:
        FAILURES.append(label)
        print("  [!] FAIL: %s" % label)


def start(config):
    """Start the lab in one config. Returns (proc, url)."""
    proc, url = gqlprobe.start_lab(config)
    print("  [*] lab %s on %s" % (config, url))
    return proc, url


def stop(proc):
    gqlprobe.stop_lab(proc)


def scan(url, token="lab-token-alice", **kw):
    """Run a full probe and return the Scan."""
    return gqlprobe.Scan(url, token=token, **kw).run()


def findings(scan, code=None):
    if code is None:
        return scan.findings
    return [f for f in scan.findings if f["code"] == code]


# ---------------------------------------------------------------------------
# Step 1 — one query against the lab API; the JSON matches the lab's own
# output (assert on the response shape, not just "it worked").
# ---------------------------------------------------------------------------

def step_1(url_vuln):
    print("Step 1 — one query, response shape matches the lab")
    status, _hd, body, _el, _raw = gqlprobe.gql_post(
        url_vuln, "{ __typename }", None, "lab-token-alice", {}, 10)
    check(status == 200, "POST returns HTTP 200")
    check(isinstance(body, dict), "response is a JSON object")
    check((body or {}).get("data") == {"__typename": "Query"},
          "data is exactly {__typename: Query} (the lab's own shape)")
    check("errors" not in body, "no errors array on a good query")
    # Variables + fragments, the way the probe sends them.
    status, _hd, body, _el, _raw = gqlprobe.gql_post(
        url_vuln,
        "query Q($id: ID!) { user(id: $id) { ...F } } "
        "fragment F on User { id name }",
        {"id": "1"}, "lab-token-alice", {}, 10)
    check(status == 200 and (body or {}).get("data", {}).get("user", {})
          .get("name") == "Alice",
          "variables + fragments: user 1 is Alice")
    # A bad field gives the GraphQL shape: data with null + errors.
    status, _hd, body, _el, _raw = gqlprobe.gql_post(
        url_vuln, "{ nosuchfield }", None, "lab-token-alice", {}, 10)
    check(isinstance(body, dict) and body.get("data") is not None
          and body.get("errors"),
          "unknown field: partial data + errors array (real GraphQL)")


# ---------------------------------------------------------------------------
# Step 2 — introspection: vulnerable returns the schema, hardened
# refuses it; partial proves the suggestion-mining path.
# ---------------------------------------------------------------------------

def step_2(url_vuln, url_hard, url_part):
    print("Step 2 — introspection: vulnerable vs hardened vs partial")
    s_v = scan(url_vuln)
    check(s_v.probes["introspection"]["verdict"] == "EXPOSED (anonymous)",
          "vulnerable: introspection EXPOSED (anonymous)")
    check(len(findings(s_v, "GQ-001")) == 1,
          "vulnerable: exactly one GQ-001 finding")
    check(s_v.probes["introspection"]["details"]["anonymous"]["exposed"]
          is True,
          "vulnerable: anonymous exposure recorded")
    check(s_v.schema is not None and len(s_v.schema["query_fields"]) == 7,
          "vulnerable: schema parsed (7 query fields)")
    s_h = scan(url_hard)
    check(s_h.probes["introspection"]["verdict"] == "DISABLED",
          "hardened: introspection DISABLED")
    check(not findings(s_h, "GQ-001"),
          "hardened: no GQ-001 finding")
    check(s_h.schema is None, "hardened: no schema parsed")
    s_p = scan(url_part)
    check(s_p.probes["introspection"]["verdict"] == "DISABLED",
          "partial: plain introspection DISABLED")
    check(s_p.probes["bypass"]["verdict"] == "BYPASSED",
          "partial: bypass probe BYPASSED (the guard has holes)")
    check(len(findings(s_p, "GQ-002")) == 3,
          "partial: three GQ-002 bypass findings "
          "(__type, GET, newline)")
    check(s_p.probes["guessing"]["verdict"] == "RECOVERABLE",
          "partial: schema RECOVERABLE via guessing/suggestions")


# ---------------------------------------------------------------------------
# Step 3 — schema parsing: the field list matches lab_api.py's schema.
# ---------------------------------------------------------------------------

def step_3(url_vuln):
    print("Step 3 — schema parsing matches lab_api.py")
    s_v = scan(url_vuln)
    schema = s_v.schema
    check(schema is not None, "schema parsed from introspection")
    expected_query = {"me", "user", "users", "post", "posts", "search",
                      "admin"}
    check(set(schema["query_fields"]) == expected_query,
          "query fields match the lab schema (%s)"
          % ", ".join(sorted(expected_query)))
    check(set(schema["mutation_fields"])
          == {"ping", "updateProfile", "grantAdmin"},
          "mutation fields are ping + updateProfile + grantAdmin")
    check(schema["mutation_fields"]["grantAdmin"]["args"]
          == {"userId": "ID"},
          "grantAdmin takes a userId argument")
    check("grantAdmin" in (schema.get("role_mutations") or []),
          "grantAdmin flagged as a role-changing mutation")
    check(schema["query_fields"]["user"]["args"] == {"id": "ID"},
          "user takes an id argument")
    check(schema["query_fields"]["search"]["args"] == {"q": "String"},
          "search takes a q argument")
    check("User" in schema["types"] and "Post" in schema["types"],
          "object types User and Post present")
    check(schema["types"]["User"]["fields"]["friends"]["type"] == "User",
          "User.friends is circular (User -> User)")
    check(any(f["field"] == "passwordHash"
              for f in schema.get("sensitive_fields") or []),
          "passwordHash flagged as a sensitive field")


# ---------------------------------------------------------------------------
# Step 4 — depth: hardened limits at 5, vulnerable answers past 20;
# the reports differ.
# ---------------------------------------------------------------------------

def step_4(url_vuln, url_hard):
    print("Step 4 — depth probe: hardened limit 5, vulnerable past 20")
    s_h = scan(url_hard)
    deep_h = s_h.probes["depth"]["details"]
    check(s_h.probes["depth"]["verdict"] == "LIMITED (max depth 5)",
          "hardened: depth LIMITED (max depth 5)")
    check(deep_h.get("deepest") == 5,
          "hardened: deepest answered depth is 5")
    check(not findings(s_h, "GQ-003"), "hardened: no GQ-003 finding")
    s_v = scan(url_vuln)
    deep_v = s_v.probes["depth"]["details"]
    check(s_v.probes["depth"]["verdict"] == "NO LIMIT",
          "vulnerable: depth NO LIMIT")
    check(deep_v.get("deepest") >= 20,
          "vulnerable: answers past depth 20 (deepest %s)"
          % deep_v.get("deepest"))
    check(len(findings(s_v, "GQ-003")) == 1,
          "vulnerable: one GQ-003 finding")
    check(s_h.score() > s_v.score(),
          "reports differ: hardened score %d > vulnerable score %d"
          % (s_h.score(), s_v.score()))


# ---------------------------------------------------------------------------
# Step 5 — batching count matches what the lab executed; authorization
# replay matches the manual observation.
# ---------------------------------------------------------------------------

def step_5(url_vuln, url_hard):
    print("Step 5 — batching counts + authorization replay")
    s_v = scan(url_vuln)
    check(s_v.probes["batching"]["verdict"] == "ENABLED",
          "vulnerable: batching ENABLED")
    check(s_v.probes["batching"]["details"].get("max_batch") == 100,
          "vulnerable: one request executed 100 queries")
    check(len(findings(s_v, "GQ-004")) == 1,
          "vulnerable: one GQ-004 finding")
    s_h = scan(url_hard)
    check(s_h.probes["batching"]["verdict"] == "DISABLED",
          "hardened: batching DISABLED")
    check(s_h.probes["batching"]["details"].get("max_batch") == 0,
          "hardened: 0 batched queries executed")
    # Authorization: unauthenticated replay.
    check(s_v.probes["authz"]["verdict"]
          == "LEAKING (me, admin, user, users)",
          "vulnerable: authz LEAKING (me, admin, user, users)")
    check(len(findings(s_v, "GQ-008")) == 4,
          "vulnerable: four GQ-008 findings, one per leaked field")
    check(s_h.probes["authz"]["verdict"] == "ENFORCED",
          "hardened: authz ENFORCED")
    check(not findings(s_h, "GQ-008"), "hardened: no GQ-008 finding")
    field_map = s_h.probes["authz"]["details"].get("field_map") or {}
    check(field_map.get("me") == "refused (auth)",
          "hardened: field map says me is refused (auth)")


# ---------------------------------------------------------------------------
# Step 6 — CLI + report: run twice with different tokens, both reports
# complete.
# ---------------------------------------------------------------------------

def step_6(url_vuln):
    print("Step 6 — CLI twice (two tokens), both reports complete")
    reports = []
    for token, name in (("lab-token-alice", "alice"),
                        ("lab-token-bob", "bob")):
        out = os.path.join(HERE, "test_report_%s.txt" % name)
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "gqlprobe.py"), url_vuln,
             "--token", token, "-o", out, "--no-color"],
            capture_output=True, text=True, timeout=120)
        check(proc.returncode == 1,
              "CLI (%s) exits 1 — findings on the vulnerable lab" % name)
        check(os.path.isfile(out), "CLI (%s) wrote %s" % (name, out))
        text = open(out, encoding="utf-8").read()
        reports.append(text)
        check("GQLProbe" in text and "Findings" in text
              and "Probes" in text,
              "CLI (%s) report has the Findings and Probes sections"
              % name)
        check("lab-token-alice" not in text and "lab-token-bob" not in text,
              "CLI (%s) report never prints the token" % name)
        check("GQ-001" in text and "GQ-009" in text,
              "CLI (%s) report names GQ-001 and GQ-009" % name)
        check("Score: 0/100" in text,
              "CLI (%s) report scores the vulnerable lab 0/100" % name)
        os.remove(out)
    check("the scan token (user 1) fetched" in reports[0],
          "alice report: IDOR evidence names user 1 as the caller")
    check("the scan token (user 2) fetched" in reports[1],
          "bob report: IDOR evidence names user 2 as the caller")
    check(reports[0] != reports[1],
          "the two token reports differ (IDOR evidence names the caller)")


# ---------------------------------------------------------------------------
# Step 7 — full end-to-end on vulnerable AND hardened; read both saved
# reports start to finish: every probe has a verdict and evidence.
# ---------------------------------------------------------------------------

def step_7(url_vuln, url_hard):
    print("Step 7 — end-to-end runs, reports read start to finish")
    for url, name, want_score in ((url_vuln, "vulnerable", 0),
                                  (url_hard, "hardened", 90)):
        out = os.path.join(HERE, "test_report_%s.txt" % name)
        out_json = os.path.join(HERE, "test_report_%s.json" % name)
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "gqlprobe.py"), url,
             "--token", "lab-token-alice", "-o", out, "--json",
             "--schema-out", os.path.join(HERE, "test_schema_%s.json"
                                          % name),
             "--no-color"],
            capture_output=True, text=True, timeout=120)
        check(proc.returncode in (0, 1),
              "CLI (%s) exits 0/1, not 2" % name)
        text = open(out, encoding="utf-8").read()
        data = json.loads(text)
        check(data["score"] == want_score,
              "CLI (%s) JSON score is %d/100" % (name, want_score))
        check(data["grade"] == ("F" if want_score == 0 else "A"),
              "CLI (%s) JSON grade is %s"
              % (name, "F" if want_score == 0 else "A"))
        check(len(data["probes"]) == 16,
              "CLI (%s) JSON has all 16 probes" % name)
        for pname in gqlprobe.PROBE_NAMES:
            p = data["probes"].get(pname)
            check(p is not None and p.get("verdict")
                  and p.get("evidence"),
                  "CLI (%s) probe %s has a verdict and evidence"
                  % (name, pname))
        check(len(data["findings"]) == data["counts"]["critical"]
              + data["counts"]["high"] + data["counts"]["medium"]
              + data["counts"]["low"],
              "CLI (%s) finding counts add up" % name)
        check("lab-token-alice" not in text,
              "CLI (%s) JSON report never prints the token" % name)
        # The text report too (same run, --json replaced the file, so
        # re-run as text and read it).
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "gqlprobe.py"), url,
             "--token", "lab-token-alice", "-o", out, "--no-color"],
            capture_output=True, text=True, timeout=120)
        text = open(out, encoding="utf-8").read()
        check(text.startswith("GQLProbe"),
              "CLI (%s) text report starts with the banner line" % name)
        for pname in gqlprobe.PROBE_NAMES:
            check(pname in text,
                  "CLI (%s) text report mentions probe %s" % (name, pname))
        for path in (out, out_json):
            if os.path.isfile(path):
                os.remove(path)
        schema_path = os.path.join(HERE, "test_schema_%s.json" % name)
        if os.path.isfile(schema_path):
            os.remove(schema_path)


# ---------------------------------------------------------------------------
# Step 8 — stretch + extras: guessing, mutation, timing, alias/directive/
# duplication, IDOR, fingerprint, snapshot + diff.
# ---------------------------------------------------------------------------

def step_8(url_vuln, url_hard, url_part):
    print("Step 8 — stretch + extras")
    s_p = scan(url_part)
    guessed = s_p.probes["guessing"]["details"]
    check(len(findings(s_p, "GQ-010")) == 1,
          "partial: one GQ-010 finding (schema recoverable)")
    check("user" in (guessed.get("discovered") or [])
          or "users" in (guessed.get("discovered") or [])
          or guessed.get("suggested"),
          "partial: guessing recovered fields and/or suggestions")
    s_h = scan(url_hard)
    check(s_h.probes["guessing"]["verdict"] == "NOT RECOVERABLE",
          "hardened: guessing finds nothing extra")
    check(not findings(s_h, "GQ-010"),
          "hardened: no GQ-010 finding")
    # Harmless mutation: with a token, and (vulnerable) without one.
    s_v = scan(url_vuln)
    check(s_v.probes["mutation"]["verdict"] == "EXECUTES WITHOUT AUTH",
          "vulnerable: mutation EXECUTES WITHOUT AUTH")
    check(len(findings(s_v, "GQ-011")) == 2,
          "vulnerable: two GQ-011 findings (ping + updateProfile)")
    check(s_h.probes["mutation"]["verdict"] == "AUTH ENFORCED",
          "hardened: mutation AUTH ENFORCED")
    check(not findings(s_h, "GQ-011"), "hardened: no GQ-011 finding")
    # Timing table present, numbers sane.
    check(s_v.timings and all(
        isinstance(v, (int, float)) and 0 <= v < 60
        for v in s_v.timings.values()),
          "vulnerable: timing table present, all values 0-60s")
    check("depth_5" in s_v.timings and "batch_100" in s_v.timings
          and "timing_shallow_1" in s_v.timings,
          "vulnerable: timing table has depth, batch and shallow rows")
    check(s_h.probes["timing"]["verdict"] == "RATE LIMIT PRESENT",
          "hardened: timing probe sees the rate limit")
    # Alias / directive / duplication: vulnerable only.
    for code, probe in (("GQ-005", "alias"), ("GQ-006", "duplication"),
                        ("GQ-007", "directive")):
        check(len(findings(s_v, code)) == 1,
              "vulnerable: %s fires (%s)" % (code, probe))
        check(s_h.probes[probe]["verdict"] == "LIMITED",
              "hardened: %s LIMITED" % probe)
        check(not findings(s_h, code),
              "hardened: no %s finding" % code)
    # IDOR: vulnerable only.
    check(s_v.probes["idor"]["verdict"] == "LEAKING",
          "vulnerable: IDOR LEAKING")
    check(len(findings(s_v, "GQ-009")) == 1,
          "vulnerable: one GQ-009 finding")
    check("user 2" in findings(s_v, "GQ-009")[0]["evidence"]
          and "lab-token" not in findings(s_v, "GQ-009")[0]["evidence"],
          "vulnerable: IDOR evidence names user 2, never the token")
    check(s_h.probes["idor"]["verdict"] == "CLOSED",
          "hardened: IDOR CLOSED")
    check(not findings(s_h, "GQ-009"), "hardened: no GQ-009 finding")
    # Fingerprinting: names a family, or says unknown honestly.
    for s, name in ((s_v, "vulnerable"), (s_h, "hardened")):
        verdict = s.probes["fingerprint"]["verdict"]
        check(verdict and verdict != "",
              "%s: fingerprint probe has a verdict" % name)
        check("unknown" in verdict.lower()
              or "Apollo" in verdict or "graphql" in verdict.lower()
              or "lab" in verdict.lower(),
              "%s: fingerprint names a family or says unknown (%s)"
              % (name, verdict[:60]))
    # GET probe: plain queries run over GET on every lab config
    # (only introspection over GET is gated) — so it WORKS even on
    # the hardened lab, and the GQ-014 note is the one finding
    # that keeps hardened at 90/100 instead of 100/100.
    check(s_v.probes["get"]["verdict"] == "WORKS",
          "vulnerable: GET WORKS")
    check(s_h.probes["get"]["verdict"] == "WORKS",
          "hardened: GET WORKS (plain queries, not introspection)")
    check(len(findings(s_h, "GQ-014")) == 1,
          "hardened: the one GQ-014 finding is the whole gap")
    # Snapshot + diff: same schema twice = no change; a changed field
    # list is detected.
    snap = gqlprobe.schema_snapshot(s_v)
    check(snap is not None and "user" in snap["query_fields"],
          "snapshot: taken from the vulnerable lab, has user")
    check(gqlprobe.schema_diff(snap, snap)
          == {"added": [], "removed": [], "changed": []},
          "diff: identical snapshots, no changes")
    changed = json.loads(json.dumps(snap))
    changed["query_fields"]["newfield"] = ["id"]
    del changed["query_fields"]["search"]
    diff = gqlprobe.schema_diff(snap, changed)
    check("query_fields.newfield" in diff["added"],
          "diff: added field detected")
    check("query_fields.search" in diff["removed"],
          "diff: removed field detected")


def main():
    procs = []
    try:
        proc_v, url_v = start("vulnerable")
        proc_h, url_h = start("hardened")
        proc_p, url_p = start("partial")
        procs = [proc_v, proc_h, proc_p]
        step_1(url_v)
        step_2(url_v, url_h, url_p)
        step_3(url_v)
        step_4(url_v, url_h)
        step_5(url_v, url_h)
        step_6(url_v)
        step_7(url_v, url_h)
        step_8(url_v, url_h, url_p)
    finally:
        for proc in procs:
            stop(proc)
    print()
    print("=" * 58)
    print("GQLProbe step tests: %d/%d checks passed"
          % (PASSED, TOTAL))
    if FAILURES:
        print("Failures (%d):" % len(FAILURES))
        for label in FAILURES:
            print("  - %s" % label)
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
