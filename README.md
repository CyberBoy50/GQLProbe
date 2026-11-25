# GQLProbe — GraphQL Security Tester

A command-line tool, written in Python, that probes a GraphQL API
the way an attacker would — and reports every hole it finds, with
the evidence and the fix. It sends the standard introspection query,
climbs nested queries until the server refuses, fires array batches,
aliases, duplicate fields and unknown directives at the engine,
replays data queries without a token, tries another user's object,
guesses field names from the server's own error suggestions, runs a
harmless mutation, and times everything — then saves a verdict +
evidence for every probe to a report file (text or JSON), with a
hardening score + grade (A–F).

Before anyone ships a GraphQL API, they ask what it leaks. This
tool answers that question by asking the API itself — with `requests`
when it is installed, and `urllib` (standard library) when it is not.
The probe itself is zero-dependency, and it runs on Windows, macOS
and Linux.

> **AUTHORIZED USE ONLY** — only probe GraphQL APIs you own or have
> written permission to test. Probing someone else's API without
> permission is unauthorized access (Prevention of Electronic Crimes
> Act, 2016, Pakistan).
>
> DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, authorized security testing only. You are using it on your own responsibility. The authors are not responsible for how you use it, or for anything that happens because of your use. Only test systems, code, and data you own or have explicit written permission to test — testing anything else may be illegal (for example, PECA 2016 in Pakistan).
>
> The repo ships a lab API (`lab_api.py`) with
> three configs — vulnerable, hardened and partial — so you never
> need a real target to learn the tool.

## The 19 probes

| Code | Probe | What it does |
|---|---|---|
| GQ-001 | Introspection exposed | Sends the standard introspection query with a token AND without one; anonymous exposure is Critical, auth-only is High |
| GQ-002 | Introspection bypass | When introspection is refused: `__type` queries, GET-based introspection, whitespace/newline tricks after `__schema`, fragment tricks |
| GQ-003 | No depth limit | Nested queries of increasing depth (1, 2, 3, 5, 8, 10, 15, 20, 30, 50) built from the schema's circular relations; records the deepest depth answered |
| GQ-004 | Batching enabled | One request with an array of 10, 50, 100 identical queries; counts the response objects |
| GQ-005 | Alias overloading | One query with 101 aliases of the same field (graphql-cop rule) |
| GQ-006 | Field duplication | The same field 50 times in one selection set |
| GQ-007 | Directive overloading | One field with 10 unknown directives |
| GQ-008 | Field returns data without auth | Replays a data query with no token, field by field against the authenticated response; plus a field-level auth map for every query field |
| GQ-009 | IDOR / BOLA | With a lab user token, asks `me` for the caller's own id, then requests other users' objects by id |
| GQ-010 | Schema recoverable via guessing | Curated wordlist (1373 common field names, `wordlist.txt`, organised by area) PLUS Clairvoyance-style suggestion mining: typo a field, read "Did you mean …?" out of the error, feed it back in |
| GQ-011 | Mutation without auth | A HARMLESS lab-only mutation (`ping`, `updateProfile`) run with and without a token; any mutation not on the allow-list is refused |
| GQ-012 | Expensive query / timing | Per-probe response times (mean of 3 runs), shallow-vs-deep and 1-vs-100-batch timing table |
| GQ-013 | Sensitive field exposed | Schema fields matching password/secret/token/key/ssn/creditCard/internal/admin, plus a live check: does `passwordHash` come back without a token? |
| GQ-014 | GET-based queries (CSRF angle) | The same query over GET — if the API ever uses cookie auth, that is a CSRF vector |
| GQ-015 | Argument injection error leak | SAFE payloads only (a single quote in a string argument); watches for a raw database error in the response |
| GQ-016 | No rate limiting observed | 20 rapid cheap queries; a 429 (or growing delay) means rate limiting is present — Low note, not a finding |
| GQ-017 | Subscriptions supported | A subscription operation over plain HTTP, plus a websocket Upgrade (graphql-ws) — a 101 or event data means the stream is live |
| GQ-018 | Persisted queries accepted (APQ) | Hash-only request (extensions.persistedQuery, no query text), then the same hash WITH the query — PersistedQueryNotFound + execution means APQ is live |
| GQ-019 | File upload accepted | A small harmless text file sent as multipart/form-data (graphql-multipart-request-spec) to the lab uploadFile mutation |

Extras beyond the PDF: engine fingerprinting (error shapes,
response headers, `__typename` behaviour, error extensions.code —
a best-guess family, or "unknown" when it cannot tell; the report
says plainly that it is a best guess, never certain); query complexity/cost estimation
(fields × (depth+1) + aliases, reported next to the server's
answer); schema snapshot + `--diff` against a previous run;
per-finding severity + hardening score + grade (start 100, −25
Critical, −15 High, −10 Medium, −5 Low, clamp 0–100, A ≥ 90
B ≥ 80 C ≥ 70 D ≥ 60 F < 60).

## How to run it

```bash
git clone https://github.com/CyberBoy50/GQLProbe.git
cd GQLProbe
python run.py setup        # first time only (venv + requests; the probe
                           # falls back to urllib without it)
python run.py lab vulnerable   # start the lab API (port 4000)
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
python run.py test         # the 217 step-test checks
python run.py doctor       # check the setup
python run.py menu         # the numbered menu
```

Or call the probe directly:

```bash
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice
python3 gqlprobe.py <url> --token <token> -o report.txt --json
python3 gqlprobe.py <url> --snapshot schema.json
python3 gqlprobe.py <url> --diff schema.json
python3 gqlprobe.py --list-probes
python3 gqlprobe.py --check
```

Exit codes: 0 = no findings above the threshold; 1 = findings;
2 = usage / unreachable endpoint / invalid response.

## The menu

```
[1] Probe an endpoint
[2] Quick probe vulnerable lab
[3] Quick probe hardened lab
[4] Quick probe partial lab (suggestions on)
[5] List all probes
[6] Show schema fields
[7] Run step tests
[8] Check setup (doctor)
[9] Start lab server
[0] Exit
```

## The lab API

`lab_api.py` is a GraphQL server on the standard library only
(`http.server` + a hand-written mini executor: fields, arguments,
nested selection sets, named + inline fragments, aliases,
variables, directives `@skip`/`@include`, `__schema`/`__type`
introspection, `__typename`). No Flask, no strawberry — nothing to
install.

Schema: `User { id name email role bio passwordHash friends }`
(friends is circular — `User → friends → User` — for the depth
probe), `Post { id title body author }`, `Query { me user(id:)
users post(id:) posts search(q:) admin }`, `Mutation { ping
updateProfile(input:) grantAdmin(userId:) }`. Three users in memory
(Alice, Bob, Carol the admin); tokens `lab-token-alice`,
`lab-token-bob`, `lab-token-admin`.

Three configs:

| Config | Introspection | Depth limit | Batching | Suggestions | Rate limit | Auth | IDOR |
|---|---|---|---|---|---|---|---|
| vulnerable | on | none | on | on | off | off | open |
| hardened | off | 5 | off | off | on | enforced | closed |
| partial | off, but the guard has holes (`__type`, GET, newline) | 5 | off | on | on | enforced | closed |

```bash
python run.py lab vulnerable   # or hardened, or partial
python3 lab_api.py --config hardened --port 4001
```

## Safety

- The token is NEVER printed in reports or verbose output (shown
  as `provided (N chars, masked)`).
- Values in responses are redacted in findings (types/lengths,
  never real emails, tokens or secrets).
- The mutation probe refuses any mutation name not on the
  allow-list (`ping`, `updateProfile`) — `grantAdmin` is flagged as
  a role-changing mutation, never executed.
- The banner says AUTHORIZED USE ONLY. The tool accepts any URL you
  give it, but the docs say lab-only: never probe a real API without
  written permission.
- The banner, every generated report (text and JSON) and this README
  carry the same explicit disclaimer: "DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, authorized security testing only. You are using it on your own responsibility. The authors are not responsible for how you use it, or for anything that happens because of your use. Only test systems, code, and data you own or have explicit written permission to test — testing anything else may be illegal (for example, PECA 2016 in Pakistan)."

## Theme

Red — chosen by the user (like PipeSentry's Red/Orange). All
colours live in one place, the `C` colour class in `gqlprobe.py`
(`ACCENT = C.RED`, `ACCENT2 = C.YEL`), so the theme is changeable
in one place. `--no-color` strips every colour code.

## Files

| File | What it is |
|---|---|
| `gqlprobe.py` | The probe (19 probes, CLI + menu + doctor) |
| `lab_api.py` | The lab GraphQL server (stdlib only, 3 configs) |
| `test_gqlprobe.py` | The 8 build-plan step tests + Step 9 for the v1.2 probes (217 checks) |
| `wordlist.txt` | The curated field-name wordlist (1373 names, organised by area) |
| `run.py` / `run.bat` / `run.sh` | Cross-platform launchers |
| `requirements.txt` | `requests` (optional — urllib fallback) |
| `RESEARCH_CLI_TOOLS.md` | Research: graphql-cop, Clairvoyance, graphw00f, InQL, gqlmap/batchql |
| `RESEARCH_IMPLEMENTATION.md` | Implementation design |
| `sample_report_vulnerable.txt` / `.json` | Real probe reports: vulnerable lab, 0/100 F |
| `sample_report_hardened.txt` / `.json` | Real probe reports: hardened lab, 90/100 A |
| `README.md` / `DEMO.md` / `STEP_BY_STEP_GUIDE.md` | Docs |

## Version history

| Version | What changed |
|---|---|
| v1.2 | Zero-limits upgrade: subscription probing (GQ-017, HTTP + websocket), persisted-query / APQ probing (GQ-018), multipart file-upload probing (GQ-019); wordlist expanded 393 → 1373 names; fingerprinting covers more engines (graphql-ruby, Hot Chocolate, graphql-java, Hasura) and reads error extensions.code, still labelled a best guess; the lab gained a Subscription type, an uploadFile mutation and APQ/upload handling, and was itself probed against the public demo endpoint countries.trevorblades.com (see DEMO.md). Vulnerable lab still 0/100 F (now 19 findings), hardened still 90/100 A (1 finding, GQ-014), partial still 30/100 F. 217 step-test checks pass. |
| v1.1 | Text-only change: added an explicit authorized-use responsibility disclaimer — in the banner, in every generated report (text header and JSON `disclaimer` field) and in the README. No detection logic, rule, finding, score or behaviour changed. 173 step-test checks pass. |
| v1.0 | First release. All 6 PDF must-haves + all 3 stretch items + the beyond-PDF extras (bypasses, alias/dup/directive, fingerprinting, IDOR, sensitive-field flagging, cost estimation, GET/CSRF, argument-injection probe, snapshot + diff, score + grade). 173 step-test checks pass. |
