# GQLProbe — Research: How to Implement It

Design notes from the research (Wed 2026-11-25, late night). Technique
facts come from the tools' own docs found in the searches (graphql-cop's
DoS tests, Clairvoyance's suggestion mining, graphw00f fingerprinting,
the graphql-audit skill's quick-kill list, CVE-2024-37155 / CVE-2024-50312)
and the GraphQL-over-HTTP specification.

## 1. HTTP client — requests preferred, urllib fallback

- The PDF's Step 1 names the `requests` library. The tool tries `import
  requests` first; when it is missing, it falls back to stdlib `urllib`
  (same interface: post JSON, get JSON, headers, timeout). `requirements.txt`
  lists `requests` but the tool must work with nothing installed — the
  probe is zero-dependency, the library is a convenience.
- Every request: POST JSON `{"query": ..., "variables": {...}}` with
  `Content-Type: application/json`, `Accept: application/json`, a
  `--timeout` (default 10s) and a `--user-agent`. Timeouts are clean
  errors ("no response in Ns"), never tracebacks. A non-JSON response is
  reported as-is (status + first 200 chars of body) and the probe is
  marked "inconclusive", not "passed".
- Auth: `--token` is sent as `Authorization: Bearer <token>`; `--header`
  allows extra headers (e.g. `X-Api-Key: ...`). The token is NEVER printed
  in the report or in verbose output (mask it as `Bearer ***`).

## 2. Introspection probe (+ bypasses)

- Standard introspection query (the full `__schema` query: queryType,
  mutationType, subscriptionType, types { name kind description fields {
  name args { name type { name kind ofType { name kind } } } } }, directives,
  plus `__type` for single types). Send it with the token AND without it
  (two runs — introspection open to anonymous users is worse than open to
  authenticated users; record both).
- Verdict: full schema returned → "Exposed" (Critical when anonymous,
  High when authenticated-only); refused with a clean GraphQL error →
  "Disabled"; refused with a non-GraphQL error (500/HTML) → "Inconclusive".
- Bypass probes (extra, Clairvoyance parity) — run when the standard query
  is refused: (a) `__type(name: "Query")` query; (b) the same introspection
  over GET (`?query=...` URL-encoded); (c) the introspection query with a
  newline/space after `__schema` (`{ __schema \n { types { name } } }` —
  the CVE-2024-37155 regex-bypass shape); (d) the introspection query
  inside a named fragment. Any bypass that returns schema is a finding
  ("Introspection disabled but bypassable via …", High) with the exact
  payload that worked.
- Save the returned schema to `--schema-out schema.json` (and always keep
  it in the JSON report) so the other probes can build queries from it.

## 3. Schema parsing

- Parse the introspection response into: query fields (name → args with
  names + types), mutation fields, subscription fields, object types
  (name → fields), input types, enums, directives. Keep the raw schema
  JSON for the report.
- Sensitive-field flagging (extra, from the GraphQL Security Tester):
  any field whose name contains password / secret / token / key / ssn /
  creditCard / internal / admin, and any mutation whose name contains
  role / permission / admin / delete / grant — list them with their type
  and arguments. These are findings (Medium: "sensitive field exposed
  in schema") only when the field is actually queryable (see §5); the
  schema list itself is informational.
- The field list is printed by `--list-fields` and in the report, and is
  what the depth/batching/authz probes build their queries from.

## 4. Depth probe

- Build nested queries from the schema's circular relations (e.g.
  `user { friends { friends { … } } }` — User → friends → User). If the
  schema has no cycle, use the introspection types themselves
  (`__schema { types { fields { type { ofType { … } } } } }` — the
  circular-introspection bomb) or the deepest chain the schema offers.
- Send depths 1, 2, 3, 5, 8, 10, 15, 20, 30, 50 (configurable
  `--max-depth`), stop at the first refusal/timeout, and record the
  deepest depth the API answered. Verdict: a limit found at depth ≤ 10 →
  "Limited (max depth N)"; answered past depth 20 → "No depth limit"
  (High — DoS); refused at depth 0 (query rejected outright) → "Blocked".
- Also record the response time per depth (see §8) — a depth that answers
  but takes 10x longer is still a finding ("expensive depth").

## 5. Batching + alias + field-duplication + directive probes (DoS set)

- **Array batching:** send a JSON array of N identical cheap queries
  (`[{query: "{ __typename }"} × N]`) with N = 10, 50, 100. Count the
  response objects. Verdict: ≥ 10 responses → "Batching enabled"
  (High — rate-limit bypass + DoS amplifier); fewer → "Limited to N";
  a single error object → "Disabled". Record the time for 1 vs 100
  (the batching-dos delta).
- **Alias overloading** (graphql-cop rule): one query with 101 aliases
  (`alias0: __typename … alias100: __typename`). Success = the 100th
  alias's data in the response → "No alias limit" (High).
- **Field duplication:** the same field repeated 50 times in one
  selection set; success = 50 copies in the response → "No dedup
  limit" (Medium).
- **Directive overloading** (graphql-cop rule): `__typename` with 10
  `@aa` directives; the error array's length proves the engine
  processed them → "No directive limit" (Medium).
- All four are cheap on the lab server (they resolve `__typename`
  only) and are capped by `--max-batch` / `--max-alias` so the tool
  never floods a real server by accident.

## 6. Authorization probe (+ IDOR/BOLA)

- Replay a data query (built from the schema — e.g. `{ me { id name
  email } }` and `{ user(id: "1") { id name } }`) with NO token and
  compare against the authenticated response, field by field. Any field
  that returns data unauthenticated is a finding (High for `me`/
  `admin`/sensitive fields, Medium for public-looking data) with the
  exact field name and the data shape (values redacted — print types
  and lengths, never real emails/tokens).
- **Field-level auth map (extra):** for every query field in the
  schema, send `{ field { __typename } }` (or with a minimal required
  argument) unauthenticated and record which answer and which refuse —
  a per-field table in the report. Fields that answer without a token
  but need one for their siblings are the interesting ones.
- **IDOR/BOLA probe (extra):** with a lab user-A token, request user
  B's object (`user(id: "2")` while authenticated as user 1); if user
  B's data comes back, that is "IDOR — object of another user returned"
  (Critical in the lab; in the report, name the field and the IDs used).
  The lab API must have two users with distinct data for this to be
  meaningful.
- **Mutation authz:** the harmless mutation (see §7) is also run
  without a token — if it executes, that is a Critical finding.

## 7. Field guessing, mutation testing, timing (the 3 stretch items)

- **Field guessing:** when introspection is disabled, probe a curated
  in-repo wordlist (`wordlist.txt`, ~200 common field names: user,
  users, me, admin, login, logout, register, profile, email, password,
  posts, post, comments, orders, payment, search, feed, settings,
  notifications, followers, …) against the Query type — send `{ <word>
  { __typename } }` per word (batched 10 at a time when batching works,
  one at a time otherwise) and record which words exist. Then
  **suggestion mining** (Clairvoyance-style): send a typo'd field
  (`usr`, `emai`, `postz`) and parse "Did you mean 'user'?" from the
  error's `extensions`/`message`; feed every suggested name back into
  the guesser and into the schema list. Verdict: any field recovered
  while introspection is off → "Schema recoverable via guessing/
  suggestions" (High) with the recovered field list.
- **Mutation testing:** run a HARMLESS mutation against the lab API
  only — the lab defines `updateProfile(input: {bio: "lab-test"})`
  (or a `ping` mutation that changes nothing) — with the token and
  without it. Record whether it executes in each case. A mutation
  that executes without authorization is Critical. The mutation must
  be read-only in effect (the lab's resolver writes to an in-memory
  lab-only field); the tool refuses to run any other mutation
  (`--mutation` takes only a name from the lab's allow-list, printed
  in the report).
- **Timing comparison:** every probe records response times (mean of 3
  runs where it makes sense). Report a timing table: shallow query vs
  deep query, 1 query vs 100-query batch, with/without token. A deep
  query that takes > 5x the shallow baseline is flagged "expensive
  query" (Medium). **Rate-limit detection (extra):** send 20 identical
  cheap queries as fast as possible; a 429, a growing delay, or an
  error after N requests means "rate limiting present (kicks in at
  request N)"; none of those means "no rate limiting observed" (Low
  note, not a finding — absence of evidence is not proof).

## 8. Extras (beyond the PDF — the "0 limits" brief)

- **Engine fingerprinting:** error shapes (Apollo-style "Cannot query
  field" vs Hasura-style vs graphene-style), response headers
  (`Server`, `x-powered-by`), `__typename` behaviour, directive names
  in errors — report the best-guess engine family ("behaves like
  Apollo Server" etc.) with the evidence, and say when it is unknown.
- **Query complexity/cost estimation:** for each probe query, count
  fields + depth + aliases into a cost number (fields × (depth + 1) +
  aliases) and report it next to the server's own answer — if the
  server reports a complexity error, quote its limit.
- **GET-support check:** run the cheapest query over GET; if it
  executes, note "GET-based queries work — CSRF angle" (Medium) with
  the curl shape.
- **Argument-injection probe (safe payloads only, lab-only):** send a
  string argument containing a single quote (`search: "lab'test"`) and
  watch for a database error in the response; a clean GraphQL error is
  fine, a raw SQL/NoSQL error leaking is a finding (High). The lab API
  must answer with a clean error — the probe proves the tool checks,
  not that it exploits.
- **Schema snapshot + diff:** `--snapshot` saves the schema JSON;
  `--diff <old.json>` compares a new run against it and lists added /
  removed / changed fields. Useful for CI ("did the schema change?").
- **Hardening score + grade (family pattern, extra):** start at 100;
  −25 per Critical, −15 per High, −10 per Medium, −5 per Low; clamp
  0–100; grade A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60. The score ranks
  the lab configs; the per-probe verdicts stay the PDF's own.
- **Severity per finding:** introspection exposed (anonymous) =
  Critical; introspection bypass = High; no depth limit = High; batching
  enabled = High; alias/directive overload = High/Medium; field
  returning data without a token = High; mutation without auth =
  Critical; IDOR = Critical; schema recoverable via guessing = High;
  expensive query = Medium; no rate limiting observed = Low note.

## 9. Lab API — a stdlib-only GraphQL server in the repo

- `lab_api.py`: a small GraphQL server on stdlib `http.server` only
  (no Flask, no strawberry — nothing to install), with a hand-written
  mini GraphQL executor: fields, arguments (`id: "1"`, `search: "x"`),
  nested selection sets, named + inline fragments, aliases, variables,
  directives `@skip` / `@include`, `__schema` / `__type` introspection,
  `__typename`. (Writing the executor is the fixture-generator work,
  like the AXML writer for APKSeeker and the PE writer for
  CanarySeeker.)
- Schema (two object types minimum per the PDF — build more, the
  probes need them): `User { id name email role friends }` (friends
  is circular — User → friends → User — for the depth probe),
  `Post { id title author }`, `Query { me user(id:) users post(id:)
  posts search(q:) admin }`, `Mutation { updateProfile(input:) ping }`.
  Two users in memory (user 1 "alice", user 2 "bob", distinct data for
  the IDOR probe); `admin` and `me` need a token; `user`/`posts` are
  public in the vulnerable config.
- Two configurations (the "prove it twice" design): **vulnerable**
  (introspection on, no depth limit, batching on, suggestions on, no
  rate limit, `admin`/`me` answer without a token, IDOR open) and
  **hardened** (introspection off, depth limit 5, batching off,
  suggestions off, rate limit 10/min, auth enforced, IDOR closed).
  A third **partial** config (introspection off BUT suggestions on)
  proves the suggestion-mining probe. The server takes `--config
  vulnerable|hardened|partial --port N` and prints its toggles on
  start. `run.py lab` starts it; the tests start it on a random free
  port per run and shut it down afterwards.
- The lab server is the ONLY target the tests ever touch. The tool
  itself accepts any URL the user gives (like SSTIProbe accepts any
  own-website URL) but the banner says AUTHORIZED USE ONLY and the
  docs say lab-only — never probe a real API without written
  permission (PECA 2016).

## 10. Interface (same family as the other six tools)

- TraceRecon colour class + clear/sep/header/ok/warn/err/info helpers,
  LEGAL DISCLAIMER + box in the banner, Gobuster-style SCAN config block,
  numbered menu with `[?] Select option:` prompt, `--batch`, `-q`, `--version`,
  `--no-color`, `-i/--interactive/--menu`.
- CLI: `gqlprobe.py <url> [--token TOKEN] [--header "K: V"] [-o/--output
  report] [--json] [--schema-out schema.json] [--snapshot] [--diff FILE]
  [--wordlist FILE] [--mutation NAME] [--max-depth N] [--max-batch N]
  [--max-alias N] [--timeout N] [--min-severity {critical,high,medium,low}]
  [--fail-on {critical,high,medium,low,none}] [--probe NAME]
  [--skip-probe NAME] [--list-probes] [--list-fields] [-q/--quiet]
  [--batch] [-i/--interactive/--menu] [--version] [--no-color]`.
  Exit codes: 0 = no findings above the threshold; 1 = findings; 2 =
  usage / unreachable endpoint / invalid response.
- Menu: [1] Probe an endpoint [2] Quick probe vulnerable lab [3] Quick
  probe hardened lab [4] Quick probe partial lab (suggestions on)
  [5] List all probes [6] Show schema fields [7] Run step tests
  [8] Check setup (doctor — python, requests, lab server) [9] Start lab
  server [0] Exit. Print the SCAN config block before each probe run.
- `run.py` launcher (venv auto-create + install; commands: setup, probe,
  test, doctor, lab (start the lab server), menu) + `run.bat` (Windows —
  must actually run the tool) + `run.sh`. requirements.txt: `requests`
  (optional — the tool falls back to urllib).
- Author "CyberBoy50" ONLY everywhere in the tool and docs — no real names
  anywhere (student Ibrar Ahmed and instructor Abdul Mannan go only in
  the REPORT document).
- Finding codes (family pattern): GQ-001 introspection exposed, GQ-002
  introspection bypass, GQ-003 no depth limit, GQ-004 batching enabled,
  GQ-005 alias overloading, GQ-006 field duplication, GQ-007 directive
  overloading, GQ-008 field returns data without auth, GQ-009 IDOR,
  GQ-010 schema recoverable via guessing/suggestions, GQ-011 mutation
  without auth, GQ-012 expensive query / timing, GQ-013 sensitive field
  exposed, GQ-014 GET-based queries (CSRF angle), GQ-015 argument
  injection error leak, GQ-016 no rate limiting observed (Low note).
