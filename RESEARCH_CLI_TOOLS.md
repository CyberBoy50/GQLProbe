# GQLProbe — Research: Similar Tools on the Internet / GitHub

Researched Wed 2026-11-25 (late night), before building. Sources are the web
searches run that day; claims below come only from those results and the
tools' own pages.

## Name check (GitHub, search_repositories, `in:name`)

The PDF's name **GraphProbe is TAKEN** (same name, same domain):
- `bovinemagnet/graphprobe` — "GraphQL Integration Testing Framework".
  (The other hits, `simachewalamneh/graphprobe` and `KILab-Lyu/GraphProbe`,
  are graph-neural-network projects — different domain.)
- GraphLens is taken (48 — incl. an Angular architecture visualizer and a
  code-analysis framework); GraphSeeker is taken (2 — an AI research-agent
  SDK and a graph retrieval system); QueryLens is taken (199 — SQL/EF
  tools); GraphScope is taken (43 — Alibaba's large-scale graph computing
  system); SchemaProbe is taken (2); GQLens is taken (7 — a GraphQL
  performance platform and a Chrome extension).

**FREE (0 results): GQLProbe, GQLLens, GQLSeeker, QueryProbe, GraphQLProbe.**

## 1. graphql-cop (dolevf/graphql-cop) — the CLI checklist

- A command-line tool to check a GraphQL API for common security
  vulnerabilities. Its DoS test suite targets five vectors, all rated
  HIGH: alias overloading (101 aliases of the same field, success = the
  100th alias's data comes back), array-based query batching (success =
  10+ response objects in one request), directive overloading (10 `@aa`
  directives on one field — the error array itself proves the engine
  processed them), field duplication (the same field repeated in one
  selection set), and introspection-based circular queries (the recursive
  `__schema` types used to build a query that never ends).
- Also covers CSRF (GET-based query execution) and the query-depth attack
  (a query that snowballs as it gets deeper; the fix is a depth limit
  checked before the engine runs).
- Limits: a checklist runner, not a full tester — it runs its own canned
  attacks and reports pass/fail; no schema parsing into a field list, no
  field-level authorization map, no field guessing, no mutation testing,
  no timing comparison, no report file with evidence per probe.
- What GQLProbe takes from it: the five DoS probes with their exact
  detection rules (101 aliases, 10+ batch responses, 10 directives) and
  the severity (HIGH). What GQLProbe does differently: the full
  PDF probe set around those DoS checks (introspection, schema parse,
  depth, batching, authz) plus the stretch items and a saved report.

## 2. Clairvoyance (Nikita Stupin) — schema recovery without introspection

- Recovers a GraphQL schema when introspection is disabled, by brute-force
  field discovery: it sends queries built from a wordlist of common field
  names and parses the server's **field-suggestion error messages**
  ("Cannot query field 'usr' … Did you mean 'user'?") to piece the schema
  back together. The Escape Technologies wordlist covers 50,000 common
  field names; the high-frequency-vocabulary list (30k.txt) is the usual
  starting point. Usage: `python3 -m clairvoyance <url> -w <wordlist>
  -o schema.json`.
- Why it works: disabling introspection is necessary but not sufficient —
  Apollo's suggestion mechanism leaks valid field names through errors,
  and the edit-distance algorithm decides which suggestions are offered.
  Apollo Server v4 added `hideSchemaDetailsFromClientErrors` to suppress
  them. Real bypasses it relies on: `__type` queries when `__schema` is
  blocked, GET-based introspection when only POST is blocked, and the
  OpenCTI CVE-2024-37155 case where a regex filter on `__schema` failed
  on queries missing `\r\n` characters (CVSS 6.5).
- Limits: one job only — schema recovery. No depth, batching, authz,
  mutation or timing probes; needs a big external wordlist.
- What GQLProbe takes from it: the suggestion-mining technique and the
  introspection-bypass list (`__type`, GET, whitespace tricks). What
  GQLProbe does differently: suggestion mining built into the field-
  guessing probe with a curated in-repo wordlist, as one probe among
  many — plus the verdict that "introspection off but suggestions on"
  is still a leak.

## 3. graphw00f (Dolev Farhi) — engine fingerprinting

- Fingerprints the GraphQL engine (35+ engines) by sending a mix of
  benign and malformed queries and matching the error shapes: different
  engines (Apollo, Hasura, graphene, Strawberry, gqlgen, AWS AppSync…)
  have different error formats, directive names and behaviours — and
  different known CVEs. `pip install graphw00f`.
- Limits: fingerprinting only — it identifies the engine, it does not
  test the API's own configuration.
- What GQLProbe takes from it: the fingerprinting idea (error shapes +
  response headers + `__typename` behaviour) as one extra probe, so the
  report can say which engine family the lab API behaves like and which
  engine-specific checks apply.

## 4. InQL (Doyensec) — Burp extension + CLI

- Burp Suite extension (and CLI `inql`) for GraphQL: runs introspection,
  generates query/mutation templates from the discovered schema, and
  supports IDOR testing. The Burp GUI version has no CLI equivalent for
  its interactive parts; the CLI can generate queries and TSV output
  from a schema file.
- Limits: a Burp extension first — it needs Burp Suite Professional for
  the full flow; it generates queries, it does not run the PDF's probe
  set or write a findings report.
- What GQLProbe takes from it: the template-generation idea (build
  queries from the schema automatically) and the IDOR angle. What
  GQLProbe does differently: a standalone CLI that runs the probes
  itself, no Burp needed.

## 5. gqlmap / batchql — injection and batching specialists

- gqlmap: SQL/NoSQL injection scanning through GraphQL arguments.
- batchql: batching attacks (array batching as a brute-force amplifier —
  100 login mutations per HTTP request to bypass per-IP lockout, OTP
  brute-force via alias batching).
- Limits: each does one attack class. Neither is a general tester.
- What GQLProbe takes from them: the batching-as-amplifier framing
  (batching is not just a DoS vector, it is a rate-limit bypass) and the
  argument-injection angle as an extra probe (safe payloads only — a
  quote in a string argument, watching for a database error in the
  response; the lab API must answer with a clean error, never with data).

## 6. Pentestas GraphQL Scanner (hosted) + graphql-audit skill

- Pentestas: a hosted scanner — introspection detection, query depth and
  complexity limits, field-level authorization, aliasing/batching abuse;
  GET and POST; PDF/CSV/JSON export. A one-off scan catches a moment in
  time; the platform runs continuously.
- graphql-audit (bounty-harness skill): the full manual workflow in one
  checklist — introspection → field-suggestions → batching-dos →
  idor-aliasing → injection, with graphw00f, clairvoyance, graphql-cop,
  inql and gqlmap as the tools. Its quick-kill list is the best short
  summary of the field: introspection on? suggestions leak? batch 100
  queries? alias bomb 1000? IDOR by ID? field auth on privileged fields?
  injection via arguments? introspection bypass (`__schema` newline,
  GET, fragments)? mutation rate limiting?
- Limits: the first is a hosted service (account + trial); the second is
  a checklist that shells out to five separate tools.
- What GQLProbe takes from them: the workflow order (introspection
  first, then suggestions, then batching/aliasing, then authz, then
  injection) and the quick-kill checklist as the probe list. What
  GQLProbe does differently: all of it in one small Python CLI with
  one report.

## 7. GraphQL Security Tester (ArmGit / CarterPerez-dev) — the student-shaped one

- A Python project that builds an intentionally vulnerable GraphQL
  server (strawberry-graphql + FastAPI) for a multi-tenant app, then a
  tester for it: introspection exposure, query depth and complexity
  attacks, authorization bypass, field suggestion abuse, batching
  attacks, mutation injection. The schema analyzer flags sensitive
  fields (password, secret, token, key), role-changing mutations and
  internal identifiers, and generates a DOT schema map (Graphviz) and a
  structured JSON report.
- Limits: a learning project built on strawberry + FastAPI (heavy deps);
  the tester is tied to its own server.
- What GQLProbe takes from it: the vulnerable-server-plus-tester
  shape (the lab API is part of the repo, not an afterthought) and the
  sensitive-field flagging. What GQLProbe does differently: the lab
  server is stdlib-only (no FastAPI/strawberry to install), and the
  tester works against any lab endpoint, not just its own server.

## Comparison table

| Tool | Introspection | Schema parse | Depth | Batching | Alias bomb | Directive overload | Field guessing/suggestions | Authz / IDOR | Mutation | Timing | Fingerprint | Report | Zero-dep CLI |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| graphql-cop | no | no | yes | yes | yes | yes | no | no | no | no | no | checklist | no (pip) |
| Clairvoyance | bypasses | recovery | no | no | no | no | yes | no | no | no | no | schema JSON | no (wordlist) |
| graphw00f | no | no | no | no | no | no | no | no | no | no | yes | yes | no (pip) |
| InQL | yes | yes | no | no | no | no | no | yes (IDOR) | templates | no | yes | no | no (Burp) |
| gqlmap / batchql | no | no | no | yes | no | no | no | no | no | no | no | no | no |
| Pentestas (hosted) | yes | yes | yes | yes | yes | no | no | yes | no | no | no | yes | no (account) |
| GraphQL Security Tester | yes | yes | yes | yes | no | no | yes | yes | yes | no | no | yes (JSON) | no (FastAPI) |
| **GQLProbe (planned)** | **yes + bypasses** | **yes** | **yes** | **yes** | **yes** | **yes** | **yes + suggestions** | **yes + IDOR** | **yes** | **yes** | **yes** | **yes (text+JSON)** | **yes** |

## What GQLProbe adds over everything found

1. **Every probe in one small CLI, zero dependencies** — the full
   graphql-cop DoS set + Clairvoyance's suggestion mining + graphw00f's
   fingerprinting + InQL's IDOR angle + the PDF's own five probes, in
   one Python tool with `requests` preferred and a urllib fallback
   (the PDF's Step 1 names requests; the tool works without it).
2. **All three stretch items in v1.0** — field guessing (wordlist +
   suggestion mining), mutation testing (harmless lab mutation, with
   and without a token), timing comparison (per-probe timings, expensive-
   query timing, rate-limit detection).
3. **Beyond-PDF extras that make it the best of the seven tools:**
   introspection bypasses (`__type`, GET, whitespace/newline tricks,
   fragment tricks); alias overloading, field duplication and directive
   overloading probes (graphql-cop parity); engine fingerprinting;
   BOLA/IDOR probe (another user's object by ID, with a lab token);
   sensitive-field flagging from the schema (password/secret/token/key
   + role-changing mutations); query complexity/cost estimation;
   GET-support check (the CSRF angle); schema snapshot + `--diff`
   against a previous run; argument-injection probe (safe payloads
   only, lab-only); per-finding severity + a hardening score + grade;
   and a lab API with TWO configurations (vulnerable and hardened)
   so every probe is proven twice — once where it fires, once where
   it does not.
4. **A stdlib-only lab GraphQL server in the repo** — a hand-written
   mini GraphQL executor (fields, arguments, nested selections,
   fragments, aliases, variables, @skip/@include, introspection) with
   toggles for every protection, so the whole test matrix runs with
   no install step at all.
5. **Menu + full CLI + text/JSON reports** — same interface family as
   SSTIProbe / RBACLens / PipeSentry / MemSeeker / APKSeeker /
   CanarySeeker.
6. **Cross-platform** — pure Python, runs on Windows, macOS and Linux
   (per the user's standing rule); the lab server runs anywhere Python
   runs.
