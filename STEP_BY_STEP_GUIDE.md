# GQLProbe — Step-by-Step Guide

Build the tool one step at a time, exactly as the PDF's build plan
says. Test each step before moving on — a step you have not tested
is a step you have not finished. Every step below has the command
and the expected result.

Prerequisites: Python 3.10+. Nothing else — the probe uses
`requests` when it is there and falls back to `urllib` (standard
library) when it is not. The lab server is standard library only.

```bash
git clone https://github.com/CyberBoy50/GQLProbe.git
cd GQLProbe
python run.py setup        # first time only (venv + requests)
python run.py lab vulnerable   # terminal 1: the lab on port 4000
```

The lab URL in every step below is
`http://127.0.0.1:4000/graphql`, the token is `lab-token-alice`.

## Step 1 — Send one query

**Write:** an HTTP client (`requests` preferred, `urllib`
fallback) that POSTs one GraphQL query as JSON and returns the
parsed response. The token goes in an `Authorization: Bearer`
header and is never printed.

```bash
python3 -c "
import gqlprobe
status, _hd, body, _el, _raw = gqlprobe.gql_post(
    'http://127.0.0.1:4000/graphql', '{ __typename }',
    None, 'lab-token-alice', {}, 10)
print(status, body)
"
```

Expected:

```
200 {'data': {'__typename': 'Query'}}
```

Then the same query with variables and a fragment, and one bad
field — the lab answers partial data + an errors array, which is
real GraphQL behaviour and which the probes rely on:

```bash
python3 test_gqlprobe.py   # Step 1 checks run here too
```

Expected: the Step 1 checks pass (`data is exactly
{__typename: Query}`, variables + fragments return Alice, an
unknown field gives partial data + errors).

## Step 2 — Introspection: vulnerable vs hardened vs partial

**Write:** send the standard introspection query with a token AND
without one; parse whether the full schema came back. Then the
bypass set: `__type`, GET-based introspection, the newline trick,
the fragment trick.

```bash
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# vulnerable lab: introspection EXPOSED (anonymous), GQ-001 Critical

python run.py lab hardened
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# hardened lab: introspection DISABLED, bypass BLOCKED

python run.py lab partial
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# partial lab: introspection DISABLED, bypass BYPASSED (3 x GQ-002),
# guessing RECOVERABLE — the guard has holes
```

Expected: vulnerable returns the schema (10 types) with no token;
hardened refuses it both ways; partial refuses the plain query
but answers `__type`, GET and the newline variant.

## Step 3 — Parse the schema

**Write:** `parse_schema()` — unwrap NON_NULL / LIST types, read
query/mutation/subscription fields with their argument names,
object types, input types, enums and directives; flag sensitive
fields (password/secret/token/key/ssn/creditCard/internal/admin)
and role-changing mutations (role/permission/admin/delete/grant).

```bash
python3 -c "
import gqlprobe
proc, url = gqlprobe.start_lab('vulnerable')
s = gqlprobe.Scan(url, token='lab-token-alice').run()
print(sorted(s.schema['query_fields']))
print(sorted(s.schema['mutation_fields']))
print(s.schema['types']['User']['fields']['friends'])
print(s.schema['sensitive_fields'])
print(s.schema['role_mutations'])
gqlprobe.stop_lab(proc)
"
```

Expected:

```
['admin', 'me', 'post', 'posts', 'search', 'user', 'users']
['grantAdmin', 'ping', 'updateProfile']
{'args': {}, 'type': 'User'}
[{'type': 'Query', 'field': 'admin'}, {'type': 'Mutation', 'field': 'grantAdmin'}, {'type': 'User', 'field': 'passwordHash'}]
['grantAdmin']
```

## Step 4 — Depth probe

**Write:** `find_cycle()` (a circular relation, preferring a root
that takes an id) + `build_depth_query()` + the ladder 1, 2, 3, 5,
8, 10, 15, 20, 30, 50. When introspection is off, the probe tries
the common nested shapes (`user -> friends`, `me -> friends`,
`post -> author -> friends`) instead of skipping.

```bash
python run.py lab hardened
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# depth LIMITED (max depth 5) — "Refused past depth 5: Query depth 8
# exceeds maximum 5"

python run.py lab vulnerable
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# depth NO LIMIT — "Answered up to depth 50 (max tried); no refusal",
# GQ-003 High, cost ~2601
```

Expected: the two reports differ — hardened finds the limit at
5, vulnerable answers past 20.

## Step 5 — Batching + authorization

**Write:** the batching probe (arrays of 10, 50, 100 identical
queries, count the response objects) and the authz probe (replay
the data query with no token, compare field by field, plus the
field-level auth map for every query field).

```bash
python run.py lab vulnerable
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# batching ENABLED — "One request executed 100 queries", GQ-004
# authz LEAKING (me, admin, user, users) — 4 x GQ-008
# field map: every field "answers (data)"

python run.py lab hardened
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# batching DISABLED, authz ENFORCED
# field map: admin/me/user/users "refused (auth)",
# posts/search "answers (data)" (public by design)
```

Expected: the batch count matches what the lab executed (100 on
vulnerable, 0 on hardened) and the unauthenticated replay matches
the manual observation.

## Step 6 — CLI + report

**Write:** the CLI (all flags in `gqlprobe.py --help`), the text
and JSON report builders, the exit codes (0 clean, 1 findings,
2 error). Run twice with different tokens; both reports complete.

```bash
python run.py lab vulnerable
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice \
  -o report_alice.txt --no-color
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-bob \
  -o report_bob.txt --no-color
```

Expected: both exit 1, both reports complete (Findings + Probes
+ Schema + Timing), neither prints a token (the header says
`provided (15 chars, masked)`), and the two differ — the IDOR
evidence names user 1 as the caller in one and user 2 in the
other.

## Step 7 — End-to-end, both labs

**Write:** `run()` — all 16 probes in workflow order (timing
last, because its rate-limit check trips the flood guard), then
the report. Read both saved reports start to finish: every probe
has a verdict and evidence.

```bash
python run.py lab vulnerable
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice \
  -o report_vulnerable.txt --json
python run.py lab hardened
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice \
  -o report_hardened.txt --json
```

Expected: vulnerable 0/100 F, 16 findings; hardened 90/100 A, 1
finding (GQ-014, GET). The JSON reports have all 16 probes, the
finding counts add up, and no token appears anywhere.

## Step 8 — Stretch + extras

**Write:** field guessing (wordlist + suggestion mining), the
harmless mutation probe (allow-list only), the timing table +
rate-limit detection, alias / duplication / directive probes, the
IDOR probe (own id via `me`, then other users' objects), engine
fingerprinting, the GET probe, the argument-injection probe, the
sensitive-field probe, schema snapshot + diff, score + grade.

```bash
python run.py lab partial
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# guessing RECOVERABLE (GQ-010) — suggestions on, schema rebuilt
# from "Did you mean …?" alone

python run.py lab hardened
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# guessing NOT RECOVERABLE, mutation AUTH ENFORCED, IDOR CLOSED,
# alias/duplication/directive LIMITED, timing RATE LIMIT PRESENT
# (first 429 at request 11/20)

# Snapshot + diff (needs a readable schema — vulnerable lab):
python run.py lab vulnerable
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice \
  --snapshot schema.json --no-color
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice \
  --diff schema.json --no-color
# Expect: "No schema changes."
```

Expected: guessing recovers fields on partial and nothing extra
on hardened; the harmless mutation executes with a token and (on
vulnerable) without one; the timing table has sane numbers;
alias/directive/duplication fire on vulnerable only; IDOR fires
on vulnerable only; fingerprinting names a family or says
unknown honestly; snapshot + diff detects a changed field list.

## Run all the checks

```bash
python run.py test
# GQLProbe step tests: 173/173 checks passed
```
