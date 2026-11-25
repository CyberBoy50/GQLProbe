# GQLProbe — Demo

Real runs against the lab API (`lab_api.py`, stdlib only), 25
November 2026. The same command, the same token, three configs —
vulnerable, hardened, partial. The full reports are in the repo:
`sample_report_vulnerable.txt` / `.json` and
`sample_report_hardened.txt` / `.json`.

```bash
python run.py lab vulnerable     # terminal 1
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
```

## 1. The vulnerable lab — 0/100, grade F

```
 RESULTS — score 0/100 (grade F)
──────────────────────────────────────────────────────────
 [!] introspection  EXPOSED (anonymous)
 [?] bypass         NOT NEEDED
 [!] depth          NO LIMIT
 [!] batching       ENABLED
 [!] alias          NO LIMIT
 [!] duplication    NO LIMIT
 [!] directive      NO LIMIT
 [!] authz          LEAKING (me, admin, user, users)
 [!] idor           LEAKING
 [?] guessing       NOT NEEDED
 [!] mutation       EXECUTES WITHOUT AUTH
 [?] timing         NO RATE LIMIT OBSERVED
 [?] fingerprint    Apollo-like (field-suggestion error shape) — lab build
 [!] get            WORKS
 [+] injection      CLEAN
 [!] sensitive      EXPOSED

 Findings: 16 (4 critical, 8 high, 3 medium, 1 low)
```

Sixteen findings, four of them Critical. The worst three, in
plain words:

- **GQ-001 — introspection exposed.** The full schema (10 types)
  comes back with NO token. Anyone on the internet can read the
  whole API: every field, every argument, every mutation.
- **GQ-009 — IDOR.** Alice's token fetched user 2 (Bob) and user 3
  (Carol) — the resolver never checks that the token's user id
  matches the requested id.
- **GQ-011 — mutation without auth.** `ping` AND `updateProfile`
  both execute with no token at all. Mutations change state;
  queries only read it.

Exit code 1.

## 2. The hardened lab — 90/100, grade A

The same command against the hardened config:

```
 RESULTS — score 90/100 (grade A)
──────────────────────────────────────────────────────────
 [+] introspection  DISABLED
 [+] bypass         BLOCKED
 [+] depth          LIMITED (max depth 5)
 [+] batching       DISABLED
 [+] alias          LIMITED
 [+] duplication    LIMITED
 [+] directive      LIMITED
 [+] authz          ENFORCED
 [+] idor           CLOSED
 [+] guessing       NOT RECOVERABLE
 [+] mutation       AUTH ENFORCED
 [+] timing         RATE LIMIT PRESENT
 [?] fingerprint    Apollo-like (error shape) — lab build
 [!] get            WORKS
 [+] injection      CLEAN
 [+] sensitive      CLEAN (NO SCHEMA)

 Findings: 1 (0 critical, 0 high, 1 medium, 0 low)
  [MEDIUM] [GQ-014] GET-based queries (CSRF angle)
```

Exit code 1 (one finding is still a finding). The single gap is
honest, not a miss: plain queries run over GET on this lab, which
is normal for GraphQL servers (Apollo, graphql-yoga) — it only
becomes a CSRF vector if the API ever switches to cookie auth. The
fix is in the report: accept GraphQL only over POST with a JSON
body, or require a CSRF token / custom header on GET.

## 3. The partial lab — 30/100, grade F

Partial is hardened with two deliberate weaknesses: suggestions
left on, and a naive introspection guard (it only looks for
`__schema {` with a literal space, only on POST, and never looks
at `__type`).

```
 RESULTS — score 30/100 (grade F)
──────────────────────────────────────────────────────────
 [+] introspection  DISABLED
 [!] bypass         BYPASSED
 [+] depth          LIMITED (max depth 5)
 [+] batching       DISABLED
 [+] alias          LIMITED
 [+] duplication    LIMITED
 [+] directive      LIMITED
 [+] authz          ENFORCED
 [+] idor           CLOSED
 [!] guessing       RECOVERABLE
 [+] mutation       AUTH ENFORCED
 [+] timing         RATE LIMIT PRESENT
 [!] get            WORKS
 [+] injection      CLEAN
 [+] sensitive      CLEAN (NO SCHEMA)

 Findings: 5 (0 critical, 4 high, 1 medium, 0 low)
  [HIGH] [GQ-002] Introspection bypass — __type
  [HIGH] [GQ-002] Introspection bypass — GET
  [HIGH] [GQ-002] Introspection bypass — newline
  [HIGH] [GQ-010] Schema recoverable via guessing/suggestions
  [MEDIUM] [GQ-014] GET-based queries (CSRF angle)
```

This is the lab that proves the bypass and guessing probes: the
front door (introspection) is locked, but the schema still leaks
through three side doors — and the server even volunteers field
names when you typo one ("Did you mean 'user'?").

## One finding, explained: introspection + depth limits

The PDF's defensive lesson is about the two cheapest, highest-
value fixes in GraphQL security: **disable introspection** and
**enforce a depth limit** in production. Here is what they are,
why they matter, and how to set them.

### Introspection

Introspection is the `__schema` / `__type` query that returns the
whole schema — every type, every field, every argument. It exists
so tools like GraphiQL and code generators can discover the API
while you develop it. In production it is a free map of the
attack surface: an attacker who reads the schema knows exactly
which fields exist, which ones take ids (IDOR targets), which
mutations change state, and which fields are sensitive
(`passwordHash`, `admin`, `grantAdmin`).

GQLProbe's vulnerable lab returns the full schema with no token
(GQ-001, Critical). The hardened lab refuses it with and without
a token, and the bypass probe confirms the refusal is real — it
tries `__type`, GET-based introspection, the newline trick and the
fragment trick, and all four are refused.

How to set it (Apollo Server):

```js
// Apollo Server 4: introspection is off in production by default.
// Be explicit anyway, and hide the schema from error messages too.
new ApolloServer({
  typeDefs, resolvers,
  introspection: false,
  includeStacktraceInErrorResponses: false,
});
```

The second line matters as much as the first: the partial lab
shows why. Its introspection is "off", but error messages still
suggest field names — and the suggestion-mining probe rebuilds
the schema from those suggestions alone (GQ-010). Turn the
suggestions off with the introspection, or the lock is only
half closed. In graphql-js that is `hideSchemaDetailsFromClientErrors`
(or the equivalent `NoSchemaIntrospectionCustomRule` + a
validation rule that strips suggestions).

### Depth limits

A GraphQL query is a tree, and a tree can nest forever. The lab
schema is circular on purpose — `User.friends` points back at
`User` — so one query can ask for a user, their friends, their
friends' friends, fifty levels deep:

```graphql
{ user(id: "1") { friends { friends { friends { … { id } } } } } }
```

On the vulnerable lab that query answers at depth 50 (cost
~2601 by GQLProbe's estimate: fields × (depth+1) + aliases) and
never refuses — GQ-003, High. Each level multiplies the resolver
work: one user becomes their friends, each friend becomes their
friends, and the database does the same query again at every
level. That is a denial-of-service shape, not a bug in one
resolver — the engine itself must stop it.

The hardened lab answers up to depth 5 and refuses depth 6 with
`Query depth 6 exceeds maximum 5`. GQLProbe's depth probe finds
that limit by climbing the ladder 1, 2, 3, 5, 8, 10 … and
recording the deepest depth answered.

How to set it (Apollo Server + graphql-validation-complexity,
or graphql-depth-limit):

```js
import depthLimit from 'graphql-depth-limit';
new ApolloServer({
  typeDefs, resolvers,
  validationRules: [depthLimit(5)],
});
```

Five is the lab's number; ten is a common production number.
Pick one, enforce it before the query reaches the engine (a
validation rule, not a resolver check), and add a complexity
budget on top when the API grows — depth alone does not stop a
wide query (101 aliases, 50 duplicate fields), which is why
GQLProbe also probes alias, duplication and directive limits.

## The field-level auth map

The authz probe does not stop at "something leaks". It replays
every query field without a token and prints the map — the
hardened lab's map, from the sample report:

```
Field-level auth map (unauthenticated)
  admin          refused (auth)
  me             refused (auth)
  posts          answers (data)
  search         answers (data)
  user           refused (auth)
  users          refused (auth)
```

`posts` and `search` answer without a token on purpose — they are
public fields. `me`, `admin`, `user`, `users` refuse. That is the
map a reviewer wants: which fields are public by design, and
which ones are gated. On the vulnerable lab every field answers.

## Try it yourself

```bash
python run.py lab partial
python run.py probe http://127.0.0.1:4000/graphql --token lab-token-alice
# Expect: 30/100 F, 5 findings — 3 bypasses + guessing + GET.

# Schema snapshot + diff needs a readable schema, so use the
# vulnerable lab for it:
python run.py lab vulnerable
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice \
  --snapshot schema.json
# Then probe again later and compare:
python3 gqlprobe.py http://127.0.0.1:4000/graphql --token lab-token-alice \
  --diff schema.json
# Expect: "No schema changes." (or the added/removed/changed fields)
```
