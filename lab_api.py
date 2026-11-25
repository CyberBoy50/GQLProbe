#!/usr/bin/env python3
"""
GQLProbe lab GraphQL API — a small GraphQL server on the Python
standard library only, with a hand-written mini GraphQL executor.

WHAT IT IS
  A deliberately insecure / hardened-by-config GraphQL API that the
  GQLProbe tester probes. It implements enough of GraphQL to make the
  probes meaningful: fields, arguments, nested selection sets, named
  and inline fragments, aliases, variables, @skip/@include, and
  __schema/__type introspection. No Flask, no strawberry, nothing to
  install — plain `python3 lab_api.py` runs it.

THE SCHEMA (two object types minimum per the PDF — built more, the
probes need them):
  User { id name email role bio passwordHash friends }
  Post { id title body author }
  Query { me user(id:) users post(id:) posts search(q:) admin }
  Mutation { ping updateProfile(input:) grantAdmin(userId:) }

  friends is circular (User -> friends -> User) so the depth probe
  has a real cycle to climb. passwordHash and admin are the sensitive
  fields the schema probe flags; grantAdmin is the role-changing
  mutation the schema probe flags (GQLProbe never calls it — it is
  not on the mutation allow-list).

THREE CONFIGURATIONS (the "prove it twice" design):
  vulnerable — introspection on, no depth limit, batching on,
    suggestions on, no rate limit, no auth on me/admin/user/users,
    IDOR open (any user can fetch any user), mutations run without
    a token.
  hardened  — introspection off, depth limit 5, batching off,
    suggestions off, rate limit on (flood guard: >10 identical
    requests in 10s -> 429), auth enforced (me needs a token, admin
    needs the admin role, user(id:) is owner-or-admin only, users
    needs admin), IDOR closed, mutations need a token.
  partial   — like hardened, BUT suggestions on and the introspection
    guard has the classic holes: __type is not blocked, GET
    introspection is not blocked, and the guard regex only matches
    "__schema {" with a literal space — a newline after __schema
    slips past it (the CVE-2024-37155 shape). This config proves the
    suggestion-mining and bypass probes.

USAGE
  python3 lab_api.py --config vulnerable --port 4000
  python3 lab_api.py --config hardened   --port 4001
  python3 lab_api.py --config partial    --port 4002
  python run.py lab [vulnerable|hardened|partial]

LAB ONLY — this server is a test fixture on your own machine. It
holds fake users with fake data. Never point it at real data, and
never expose it to a network you do not control.
"""

import argparse
import difflib
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.0"
AUTHOR = "CyberBoy50"

# ---------------------------------------------------------------------------
# The data — fake users and posts, in memory only.
# ---------------------------------------------------------------------------
USERS = {
    "1": {"id": "1", "name": "Alice", "email": "alice@lab.local",
          "role": "user", "bio": "Alice's lab bio",
          "passwordHash": "pbkdf2-sha256:1000:lab-fake-hash-alice",
          "friends": ["2"]},
    "2": {"id": "2", "name": "Bob", "email": "bob@lab.local",
          "role": "user", "bio": "Bob's lab bio",
          "passwordHash": "pbkdf2-sha256:1000:lab-fake-hash-bob",
          "friends": ["1"]},
    "3": {"id": "3", "name": "Carol", "email": "carol@lab.local",
          "role": "admin", "bio": "Carol (lab admin)",
          "passwordHash": "pbkdf2-sha256:1000:lab-fake-hash-carol",
          "friends": ["1", "2"]},
}
POSTS = {
    "1": {"id": "1", "title": "Hello Lab", "body": "First lab post.",
          "author": "1"},
    "2": {"id": "2", "title": "GraphQL Notes",
          "body": "Notes about queries.", "author": "2"},
    "3": {"id": "3", "title": "Lab Secrets", "body": "Admin post.",
          "author": "3"},
}
# Lab tokens: header "Authorization: Bearer <token>".
TOKENS = {"lab-token-alice": "1", "lab-token-bob": "2",
          "lab-token-admin": "3"}
ADMIN_SECRET = "ADMIN-SECRET-LAB-ONLY"

# ---------------------------------------------------------------------------
# Configurations.
# ---------------------------------------------------------------------------
CONFIGS = {
    "vulnerable": {
        "introspection": True, "depth_limit": None, "batching": True,
        "suggestions": True, "rate_limit": False, "auth_enforced": False,
        "idor_open": True, "get_introspection": True,
        "type_bypass": True, "newline_bypass": True,
        "max_aliases": None, "max_duplicates": None,
        "max_directives": None,
    },
    "hardened": {
        "introspection": False, "depth_limit": 5, "batching": False,
        "suggestions": False, "rate_limit": True, "auth_enforced": True,
        "idor_open": False, "get_introspection": False,
        "type_bypass": False, "newline_bypass": False,
        "max_aliases": 10, "max_duplicates": 2, "max_directives": 2,
    },
    "partial": {
        "introspection": False, "depth_limit": 5, "batching": False,
        "suggestions": True, "rate_limit": True, "auth_enforced": True,
        "idor_open": False, "get_introspection": True,
        "type_bypass": True, "newline_bypass": True,
        # Same abuse limits as hardened — partial is only weak on
        # introspection (suggestions + the naive guard), not on
        # query-shape abuse.
        "max_aliases": 10, "max_duplicates": 2, "max_directives": 2,
    },
}
# Rate-limit flood guard: more than this many IDENTICAL queries inside
# the window -> 429. Identical-query counting (not total counting) so
# normal probe traffic — every query different — never trips it. The
# window is SHORT (2s) on purpose: the timing probe's deliberate
# flood is 20 identical queries back-to-back, inside one second, so
# it still trips the guard — but a normal scan, which sends the same
# cheap query a handful of times spread over seconds (and a second
# scan a few seconds later), must not. A 10s window tripped on
# repeat scans and made the GET probe misread a 429 as "blocked".
RATE_LIMIT_COUNT = 10
RATE_LIMIT_WINDOW = 2.0
# Safety cap on query depth so a hostile query cannot recurse forever.
# The depth probe goes to 50; the cap is above that.
MAX_DEPTH_CAP = 60

# ---------------------------------------------------------------------------
# The schema, as data — the introspection builder reads this.
# type_ref(kind, name, ofType) mirrors the introspection JSON shape.
# ---------------------------------------------------------------------------


def _ref(kind, name=None, of_type=None):
    out = {"kind": kind, "name": name, "ofType": of_type}
    return out


def _nn(inner):
    return _ref("NON_NULL", None, inner)


def _lst(inner):
    return _ref("LIST", None, inner)


def _named(kind, name):
    return _ref(kind, name, None)


def _arg(name, type_ref):
    return {"name": name, "description": None, "type": type_ref,
            "defaultValue": None}


def _field(name, type_ref, args=None, description=None):
    return {"name": name, "description": description, "args": args or [],
            "type": type_ref, "isDeprecated": False,
            "deprecationReason": None}


SCALARS = ["String", "Int", "Float", "Boolean", "ID"]

# Query / Mutation / User / Post field tables (name -> (type, args)).
QUERY_FIELDS = {
    "me": ("User", []),
    "user": ("User", [("id", "ID!")]),
    "users": ("[User]", []),
    "post": ("Post", [("id", "ID!")]),
    "posts": ("[Post]", []),
    "search": ("[Post]", [("q", "String")]),
    "admin": ("String", []),
}
MUTATION_FIELDS = {
    "ping": ("String", []),
    "updateProfile": ("User", [("input", "UpdateProfileInput")]),
    "grantAdmin": ("User", [("userId", "ID!")]),
}
USER_FIELDS = {
    "id": "ID!", "name": "String", "email": "String", "role": "String",
    "bio": "String", "passwordHash": "String", "friends": "[User]",
}
POST_FIELDS = {
    "id": "ID!", "title": "String", "body": "String", "author": "User",
}
# Fields that must be auth-gated (the authz probe's protected set).
PROTECTED_FIELDS = {"me", "admin", "user", "users"}
# The mutation allow-list: GQLProbe refuses any other mutation name.
MUTATION_ALLOWLIST = {"ping", "updateProfile"}


def _type_from_str(spec):
    """'User' / 'ID!' / '[User]' / '[Post]' -> introspection type ref."""
    if spec.endswith("!"):
        return _nn(_type_from_str(spec[:-1]))
    if spec.startswith("[") and spec.endswith("]"):
        return _lst(_type_from_str(spec[1:-1]))
    kind = "OBJECT" if spec in ("Query", "Mutation", "User", "Post") \
        else "SCALAR"
    return _named(kind, spec)


def _schema_types():
    """The full introspection 'types' array, built from the tables."""
    def fields_of(table):
        out = []
        for name, spec in table.items():
            if isinstance(spec, tuple):
                t, args = spec
            else:
                t, args = spec, []
            arg_list = []
            for a_name, a_type in args:
                arg_list.append(_arg(a_name, _type_from_str(a_type)))
            out.append(_field(name, _type_from_str(t), arg_list))
        return out

    types = []
    for name, kind, fields in (
            ("Query", "OBJECT", fields_of(QUERY_FIELDS)),
            ("Mutation", "OBJECT", fields_of(MUTATION_FIELDS)),
            ("User", "OBJECT", fields_of(USER_FIELDS)),
            ("Post", "OBJECT", fields_of(POST_FIELDS))):
        types.append({"kind": kind, "name": name, "description": None,
                      "fields": fields, "inputFields": None,
                      "interfaces": [], "enumValues": None,
                      "possibleTypes": None})
    for name in SCALARS:
        types.append({"kind": "SCALAR", "name": name, "description": None,
                      "fields": None, "inputFields": None,
                      "interfaces": None, "enumValues": None,
                      "possibleTypes": None})
    types.append({"kind": "INPUT_OBJECT", "name": "UpdateProfileInput",
                  "description": None, "fields": None,
                  "inputFields": [_field("bio", _named("SCALAR", "String"))],
                  "interfaces": None, "enumValues": None,
                  "possibleTypes": None})
    return types


def build_introspection():
    """The __schema answer, in real introspection JSON shape."""
    return {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": _schema_types(),
        "directives": [
            {"name": "skip", "description": None, "locations": ["FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"],
             "args": [_arg("if", _nn(_named("SCALAR", "Boolean")))]},
            {"name": "include", "description": None, "locations": ["FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"],
             "args": [_arg("if", _nn(_named("SCALAR", "Boolean")))]},
        ],
    }


# ---------------------------------------------------------------------------
# Lexer — GraphQL query text -> tokens.
# ---------------------------------------------------------------------------

class GraphQLError(Exception):
    """A clean GraphQL error (goes in the 'errors' array, never a 500)."""


class _Token:
    __slots__ = ("kind", "value")

    def __init__(self, kind, value):
        self.kind = kind
        self.value = value

    def __repr__(self):
        return "<%s %r>" % (self.kind, self.value)


_PUNCT = set("{}()[]:!=$@=,")
# '...' is one token (SPREAD); '.' alone never appears.


def tokenize(text):
    """Split GraphQL source into tokens. Raises GraphQLError on bad input."""
    tokens = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n,":
            i += 1
            continue
        if ch == "#":  # comment to end of line
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("...", i):
            tokens.append(_Token("SPREAD", "..."))
            i += 3
            continue
        if ch in _PUNCT:
            tokens.append(_Token(ch, ch))
            i += 1
            continue
        if ch == '"':
            j = i + 1
            out = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    esc = text[j + 1]
                    mapping = {"n": "\n", "t": "\t", "r": "\r",
                               '"': '"', "\\": "\\", "/": "/",
                               "b": "\b", "f": "\f"}
                    if esc == "u" and j + 5 < n:
                        try:
                            out.append(chr(int(text[j + 2:j + 6], 16)))
                        except ValueError:
                            raise GraphQLError("Bad unicode escape")
                        j += 6
                        continue
                    out.append(mapping.get(esc, esc))
                    j += 2
                    continue
                out.append(text[j])
                j += 1
            if j >= n:
                raise GraphQLError("Unterminated string")
            tokens.append(_Token("STRING", "".join(out)))
            i = j + 1
            continue
        if ch.isdigit() or (ch == "-" and i + 1 < n and text[i + 1].isdigit()):
            m = re.match(r"-?\d+(\.\d+([eE][+-]?\d+)?|[eE][+-]?\d+)?", text[i:])
            num = m.group(0)
            if "." in num or "e" in num or "E" in num:
                tokens.append(_Token("FLOAT", float(num)))
            else:
                tokens.append(_Token("INT", int(num)))
            i += len(num)
            continue
        if ch.isalpha() or ch == "_":
            m = re.match(r"[_A-Za-z][_0-9A-Za-z]*", text[i:])
            tokens.append(_Token("NAME", m.group(0)))
            i += len(m.group(0))
            continue
        raise GraphQLError("Unexpected character %r" % ch)
    tokens.append(_Token("EOF", None))
    return tokens


# ---------------------------------------------------------------------------
# Parser — tokens -> {operations, fragments}.
# ---------------------------------------------------------------------------

class _Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.pos = 0

    def peek(self):
        return self.toks[self.pos]

    def next(self):
        tok = self.toks[self.pos]
        self.pos += 1
        return tok

    def expect(self, kind):
        tok = self.next()
        if tok.kind != kind:
            raise GraphQLError("Expected %s, got %s" % (kind, tok.kind))
        return tok

    def expect_name(self):
        tok = self.next()
        if tok.kind != "NAME":
            raise GraphQLError("Expected a name, got %s" % tok.kind)
        return tok.value

    def parse_document(self):
        operations, fragments = [], {}
        while self.peek().kind != "EOF":
            if self.peek().kind == "{":
                operations.append({"type": "query", "name": None,
                                   "variables": {}, "directives": [],
                                   "selection_set": self.parse_selection_set()})
            elif self.peek().kind == "NAME" and self.peek().value == "fragment":
                self.next()
                name = self.expect_name()
                self.expect_name()  # 'on'
                type_cond = self.expect_name()
                fragments[name] = {"type_condition": type_cond,
                                   "directives": [],
                                   "selection_set": self.parse_selection_set()}
            elif self.peek().kind == "NAME" and self.peek().value in (
                    "query", "mutation", "subscription"):
                op_type = self.next().value
                name = None
                if self.peek().kind == "NAME":
                    name = self.next().value
                variables = {}
                if self.peek().kind == "(":
                    variables = self.parse_variable_definitions()
                directives = self.parse_directives()
                operations.append({"type": op_type, "name": name,
                                   "variables": variables,
                                   "directives": directives,
                                   "selection_set": self.parse_selection_set()})
            else:
                raise GraphQLError("Unexpected token %s" % self.peek().kind)
        return {"operations": operations, "fragments": fragments}

    def parse_variable_definitions(self):
        variables = {}
        self.expect("(")
        while self.peek().kind != ")":
            self.expect("$")
            name = self.expect_name()
            self.expect(":")
            variables[name] = self.parse_type()
            if self.peek().kind == "=":
                self.next()
                variables[name]["default"] = self.parse_value()
            if self.peek().kind == ",":
                self.next()
        self.expect(")")
        return variables

    def parse_type(self):
        if self.peek().kind == "[":
            self.next()
            inner = self.parse_type()
            self.expect("]")
            t = {"kind": "LIST", "ofType": inner}
        else:
            t = {"kind": "NAMED", "name": self.expect_name()}
        if self.peek().kind == "!":
            self.next()
            t = {"kind": "NON_NULL", "ofType": t}
        return t

    def parse_directives(self):
        directives = []
        while self.peek().kind == "@":
            self.next()
            name = self.expect_name()
            args = {}
            if self.peek().kind == "(":
                args = self.parse_arguments()
            directives.append({"name": name, "args": args})
        return directives

    def parse_arguments(self):
        args = {}
        self.expect("(")
        while self.peek().kind != ")":
            name = self.expect_name()
            self.expect(":")
            args[name] = self.parse_value()
            if self.peek().kind == ",":
                self.next()
        self.expect(")")
        return args

    def parse_value(self):
        tok = self.next()
        if tok.kind == "STRING":
            return tok.value
        if tok.kind == "INT":
            return tok.value
        if tok.kind == "FLOAT":
            return tok.value
        if tok.kind == "NAME":
            if tok.value == "true":
                return True
            if tok.value == "false":
                return False
            if tok.value == "null":
                return None
            return {"__enum__": tok.value}
        if tok.kind == "$":
            return {"__var__": self.expect_name()}
        if tok.kind == "[":
            items = []
            while self.peek().kind != "]":
                items.append(self.parse_value())
                if self.peek().kind == ",":
                    self.next()
            self.expect("]")
            return items
        if tok.kind == "{":
            obj = {}
            while self.peek().kind != "}":
                key = self.expect_name()
                self.expect(":")
                obj[key] = self.parse_value()
                if self.peek().kind == ",":
                    self.next()
            self.expect("}")
            return obj
        raise GraphQLError("Unexpected value token %s" % tok.kind)

    def parse_selection_set(self):
        self.expect("{")
        selections = []
        while self.peek().kind != "}":
            if self.peek().kind == "SPREAD":
                self.next()
                if self.peek().kind == "NAME" and self.peek().value == "on":
                    self.next()
                    type_cond = self.expect_name()
                    directives = self.parse_directives()
                    selections.append({"kind": "inline_fragment",
                                       "type_condition": type_cond,
                                       "directives": directives,
                                       "selection_set": self.parse_selection_set()})
                elif self.peek().kind == "NAME":
                    name = self.next().value
                    directives = self.parse_directives()
                    selections.append({"kind": "fragment_spread",
                                       "name": name,
                                       "directives": directives})
                else:
                    directives = self.parse_directives()
                    selections.append({"kind": "inline_fragment",
                                       "type_condition": None,
                                       "directives": directives,
                                       "selection_set": self.parse_selection_set()})
                continue
            # A field: [alias:] name (args) directives [selection set]
            first = self.expect_name()
            if self.peek().kind == ":":
                self.next()
                alias, name = first, self.expect_name()
            else:
                alias, name = None, first
            args = {}
            if self.peek().kind == "(":
                args = self.parse_arguments()
            directives = self.parse_directives()
            sub = None
            if self.peek().kind == "{":
                sub = self.parse_selection_set()
            selections.append({"kind": "field", "alias": alias,
                               "name": name, "args": args,
                               "directives": directives,
                               "selection_set": sub})
        self.expect("}")
        return selections


def parse_query(text):
    """Parse GraphQL source into a document dict."""
    return _Parser(tokenize(text)).parse_document()


def query_depth(selection_set, fragments, _seen=None):
    """Max nesting of selection sets (root field = depth 1).

    Fragment cycles are counted once, then cut — a cycle cannot make
    the depth infinite."""
    if _seen is None:
        _seen = frozenset()
    depth = 0
    for sel in selection_set:
        if sel["kind"] == "field":
            sub = sel.get("selection_set")
            d = 1 + (query_depth(sub, fragments, _seen) if sub else 0)
            depth = max(depth, d)
        elif sel["kind"] == "fragment_spread":
            name = sel["name"]
            if name in _seen or name not in fragments:
                continue
            d = query_depth(fragments[name]["selection_set"], fragments,
                            _seen | {name})
            depth = max(depth, d)
        elif sel["kind"] == "inline_fragment":
            d = query_depth(sel["selection_set"], fragments, _seen)
            depth = max(depth, d)
    return depth

def query_shape_violation(selection_set, fragments, cfg, _seen=None):
    """Alias / duplicate-field / directive abuse in one query.
    Returns an error string, or None when the query is within the
    configured limits (None in the config = no limit). Checked
    before execution, like the depth limit: aliases first (an alias
    bomb is 101 copies of one field), then duplicates within one
    selection set, then directives on one field. One error only —
    the probe treats many errors as "the engine processed them all".
    """
    if _seen is None:
        _seen = frozenset()
    max_aliases = cfg.get("max_aliases")
    max_dup = cfg.get("max_duplicates")
    max_dir = cfg.get("max_directives")
    if max_aliases is None and max_dup is None and max_dir is None:
        return None
    aliases = 0
    names = {}
    for sel in selection_set:
        if sel["kind"] == "field":
            if sel.get("alias"):
                aliases += 1
            names[sel["name"]] = names.get(sel["name"], 0) + 1
            if max_dir is not None and len(sel.get("directives") or []) \
                    > max_dir:
                return ("Too many directives on field '%s' (%d > %d)"
                        % (sel["name"], len(sel["directives"]), max_dir))
        elif sel["kind"] == "fragment_spread":
            name = sel["name"]
            if name in _seen or name not in fragments:
                continue
            err = query_shape_violation(
                fragments[name]["selection_set"], fragments, cfg,
                _seen | {name})
            if err:
                return err
        elif sel["kind"] == "inline_fragment":
            err = query_shape_violation(sel["selection_set"], fragments,
                                        cfg, _seen)
            if err:
                return err
    if max_aliases is not None and aliases > max_aliases:
        return "Too many aliases in one query (%d > %d)" % (
            aliases, max_aliases)
    if max_dup is not None:
        for name, count in names.items():
            if count > max_dup:
                return ("Field '%s' repeated %d times in one selection "
                        "set (max %d)" % (name, count, max_dup))
    for sel in selection_set:
        if sel["kind"] == "field" and sel.get("selection_set"):
            err = query_shape_violation(sel["selection_set"], fragments,
                                        cfg, _seen)
            if err:
                return err
    return None


# ---------------------------------------------------------------------------
# Executor — runs a parsed document against the schema.
# ---------------------------------------------------------------------------

# Fields of each object type, for validation + suggestions.
TYPE_FIELDS = {"Query": list(QUERY_FIELDS), "Mutation": list(MUTATION_FIELDS),
               "User": list(USER_FIELDS), "Post": list(POST_FIELDS)}


def _suggest(word, candidates):
    """Closest field name (difflib) — the Clairvoyance leak."""
    matches = difflib.get_close_matches(word, candidates, n=1, cutoff=0.6)
    return matches[0] if matches else None


def _resolve_value(value, variables):
    """Replace $variables and unwrap enums in an argument value."""
    if isinstance(value, dict):
        if "__var__" in value:
            name = value["__var__"]
            if name not in variables:
                raise GraphQLError("Variable $%s was not provided" % name)
            return variables[name]
        if "__enum__" in value:
            return value["__enum__"]
        return {k: _resolve_value(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_value(v, variables) for v in value]
    return value


def _directive_allows(directives, variables):
    """@skip(if:) / @include(if:) — False means 'leave this out'."""
    for d in directives:
        if d["name"] not in ("skip", "include"):
            continue
        raw = d["args"].get("if")
        val = _resolve_value(raw, variables) if raw is not None else None
        if d["name"] == "skip" and val is True:
            return False
        if d["name"] == "include" and val is False:
            return False
    return True


class Executor:
    """One request's execution. config = one of CONFIGS; user_id is
    the id from the Bearer token, or None for anonymous."""

    def __init__(self, config, user_id=None):
        self.cfg = CONFIGS[config]
        self.config_name = config
        self.user_id = user_id

    # -- auth helpers ---------------------------------------------------
    def _authed(self):
        return self.user_id is not None

    def _is_admin(self):
        return self._authed() and USERS[self.user_id]["role"] == "admin"

    def _need_token(self, what):
        if not self.cfg["auth_enforced"]:
            return
        if not self._authed():
            raise GraphQLError("Authentication required to access %s" % what)

    # -- introspection --------------------------------------------------
    def _introspection_blocked(self, query_text, via_get):
        """True when this request's introspection must be refused.

        vulnerable: never blocked. hardened: always blocked.
        partial: the guard only looks for '__schema {' with a literal
        space (the CVE-2024-37155 shape), only on POST, and never
        looks at __type at all — so __type, GET and the newline
        variant slip past it."""
        if self.cfg["introspection"]:
            return False
        if self.config_name == "hardened":
            return True
        # partial: naive guard
        if via_get and self.cfg["get_introspection"]:
            return False
        # __type as a FIELD name — not __typename, which is a normal
        # meta-field (a plain substring test would block every query
        # that uses __typename, including the probe's alias/dup/
        # directive bombs).
        if (re.search(r"__type(?!name)\b", query_text)
                and "__schema" not in query_text):
            return self.cfg["type_bypass"] is False
        if self.cfg["newline_bypass"] and re.search(r"__schema\s*\n\s*\{",
                                                    query_text):
            return False
        if re.search(r"__schema \{", query_text):
            return True
        return False

    # -- main entry -----------------------------------------------------
    def execute(self, query_text, variables=None, operation_name=None,
                via_get=False):
        variables = variables or {}
        try:
            doc = parse_query(query_text)
        except GraphQLError as exc:
            return {"data": None, "errors": [{"message": str(exc)}]}
        if not doc["operations"]:
            return {"data": None,
                    "errors": [{"message": "No operation found"}]}
        op = doc["operations"][0]
        if operation_name:
            for cand in doc["operations"]:
                if cand["name"] == operation_name:
                    op = cand
                    break
        # Introspection guard (checked on the raw text, like the real
        # regex filters do — that is exactly what makes the bypasses
        # possible on the partial config). __type is matched as a
        # field name: __typename is NOT introspection (it only names
        # the current object's type), so a plain substring test would
        # wrongly refuse every __typename query.
        if "__schema" in query_text or re.search(
                r"__type(?!name)\b", query_text):
            if self._introspection_blocked(query_text, via_get=via_get):
                return {"data": None, "errors": [
                    {"message": "Introspection is disabled"}]}
        # Depth limit (checked before execution, like the real fix).
        depth = query_depth(op["selection_set"], doc["fragments"])
        limit = self.cfg["depth_limit"]
        if limit is not None and depth > limit:
            return {"data": None, "errors": [
                {"message": "Query depth %d exceeds maximum %d"
                            % (depth, limit)}]}
        if depth > MAX_DEPTH_CAP:
            return {"data": None, "errors": [
                {"message": "Query too deep (safety cap %d)" % MAX_DEPTH_CAP}]}
        # Query-shape abuse limits (aliases, duplicate fields,
        # directives) — checked before execution, like the depth limit.
        shape_err = query_shape_violation(op["selection_set"],
                                          doc["fragments"], self.cfg)
        if shape_err:
            return {"data": None, "errors": [{"message": shape_err}]}
        # Field errors become partial data + an errors array (real
        # GraphQL behaviour: one bad field nulls itself, it does not
        # wipe the whole response). Only parse / depth / introspection
        # failures return data: null.
        self._errors = []
        try:
            if op["type"] == "query":
                data = self._execute_selection(
                    "Query", None, op["selection_set"], doc, variables)
            elif op["type"] == "mutation":
                data = self._execute_selection(
                    "Mutation", None, op["selection_set"], doc, variables)
            else:
                return {"data": None, "errors": [
                    {"message": "Subscriptions are not supported by "
                                "this lab API"}]}
        except GraphQLError as exc:
            return {"data": None, "errors": [{"message": str(exc)}]}
        if self._errors:
            return {"data": data,
                    "errors": [{"message": m} for m in self._errors]}
        return {"data": data}

    def execute_get(self, query_text, variables=None):
        """Same as execute(), but the request came over GET — the
        introspection guard is checked once, with via_get=True, so a
        GET-only hole (partial config) is not re-blocked by the POST
        guard inside execute()."""
        return self.execute(query_text, variables, via_get=True)

    # -- selection execution --------------------------------------------
    def _execute_selection(self, type_name, obj, selection_set, doc,
                           variables):
        out = {}
        for sel in selection_set:
            if sel["kind"] == "fragment_spread":
                frag = doc["fragments"].get(sel["name"])
                if frag is None:
                    self._errors.append("Unknown fragment %r" % sel["name"])
                    continue
                if not _directive_allows(sel["directives"], variables):
                    continue
                sub = self._execute_selection(
                    type_name, obj, frag["selection_set"], doc, variables)
                out.update(sub)
                continue
            if sel["kind"] == "inline_fragment":
                cond = sel.get("type_condition")
                if cond is not None and cond != type_name:
                    continue
                if not _directive_allows(sel["directives"], variables):
                    continue
                sub = self._execute_selection(
                    type_name, obj, sel["selection_set"], doc, variables)
                out.update(sub)
                continue
            # Field
            if not _directive_allows(sel["directives"], variables):
                continue
            key = sel["alias"] or sel["name"]
            try:
                value = self._resolve_field(type_name, obj, sel, doc,
                                            variables)
            except GraphQLError as exc:
                self._errors.append(str(exc))
                out[key] = None
                continue
            out[key] = value
        return out

    def _resolve_field(self, type_name, obj, sel, doc, variables):
        name = sel["name"]
        args = {k: _resolve_value(v, variables)
                for k, v in sel["args"].items()}
        sub = sel.get("selection_set")
        if name == "__typename":
            if sub:
                raise GraphQLError("Field '__typename' must not have a "
                                   "selection of subfields")
            return type_name
        if name == "__schema":
            return self._resolve_schema(sub, doc, variables)
        if name == "__type":
            return self._resolve_type(args, sub, doc, variables)
        fields = TYPE_FIELDS.get(type_name)
        if fields is None or name not in fields:
            msg = "Cannot query field %r on type %r" % (name, type_name)
            if self.cfg["suggestions"]:
                sug = _suggest(name, fields or [])
                if sug:
                    msg += ". Did you mean %r?" % sug
            raise GraphQLError(msg)
        if type_name == "Query":
            return self._resolve_query(name, args, sub, doc, variables)
        if type_name == "Mutation":
            return self._resolve_mutation(name, args, sub, doc, variables)
        if type_name == "User":
            return self._resolve_user(obj, name, sub, doc, variables)
        if type_name == "Post":
            return self._resolve_post(obj, name, sub, doc, variables)
        raise GraphQLError("Unknown type %r" % type_name)

    # -- meta-fields ------------------------------------------------------
    def _resolve_schema(self, sub, doc, variables):
        if not sub:
            raise GraphQLError("Field '__schema' of type '__Schema' must "
                               "have a selection of subfields")
        out = {}
        for sel in sub:
            if sel["kind"] != "field":
                continue
            fname = sel["name"]
            if fname == "__typename":
                out[sel["alias"] or fname] = "__Schema"
            elif fname == "queryType":
                out[sel["alias"] or fname] = {"name": "Query"}
            elif fname == "mutationType":
                out[sel["alias"] or fname] = {"name": "Mutation"}
            elif fname == "subscriptionType":
                out[sel["alias"] or fname] = None
            elif fname == "types":
                out[sel["alias"] or fname] = self._types_selection(
                    sel.get("selection_set") or [], doc, variables)
            elif fname == "directives":
                out[sel["alias"] or fname] = build_introspection()["directives"]
            else:
                raise GraphQLError("Cannot query field %r on type "
                                   "'__Schema'" % fname)
        return out

    def _types_selection(self, selection_set, doc, variables):
        """__schema { types { ... } } — project the static type list."""
        out_types = []
        for t in _schema_types():
            entry = {}
            for sel in selection_set:
                if sel["kind"] != "field":
                    continue
                fname = sel["name"]
                key = sel["alias"] or fname
                if fname == "__typename":
                    entry[key] = "__Type"
                elif fname == "name":
                    entry[key] = t["name"]
                elif fname == "kind":
                    entry[key] = t["kind"]
                elif fname == "description":
                    entry[key] = t.get("description")
                elif fname == "fields":
                    entry[key] = self._fields_selection(
                        t.get("fields") or [],
                        sel.get("selection_set") or [], doc, variables)
                elif fname == "inputFields":
                    entry[key] = t.get("inputFields")
                elif fname == "interfaces":
                    entry[key] = t.get("interfaces") or []
                elif fname == "enumValues":
                    entry[key] = t.get("enumValues")
                elif fname == "possibleTypes":
                    entry[key] = t.get("possibleTypes")
            out_types.append(entry)
        return out_types

    def _fields_selection(self, fields, selection_set, doc, variables):
        out = []
        for f in fields:
            entry = {}
            for sel in selection_set:
                if sel["kind"] != "field":
                    continue
                fname = sel["name"]
                key = sel["alias"] or fname
                if fname == "__typename":
                    entry[key] = "__Field"
                elif fname == "name":
                    entry[key] = f["name"]
                elif fname == "description":
                    entry[key] = f.get("description")
                elif fname == "args":
                    entry[key] = self._args_selection(
                        f.get("args") or [], sel.get("selection_set") or [])
                elif fname == "type":
                    entry[key] = self._type_selection(
                        f["type"], sel.get("selection_set") or [])
                elif fname == "isDeprecated":
                    entry[key] = f.get("isDeprecated", False)
                elif fname == "deprecationReason":
                    entry[key] = f.get("deprecationReason")
            out.append(entry)
        return out

    def _args_selection(self, args, selection_set):
        out = []
        for a in args:
            entry = {}
            for sel in selection_set:
                if sel["kind"] != "field":
                    continue
                fname = sel["name"]
                key = sel["alias"] or fname
                if fname == "__typename":
                    entry[key] = "__InputValue"
                elif fname == "name":
                    entry[key] = a["name"]
                elif fname == "description":
                    entry[key] = a.get("description")
                elif fname == "type":
                    entry[key] = self._type_selection(
                        a["type"], sel.get("selection_set") or [])
                elif fname == "defaultValue":
                    entry[key] = a.get("defaultValue")
            out.append(entry)
        return out

    def _type_selection(self, tref, selection_set):
        entry = {}
        for sel in selection_set:
            if sel["kind"] != "field":
                continue
            fname = sel["name"]
            key = sel["alias"] or fname
            if fname == "__typename":
                entry[key] = "__Type"
            elif fname == "kind":
                entry[key] = tref["kind"]
            elif fname == "name":
                entry[key] = tref.get("name")
            elif fname == "ofType":
                inner = tref.get("ofType")
                entry[key] = (self._type_selection(
                    inner, sel.get("selection_set") or [])
                    if inner else None)
        return entry

    def _resolve_type(self, args, sub, doc, variables):
        name = args.get("name")
        match = [t for t in _schema_types() if t["name"] == name]
        if not match:
            return None
        if not sub:
            raise GraphQLError("Field '__type' of type '__Type' must have "
                               "a selection of subfields")
        t = match[0]
        out = {}
        for sel in sub:
            if sel["kind"] != "field":
                continue
            fname = sel["name"]
            key = sel["alias"] or fname
            if fname == "__typename":
                out[key] = "__Type"
            elif fname == "name":
                out[key] = t["name"]
            elif fname == "kind":
                out[key] = t["kind"]
            elif fname == "description":
                out[key] = t.get("description")
            elif fname == "fields":
                out[key] = self._fields_selection(
                    t.get("fields") or [], sel.get("selection_set") or [],
                    doc, variables)
            elif fname == "inputFields":
                out[key] = t.get("inputFields")
            elif fname == "interfaces":
                out[key] = t.get("interfaces") or []
            elif fname == "enumValues":
                out[key] = t.get("enumValues")
            elif fname == "possibleTypes":
                out[key] = t.get("possibleTypes")
        return out

    # -- Query / Mutation / User / Post resolvers -------------------------
    def _resolve_query(self, name, args, sub, doc, variables):
        if name == "me":
            self._need_token("me")
            uid = self.user_id or "1"
            return self._user_obj(USERS[uid], sub, doc, variables)
        if name == "user":
            uid = args.get("id")
            if self.cfg["auth_enforced"]:
                self._need_token("user")
                if not self.cfg["idor_open"] and not self._is_admin() \
                        and uid != self.user_id:
                    raise GraphQLError(
                        "Forbidden: you can only fetch your own user")
            if uid not in USERS:
                return None
            return self._user_obj(USERS[uid], sub, doc, variables)
        if name == "users":
            if self.cfg["auth_enforced"] and not self._is_admin():
                self._need_token("users")
                raise GraphQLError("Forbidden: users needs the admin role")
            return [self._user_obj(u, sub, doc, variables)
                    for u in USERS.values()]
        if name == "post":
            post = POSTS.get(str(args.get("id")))
            if post is None:
                return None
            return self._post_obj(post, sub, doc, variables)
        if name == "posts":
            return [self._post_obj(p, sub, doc, variables)
                    for p in POSTS.values()]
        if name == "search":
            q = (args.get("q") or "").lower()
            return [self._post_obj(p, sub, doc, variables)
                    for p in POSTS.values()
                    if q in p["title"].lower() or q in p["body"].lower()]
        if name == "admin":
            if self.cfg["auth_enforced"]:
                self._need_token("admin")
                if not self._is_admin():
                    raise GraphQLError("Forbidden: admin only")
            return ADMIN_SECRET
        raise GraphQLError("Unknown query field %r" % name)

    def _resolve_mutation(self, name, args, sub, doc, variables):
        if name == "ping":
            self._need_token("ping")
            return "pong"
        if name == "updateProfile":
            self._need_token("updateProfile")
            uid = self.user_id or "1"
            user = USERS[uid]
            inp = args.get("input") or {}
            if isinstance(inp, dict) and "bio" in inp and inp["bio"] is not None:
                user["bio"] = inp["bio"]
            return self._user_obj(user, sub, doc, variables)
        if name == "grantAdmin":
            if self.cfg["auth_enforced"] and not self._is_admin():
                self._need_token("grantAdmin")
                raise GraphQLError("Forbidden: grantAdmin needs the "
                                   "admin role")
            uid = args.get("userId")
            if uid not in USERS:
                raise GraphQLError("No such user %r" % uid)
            USERS[uid]["role"] = "admin"
            return self._user_obj(USERS[uid], sub, doc, variables)
        raise GraphQLError("Unknown mutation %r" % name)

    def _require_sub(self, sub, type_name, field_name):
        if not sub:
            raise GraphQLError(
                "Field %r of type %r must have a selection of subfields"
                % (field_name, type_name))

    def _user_obj(self, user, sub, doc, variables):
        self._require_sub(sub, "User", "user")
        return self._execute_selection("User", user, sub, doc, variables)

    def _post_obj(self, post, sub, doc, variables):
        self._require_sub(sub, "Post", "post")
        return self._execute_selection("Post", post, sub, doc, variables)

    def _resolve_user(self, user, name, sub, doc, variables):
        if name == "friends":
            self._require_sub(sub, "User", "friends")
            return [self._user_obj(USERS[fid], sub, doc, variables)
                    for fid in user["friends"] if fid in USERS]
        if name in ("id", "name", "email", "role", "bio", "passwordHash"):
            if sub:
                raise GraphQLError("Field %r must not have a selection of "
                                   "subfields" % name)
            return user[name]
        raise GraphQLError("Unknown User field %r" % name)

    def _resolve_post(self, post, name, sub, doc, variables):
        if name == "author":
            self._require_sub(sub, "Post", "author")
            return self._user_obj(USERS[post["author"]], sub, doc,
                                  variables)
        if name in ("id", "title", "body"):
            if sub:
                raise GraphQLError("Field %r must not have a selection of "
                                   "subfields" % name)
            return post[name]
        raise GraphQLError("Unknown Post field %r" % name)

# ---------------------------------------------------------------------------
# HTTP layer — POST JSON, GET ?query=, array batching, flood guard.
# ---------------------------------------------------------------------------


class LabState:
    """Per-server mutable state: the rate-limit flood guard."""

    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        # query text -> (count, window_start)
        self.seen = {}

    def rate_limited(self, query_text):
        """True when this identical query has been seen too often in
        the current window (hardened/partial configs only)."""
        if not CONFIGS[self.config]["rate_limit"]:
            return False
        now = time.time()
        with self.lock:
            count, start = self.seen.get(query_text, (0, now))
            if now - start > RATE_LIMIT_WINDOW:
                count, start = 0, now
            count += 1
            self.seen[query_text] = (count, start)
            return count > RATE_LIMIT_COUNT


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep the lab quiet
            pass

        def _send_json(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            # A Server header on purpose: the fingerprint probe reads it.
            self.send_header("Server", "GQLProbe-Lab/1.0")
            self.end_headers()
            self.wfile.write(body)

        def _user_id(self):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return TOKENS.get(auth[7:].strip())
            return None

        def _run_one(self, payload, via_get):
            """Run one GraphQL operation object. Returns (status, dict)."""
            if not isinstance(payload, dict) or "query" not in payload:
                return 400, {"errors": [{"message":
                    "Expected a JSON object with a 'query' field"}]}
            query = payload["query"]
            variables = payload.get("variables") or {}
            if isinstance(variables, str):
                try:
                    variables = json.loads(variables)
                except ValueError:
                    variables = {}
            if state.rate_limited(query):
                return 429, {"errors": [{"message":
                    "Too many requests — rate limit exceeded "
                    "(%d identical requests in %ds)"
                    % (RATE_LIMIT_COUNT, int(RATE_LIMIT_WINDOW))}]}
            ex = Executor(state.config, self._user_id())
            if via_get:
                return 200, ex.execute_get(query, variables)
            return 200, ex.execute(query, variables,
                                   payload.get("operationName"))

        def _handle_graphql(self, via_get, body=None):
            if via_get:
                qs = parse_qs(urlparse(self.path).query)
                query = qs.get("query", [None])[0]
                if query is None:
                    self._send_json(400, {"errors": [{"message":
                        "GET needs a 'query' parameter"}]})
                    return
                variables = {}
                raw_vars = qs.get("variables", [None])[0]
                if raw_vars:
                    try:
                        variables = json.loads(raw_vars)
                    except ValueError:
                        variables = {}
                status, payload = self._run_one(
                    {"query": query, "variables": variables}, via_get=True)
                self._send_json(status, payload)
                return
            try:
                data = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._send_json(400, {"errors": [{"message":
                    "Invalid JSON body"}]})
                return
            if isinstance(data, list):
                # Array batching.
                if not CONFIGS[state.config]["batching"]:
                    self._send_json(200, {"errors": [{"message":
                        "Batching is disabled"}]})
                    return
                out = []
                for item in data:
                    status, payload = self._run_one(item, via_get=False)
                    out.append(payload)
                self._send_json(200, out)
                return
            status, payload = self._run_one(data, via_get=False)
            self._send_json(status, payload)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            self._handle_graphql(via_get=False, body=body)

        def do_GET(self):
            self._handle_graphql(via_get=True)

    return Handler


def print_config(config):
    cfg = CONFIGS[config]
    print("GQLProbe lab API — config: %s" % config)
    for key in ("introspection", "depth_limit", "batching",
                "suggestions", "rate_limit", "auth_enforced",
                "idor_open"):
        print("  %-14s: %s" % (key, cfg[key]))
    print("  tokens: lab-token-alice (user 1), lab-token-bob (user 2), "
          "lab-token-admin (user 3, admin)")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="GQLProbe lab GraphQL API (stdlib only)")
    parser.add_argument("--config", default="vulnerable",
                        choices=list(CONFIGS),
                        help="lab configuration (default: vulnerable)")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)
    print_config(args.config)
    state = LabState(args.config)
    server = ThreadingHTTPServer((args.host, args.port),
                                 make_handler(state))
    print("Listening on http://%s:%d/graphql" % (args.host, args.port))
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
