"""Deterministic rule matching and the pack expression language.

Pack rules are written by compliance people, so the expression language is a
small, readable subset of Python's expression grammar, parsed with ``ast`` and
evaluated with a whitelist. No attribute access on arbitrary objects, no calls
except the registered helper functions, no comprehensions.

Namespaces available in an expression:

    args.<name>        tool-call arguments (missing -> None)
    principal.<name>   user / agent / roles / any claim (missing -> None)
    firm.<name>        the firm overlay (thresholds, restricted list, flags) — constants per deployment
    call.tool, call.session_id
    bare identifiers   treated as string literals ("options", "ssn") so a CCO can
                       write ``args.security_type in [options, margin]``

Functions: contains_pii(text, [kinds]), contains_hypothetical_performance(text), len, lower,
upper, startswith, endswith, matches(text, regex), has(args.x), any_in(list, list), hour_utc(),
weekday_utc().

The same AST is what the compilers (cel.py, cedar.py, rego.py) translate, so
one pack runs everywhere.
"""
from __future__ import annotations

import ast
import fnmatch
import re
from datetime import datetime, timezone
from typing import Any, Callable

from regent.core.models import Pack, Rule, ToolCall

# ----------------------------------------------------------------------------- PII detectors

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
    "account_number": re.compile(r"\b(?:acct|account|a/c)[\s#:]*\d{6,17}\b", re.I),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "routing_number": re.compile(r"\b(?:aba|routing)[\s#:]*\d{9}\b", re.I),
    "dob": re.compile(r"\b(?:dob|date of birth)[\s:]*\d{1,2}/\d{1,2}/\d{2,4}\b", re.I),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "phone": re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
    "npi": re.compile(r"\bNPI[\s#:]*\d{10}\b", re.I),
    "mrn": re.compile(r"\bMRN[\s#:]*\w{6,12}\b", re.I),
}


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def contains_pii(text: Any, kinds: list[str] | None = None) -> bool:
    if text is None:
        return False
    if not isinstance(text, str):
        text = str(text)
    kinds = kinds or ["ssn", "account_number", "credit_card"]
    for kind in kinds:
        pat = PII_PATTERNS.get(kind)
        if pat is None:
            raise ValueError(f"unknown pii kind: {kind}")
        for m in pat.finditer(text):
            if kind == "credit_card":
                digits = re.sub(r"\D", "", m.group(0))
                if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                    return True
                continue
            return True
    return False


HYPOTHETICAL_PERFORMANCE = re.compile(
    r"\b(hypothetical|back[- ]?tested?|backtest(ing|ed)?|projected (returns?|performance)|target(ed)? returns?|"
    r"model (portfolio )?performance|simulated (returns?|performance)|pro[- ]?forma (returns?|performance)|"
    r"extracted performance|would have (returned|earned|grown))\b", re.I)


def contains_hypothetical_performance(text: Any) -> bool:
    """Marketing Rule 206(4)-1(d)(6): hypothetical performance needs policies, an intended
    audience and (for one-on-one) still counts as an advertisement. Heuristic regex; a firm
    tightens it in the overlay if needed."""
    return bool(text) and HYPOTHETICAL_PERFORMANCE.search(str(text)) is not None


def pii_kinds_found(text: Any, kinds: list[str] | None = None) -> list[str]:
    kinds = kinds or list(PII_PATTERNS)
    return [k for k in kinds if contains_pii(text, [k])]


# ----------------------------------------------------------------------------- evaluator

FUNCTIONS: dict[str, Callable[..., Any]] = {
    "contains_pii": contains_pii,
    "contains_hypothetical_performance": contains_hypothetical_performance,
    "len": lambda x: 0 if x is None else len(x),
    "lower": lambda s: (s or "").lower(),
    "upper": lambda s: (s or "").upper(),
    "startswith": lambda s, p: str(s or "").startswith(p),
    "endswith": lambda s, p: str(s or "").endswith(p),
    "matches": lambda s, rx: re.search(rx, str(s or "")) is not None,
    "has": lambda v: v is not None,
    "any_in": lambda a, b: any(x in (b or []) for x in (a or [])),
    "hour_utc": lambda: datetime.now(timezone.utc).hour,
    "weekday_utc": lambda: datetime.now(timezone.utc).weekday(),
    "abs": abs,
    "min": min,
    "max": max,
    "str": str,
    "int": int,
    "float": float,
}

_BIN = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.Mod: lambda a, b: a % b,
}
_CMP = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: _num(a) < _num(b),
    ast.LtE: lambda a, b: _num(a) <= _num(b),
    ast.Gt: lambda a, b: _num(a) > _num(b),
    ast.GtE: lambda a, b: _num(a) >= _num(b),
    ast.In: lambda a, b: a in (b if b is not None else []),
    ast.NotIn: lambda a, b: a not in (b if b is not None else []),
}


def _num(v: Any) -> float:
    """Missing numeric args compare as -inf so ``args.x <= 5000`` with no x is True
    only for upper bounds; callers that care use has(args.x)."""
    if v is None:
        return float("-inf")
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(str(v).replace(",", ""))
    except ValueError:
        raise TypeError(f"not numeric: {v!r}")


class ExpressionError(ValueError):
    pass


class Expression:
    """A parsed, validated pack expression. Evaluate with ``.eval(call)``."""

    __slots__ = ("text", "tree", "uses_args", "firm_keys")

    def __init__(self, text: str):
        self.text = text.strip()
        try:
            self.tree = ast.parse(self.text, mode="eval").body
        except SyntaxError as e:
            raise ExpressionError(f"bad expression {text!r}: {e}") from e
        self._validate(self.tree)
        self.uses_args = any(
            isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "args"
            for n in ast.walk(self.tree)
        )
        self.firm_keys = tuple(sorted({n.attr for n in ast.walk(self.tree)
                                       if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "firm"}))

    def _validate(self, node: ast.AST) -> None:
        allowed = (ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare, ast.Call, ast.Name, ast.Constant,
                   ast.Attribute, ast.List, ast.Tuple, ast.And, ast.Or, ast.Not, ast.USub, ast.Load,
                   ast.Subscript, ast.IfExp) + tuple(_BIN) + tuple(_CMP)
        for n in ast.walk(node):
            if not isinstance(n, allowed):
                raise ExpressionError(f"disallowed syntax {type(n).__name__} in {self.text!r}")
            if isinstance(n, ast.Call):
                if not isinstance(n.func, ast.Name) or n.func.id not in FUNCTIONS:
                    raise ExpressionError(f"unknown function in {self.text!r}")
                if n.keywords:
                    raise ExpressionError("keyword arguments not allowed")
            if isinstance(n, ast.Attribute):
                if not (isinstance(n.value, ast.Name) and n.value.id in ("args", "principal", "call", "firm")):
                    raise ExpressionError(f"attribute access only on args/principal/call/firm: {self.text!r}")
                if n.attr.startswith("_"):
                    raise ExpressionError(f"private attribute in {self.text!r}")

    def eval(self, call: ToolCall, firm: dict[str, Any] | None = None) -> bool:
        return bool(self._ev(self.tree, call, firm or {}))

    def _ev(self, n: ast.AST, call: ToolCall, firm: dict[str, Any]) -> Any:
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            if n.id in ("True", "true"):
                return True
            if n.id in ("False", "false"):
                return False
            if n.id in ("None", "null"):
                return None
            return n.id  # bare identifier == string literal
        if isinstance(n, ast.Attribute):
            root = n.value.id  # type: ignore[attr-defined]
            if root == "args":
                return call.args.get(n.attr)
            if root == "principal":
                return call.principal.get(n.attr)
            if root == "call":
                return getattr(call, n.attr, None)
            if root == "firm":
                return firm.get(n.attr)
        if isinstance(n, (ast.List, ast.Tuple)):
            return [self._ev(e, call, firm) for e in n.elts]
        if isinstance(n, ast.Subscript):
            base = self._ev(n.value, call, firm)
            key = self._ev(n.slice, call, firm)
            try:
                return base[key]
            except (KeyError, IndexError, TypeError):
                return None
        if isinstance(n, ast.BoolOp):
            if isinstance(n.op, ast.And):
                return all(self._ev(v, call, firm) for v in n.values)
            return any(self._ev(v, call, firm) for v in n.values)
        if isinstance(n, ast.UnaryOp):
            v = self._ev(n.operand, call, firm)
            return (not v) if isinstance(n.op, ast.Not) else -_num(v)
        if isinstance(n, ast.BinOp):
            return _BIN[type(n.op)](_num(self._ev(n.left, call, firm)), _num(self._ev(n.right, call, firm)))
        if isinstance(n, ast.Compare):
            left = self._ev(n.left, call, firm)
            for op, comp in zip(n.ops, n.comparators):
                right = self._ev(comp, call, firm)
                if not _CMP[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(n, ast.Call):
            fn = FUNCTIONS[n.func.id]  # type: ignore[attr-defined]
            return fn(*[self._ev(a, call, firm) for a in n.args])
        if isinstance(n, ast.IfExp):
            return self._ev(n.body, call, firm) if self._ev(n.test, call, firm) else self._ev(n.orelse, call, firm)
        raise ExpressionError(f"cannot evaluate {ast.dump(n)}")


_cache: dict[str, Expression] = {}


def compile_expression(text: str) -> Expression:
    e = _cache.get(text)
    if e is None:
        e = _cache[text] = Expression(text)
    return e


def expression_uses_args(text: str) -> bool:
    return compile_expression(text).uses_args


def expression_firm_keys(text: str) -> tuple[str, ...]:
    return compile_expression(text).firm_keys


# ----------------------------------------------------------------------------- matching


def tool_matches(pattern: str, tool: str) -> bool:
    return fnmatch.fnmatchcase(tool, pattern)


def pattern_specificity(pattern: str) -> int:
    """Longer, more literal patterns win. '*' is least specific."""
    return sum(1 for c in pattern if c not in "*?[]")


class Matcher:
    """Deterministic: for a call, find the governing rule across loaded packs.

    Order: most specific tool pattern first, then explicit ``priority`` (lower
    first), then pack load order, then rule order in the pack. Unit-tested;
    no randomness, no time dependence beyond explicit hour_utc() calls.
    """

    def __init__(self, packs: list[Pack]):
        self.packs = packs
        self._index: list[tuple[int, int, int, int, Pack, Rule]] = []
        for pi, pack in enumerate(packs):
            for ri, rule in enumerate(pack.rules):
                self._index.append((-pattern_specificity(rule.tool), rule.priority, pi, ri, pack, rule))
        self._index.sort(key=lambda t: t[:4])

    def candidates(self, tool: str) -> list[tuple[Pack, Rule]]:
        return [(p, r) for *_, p, r in self._index if tool_matches(r.tool, tool)]

    def governing(self, tool: str) -> tuple[Pack, Rule] | None:
        c = self.candidates(tool)
        return c[0] if c else None

    def coverage_gaps(self, tools: list[str]) -> list[str]:
        """Tools reachable through the gateway that no rule governs — the finding
        an examiner would otherwise write."""
        return [t for t in tools if not self.candidates(t)]

    def evaluate(self, call: ToolCall) -> tuple[str, Pack, Rule] | None:
        """Return (verdict, pack, rule) for the first candidate that produces a
        verdict. ``deny_if`` is checked before ``hold_if`` before ``allow_if`` so a
        deny can never be bypassed by an allow in the same rule."""
        below_threshold: tuple[Pack, Rule] | None = None
        for pack, rule in self.candidates(call.tool):
            if rule.deny_if and compile_expression(rule.deny_if).eval(call, pack.firm):
                return ("deny", pack, rule)
            if rule.hold_if and compile_expression(rule.hold_if).eval(call, pack.firm):
                return ("hold", pack, rule)
            if rule.allow_if is None:
                # deny-only or hold-only rule that did not fire: it neither allows nor denies
                # on its own. Remember a hold-only rule as the "below threshold" allow.
                if rule.hold_if and below_threshold is None:
                    below_threshold = (pack, rule)
                continue
            if compile_expression(rule.allow_if).eval(call, pack.firm):
                return ("allow", pack, rule)
            # allow_if present but false: the explicit allow condition is not met → deny
            return ("deny", pack, rule)
        if below_threshold:
            return ("allow", *below_threshold)
        return None
