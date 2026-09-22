"""Shared AST → dialect translation for the pack expression language.

Each dialect supplies how to render: an ``args`` reference, a ``principal``
reference, string literals, lists, ``in``, and the helper functions. Anything a
dialect cannot express raises ``Uncompilable`` and the rule is routed to the PDS.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Callable

from regent.core.match import compile_expression


class Uncompilable(Exception):
    pass


@dataclass
class Dialect:
    name: str
    args_ref: Callable[[str], str]  # "notional_usd" -> "context.args.notional_usd"
    principal_ref: Callable[[str], str]  # "roles" -> "jwt.roles"
    string: Callable[[str], str] = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    list_: Callable[[list[str]], str] = lambda xs: "[" + ", ".join(xs) + "]"
    in_: Callable[[str, str], str] = lambda a, b: f"{a} in {b}"
    not_in: Callable[[str, str], str] = lambda a, b: f"!({a} in {b})"
    and_: str = "&&"
    or_: str | None = "||"
    not_: Callable[[str], str] = lambda x: f"!({x})"
    eq: str = "=="
    ne: str = "!="
    true: str = "true"
    false: str = "false"
    null: str = "null"
    functions: dict[str, Callable[[list[str]], str]] = field(default_factory=dict)
    args_supported: bool = True
    has: Callable[[str], str] | None = None  # render has(<ref>)
    paren_and: bool = True  # Rego bodies are newline-joined conjunctions, not parenthesised


_CMP_TXT = {ast.Eq: "eq", ast.NotEq: "ne", ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">="}
_BIN_TXT = {ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/", ast.Mod: "%"}


def translate(text: str, d: Dialect, firm: dict | None = None) -> str:
    expr = compile_expression(text)
    return _tr(expr.tree, d, firm or {})


def _const(v, d: Dialect) -> str:
    if isinstance(v, bool):
        return d.true if v else d.false
    if v is None:
        return d.null
    if isinstance(v, str):
        return d.string(v)
    if isinstance(v, (list, tuple)):
        return d.list_([_const(x, d) for x in v])
    return repr(v)


def _tr(n: ast.AST, d: Dialect, firm: dict | None = None) -> str:
    firm = firm or {}
    if isinstance(n, ast.Constant):
        if isinstance(n.value, bool):
            return d.true if n.value else d.false
        if n.value is None:
            return d.null
        if isinstance(n.value, str):
            return d.string(n.value)
        return repr(n.value)
    if isinstance(n, ast.Name):
        if n.id in ("True", "true"):
            return d.true
        if n.id in ("False", "false"):
            return d.false
        if n.id in ("None", "null"):
            return d.null
        return d.string(n.id)
    if isinstance(n, ast.Attribute):
        root = n.value.id  # type: ignore[attr-defined]
        if root == "args":
            if not d.args_supported:
                raise Uncompilable(f"{d.name}: tool arguments are not available at authorization time")
            return d.args_ref(n.attr)
        if root == "principal":
            return d.principal_ref(n.attr)
        if root == "firm":
            if n.attr not in firm:
                raise Uncompilable(f"{d.name}: firm.{n.attr} not supplied by the overlay")
            return _const(firm[n.attr], d)
        raise Uncompilable(f"{d.name}: call.* not available")
    if isinstance(n, (ast.List, ast.Tuple)):
        return d.list_([_tr(e, d, firm) for e in n.elts])
    if isinstance(n, ast.BoolOp):
        if isinstance(n.op, ast.Or) and d.or_ is None:
            raise Uncompilable(f"{d.name}: 'or' has no inline form — split the rule")
        if isinstance(n.op, ast.And) and not d.paren_and:
            return d.and_.join(_tr(v, d, firm) for v in n.values)
        op = f" {d.and_} " if isinstance(n.op, ast.And) else f" {d.or_} "
        return "(" + op.join(_tr(v, d, firm) for v in n.values) + ")"
    if isinstance(n, ast.UnaryOp):
        if isinstance(n.op, ast.Not):
            return d.not_(_tr(n.operand, d, firm))
        return f"-{_tr(n.operand, d, firm)}"
    if isinstance(n, ast.BinOp):
        return f"({_tr(n.left, d, firm)} {_BIN_TXT[type(n.op)]} {_tr(n.right, d, firm)})"
    if isinstance(n, ast.Compare):
        parts = []
        left = _tr(n.left, d, firm)
        for op, comp in zip(n.ops, n.comparators):
            right = _tr(comp, d, firm)
            if isinstance(op, ast.In):
                parts.append(d.in_(left, right))
            elif isinstance(op, ast.NotIn):
                parts.append(d.not_in(left, right))
            else:
                sym = _CMP_TXT[type(op)]
                sym = d.eq if sym == "eq" else d.ne if sym == "ne" else sym
                parts.append(f"{left} {sym} {right}")
            left = right
        if len(parts) == 1:
            return parts[0]
        return d.and_.join(parts) if not d.paren_and else "(" + f" {d.and_} ".join(parts) + ")"
    if isinstance(n, ast.Call):
        fname = n.func.id  # type: ignore[attr-defined]
        if fname == "has" and d.has and n.args and isinstance(n.args[0], ast.Attribute):
            return d.has(_tr(n.args[0], d, firm))
        fn = d.functions.get(fname)
        if fn is None:
            raise Uncompilable(f"{d.name}: function {fname}() has no native equivalent")
        return fn([_tr(a, d, firm) for a in n.args])
    if isinstance(n, ast.Subscript):
        return f"{_tr(n.value, d, firm)}[{_tr(n.slice, d, firm)}]"
    if isinstance(n, ast.IfExp):
        return f"({_tr(n.test, d, firm)} ? {_tr(n.body, d, firm)} : {_tr(n.orelse, d, firm)})"
    raise Uncompilable(f"{d.name}: cannot translate {type(n).__name__}")


def split_tool(tool: str) -> tuple[str | None, str]:
    """'custodian.place_trade' -> ('custodian', 'place_trade'); 'custodian.*' -> ('custodian', '*')."""
    if "." in tool:
        t, _, name = tool.partition(".")
        return t, name
    return None, tool
