"""Pack loader. YAML in, validated Pack out.

Loader rejects (raises PackError) any rule missing ``controls`` or
``examiner_asks`` — this is the product, not a nicety.
"""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from regent.core.match import ExpressionError, compile_expression, expression_firm_keys
from regent.core.models import ApprovalSpec, Pack, Rule, sha256_hex


class PackError(ValueError):
    pass


_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")


def parse_duration(v: Any) -> timedelta:
    if isinstance(v, timedelta):
        return v
    if isinstance(v, (int, float)):
        return timedelta(seconds=v)
    m = _DURATION.match(str(v))
    if not m:
        raise PackError(f"bad duration {v!r} (use e.g. 10m, 2h, 30s)")
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


def _approval(d: dict[str, Any] | None) -> ApprovalSpec | None:
    if not d:
        return None
    approvers = d.get("approvers", [])
    if isinstance(approvers, str):
        approvers = [approvers]
    escalate = d.get("escalate_to", [])
    if isinstance(escalate, str):
        escalate = [escalate]
    wf = d.get("workflow", "single")
    if wf not in ("single", "four_eyes"):
        raise PackError(f"unknown workflow {wf!r}")
    return ApprovalSpec(workflow=wf, approvers=tuple(approvers), attest=d.get("attest"),
                        grant_ttl=parse_duration(d.get("grant_ttl", "10m")), escalate_to=tuple(escalate),
                        sla=parse_duration(d.get("sla", "30m")), sod=bool(d.get("sod", True)),
                        on_sla_expiry=str(d.get("on_sla_expiry", "deny_and_log")))


def _rule(d: dict[str, Any], pack_name: str) -> Rule:
    for req in ("id", "tool", "controls", "examiner_asks"):
        if not d.get(req):
            raise PackError(f"{pack_name}: rule {d.get('id', '?')} missing required field {req!r}")
    controls = d["controls"]
    if isinstance(controls, str):
        controls = [controls]
    if not all(isinstance(c, str) and c.strip() for c in controls):
        raise PackError(f"{pack_name}: rule {d['id']} controls must be non-empty strings")
    for key in ("allow_if", "hold_if", "deny_if"):
        if d.get(key):
            try:
                compile_expression(str(d[key]))
            except ExpressionError as e:
                raise PackError(f"{pack_name}: rule {d['id']} {key}: {e}") from e
    if not any(d.get(k) for k in ("allow_if", "hold_if", "deny_if")):
        raise PackError(f"{pack_name}: rule {d['id']} has no allow_if/hold_if/deny_if")
    approval = _approval(d.get("approval"))
    if d.get("hold_if") and approval is None and not d.get("no_override"):
        raise PackError(f"{pack_name}: rule {d['id']} has hold_if but no approval block")
    if d.get("no_override") and approval is not None:
        raise PackError(f"{pack_name}: rule {d['id']} is no_override and cannot have an approval path")
    return Rule(id=str(d["id"]), tool=str(d["tool"]), controls=tuple(controls), examiner_asks=str(d["examiner_asks"]),
                description=str(d.get("description", "")), allow_if=d.get("allow_if"), hold_if=d.get("hold_if"),
                deny_if=d.get("deny_if"), approval=approval, no_override=bool(d.get("no_override", False)),
                priority=int(d.get("priority", 100)))


def load_pack_text(text: str, source_path: str | None = None) -> Pack:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict) or "pack" not in data:
        raise PackError(f"{source_path or '<text>'}: top-level 'pack:' is required")
    name = str(data["pack"])
    rules = [_rule(r, name) for r in data.get("rules", [])]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise PackError(f"{name}: duplicate rule ids")
    controls = {str(k): str(v) for k, v in (data.get("controls") or {}).items()}
    firm_required = data.get("firm_overlay_required") or []
    if isinstance(firm_required, str):
        firm_required = [firm_required]
    return Pack(name=name, version=str(data.get("version", name.rsplit("/", 1)[-1])), rules=rules,
                description=str(data.get("description", "")), controls=controls, source_path=source_path,
                source_hash=sha256_hex(text), firm=dict(data.get("firm") or {}),
                firm_keys_required=tuple(str(k) for k in firm_required),
                exam_requests=list(data.get("exam_requests") or []))


def firm_keys_referenced(pack: Pack) -> dict[str, list[str]]:
    """firm.<key> -> rule ids that reference it."""
    out: dict[str, list[str]] = {}
    for r in pack.rules:
        for expr in (r.allow_if, r.hold_if, r.deny_if):
            if expr:
                for k in expression_firm_keys(expr):
                    out.setdefault(k, []).append(r.id)
    return out


def load_firm_overlay(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(data, dict) or "firm" not in data or not isinstance(data["firm"], dict):
        raise PackError(f"{path}: a firm overlay is a YAML file with a top-level 'firm:' mapping")
    return dict(data["firm"])


def apply_firm_overlay(pack: Pack, firm: dict[str, Any] | None, source: str | None = None) -> Pack:
    """Merge overlay values into the pack and enforce that every referenced / required firm key
    is supplied. Thresholds never live in the pack, so a missing overlay is a hard error."""
    if firm:
        pack.firm.update(firm)
    referenced = firm_keys_referenced(pack)
    missing = sorted((set(referenced) | set(pack.firm_keys_required)) - set(pack.firm))
    if missing:
        where = f" (overlay: {source})" if source else " (no overlay given: pass --firm-overlay <file> or add firm.yaml to the pack dir)"
        detail = ", ".join(f"{k} [{', '.join(referenced.get(k, ['required']))}]" for k in missing)
        raise PackError(f"{pack.name}: firm overlay missing keys{where}: {detail}")
    return pack


def load_pack(path: str | Path, firm: str | Path | dict[str, Any] | None = None) -> Pack:
    """Load one pack. ``path`` is a YAML file or a directory of rule files (merged, sorted by name).

    Firm overlay resolution: ``firm`` argument (path or dict) > ``firm.yaml`` in the pack
    directory > error if any rule references ``firm.<key>``. ``firm.example.yaml`` is never
    picked up implicitly; pass it explicitly for demos and tests.
    """
    p = Path(path)
    overlay: dict[str, Any] | None = None
    overlay_src: str | None = None
    if isinstance(firm, dict):
        overlay, overlay_src = firm, "<dict>"
    elif firm is not None:
        overlay, overlay_src = load_firm_overlay(firm), str(firm)
    if p.is_dir():
        files = sorted(f for f in p.iterdir() if f.suffix in (".yaml", ".yml") and not f.name.startswith("firm"))
        if not files:
            raise PackError(f"no rule yaml in {p}")
        packs = [load_pack_text(f.read_text(), str(f)) for f in files]
        base = packs[0]
        for other in packs[1:]:
            if other.name != base.name:
                raise PackError(f"{p}: mixed pack names {base.name} vs {other.name}")
            base.rules.extend(other.rules)
            base.controls.update(other.controls)
            base.firm.update(other.firm)
            base.exam_requests.extend(other.exam_requests)
        base.source_path = str(p)
        base.source_hash = sha256_hex("".join(f.read_text() for f in files))
        ids = [r.id for r in base.rules]
        if len(ids) != len(set(ids)):
            raise PackError(f"{base.name}: duplicate rule ids across files")
        if overlay is None and (p / "firm.yaml").exists():
            overlay, overlay_src = load_firm_overlay(p / "firm.yaml"), str(p / "firm.yaml")
    else:
        base = load_pack_text(p.read_text(), str(p))
        if overlay is None and (p.parent / "firm.yaml").exists():
            overlay, overlay_src = load_firm_overlay(p.parent / "firm.yaml"), str(p.parent / "firm.yaml")
    return apply_firm_overlay(base, overlay, overlay_src)


def load_packs(paths: list[str | Path], firm: str | Path | dict[str, Any] | None = None) -> list[Pack]:
    return [load_pack(p, firm) for p in paths]
