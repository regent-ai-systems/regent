"""Compiler contract tests. CEL is validated against the real agentgateway binary when AGENTGATEWAY is set."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest
import yaml

from regent.compilers.cedar import CedarCompiler
from regent.compilers.cel import CELCompiler, agentgateway_config
from regent.compilers.rego import RegoCompiler

AG = os.environ.get("AGENTGATEWAY") or shutil.which("agentgateway")


def test_cel_routes_arg_rules_to_pds(ria):
    res = CELCompiler().compile(ria)
    assert "RIA-TRD-001" in res.pds_rule_ids and "RIA-DAT-005" in res.pds_rule_ids
    assert "RIA-REC-009" in res.native_rule_ids and "RIA-REC-010" in res.pds_rule_ids  # -010 now reads envelope_status
    doc = yaml.safe_load(res.text.split("# Rule map")[0])
    rules = doc["policies"]["mcpAuthorization"]["rules"]
    assert 'mcp.tool.target == "custodian" && mcp.tool.name == "place_trade"' in rules
    assert not any("delete" in r for r in rules)  # denied natively by omission
    assert doc["policies"]["extAuthz"]["includeRequestBody"]["maxRequestBytes"] == 65536
    assert "mcp.tool.arguments" not in res.text  # never emitted: not available at authz time


def test_cel_native_conditions(dev):
    res = CELCompiler().compile(dev)
    rules = yaml.safe_load(res.text.split("# Rule map")[0])["policies"]["mcpAuthorization"]["rules"]
    assert 'mcp.tool.target == "github" && mcp.tool.name.matches("^get_.*$")' in rules
    assert "DEV-GH-001" in res.native_rule_ids and "DEV-FS-004" in res.pds_rule_ids


def test_cedar_emits_forbid_and_permit(ria):
    res = CedarCompiler().compile(ria)
    assert 'forbid(principal, action, resource) when { action == Action::"custodian.place_trade"' in res.text
    assert "context.grant == true" in res.text
    assert '["option", "options", "margin"].contains(context.args.security_type)' in res.text
    assert "context.args has client_consent_id" in res.text
    assert '["ACME", "BIGCO", "CUSIP-000000000"].contains(context.args.security_id)' in res.text  # firm constants inlined
    assert "context.args.notional_usd > 250000" in res.text


def test_rego_structure(ria):
    res = RegoCompiler().compile(ria)
    assert "package regent" in res.text and "import rego.v1" in res.text
    assert 'deny["RIA-DAT-005"] if {' in res.text and "regent_pii(" in res.text
    assert "\t;" not in res.text  # conjunctions are newline-joined, never inline ';' inside parens


@pytest.mark.skipif(not AG, reason="set AGENTGATEWAY=/path/to/binary to validate CEL against the real gateway")
@pytest.mark.parametrize("fixture", ["ria", "dev"])
def test_cel_full_config_validates_with_real_agentgateway(request, fixture):
    packs = request.getfixturevalue(fixture)
    targets = [{"name": n, "stdio": {"cmd": "true", "args": []}} for n in
               sorted({r.tool.split(".")[0] for p in packs for r in p.rules if "*" not in r.tool.split(".")[0]})]
    text = agentgateway_config(packs, targets, 3000)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
    r = subprocess.run([AG, "-f", f.name, "--validate-only"], capture_output=True, text=True)
    assert r.returncode == 0, (r.stdout + r.stderr)[:500]
