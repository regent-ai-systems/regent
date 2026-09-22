from __future__ import annotations

from pathlib import Path

import pytest

from regent.core.models import Principal, ToolCall
from regent.core.packs import load_packs

ROOT = Path(__file__).resolve().parent.parent


FIRM = ROOT / "packs" / "ria" / "firm.example.yaml"

# A complete Rule 204-2(a)(3) order memorandum, discretionary, routine. Tests override single keys.
TRADE = {"account": "A1", "security_id": "VTI", "notional_usd": 12000,
         "order_terms": {"side": "buy", "quantity": 40, "order_type": "market", "tif": "day"},
         "discretionary": True, "recommended_by": "model:core-60-40", "placed_by": "portfolio-assistant on behalf of agent7",
         "executing_broker": "CUSTODIAN-BD"}

# One-to-one client correspondence through the archived channel.
EMAIL = {"to": ["client@example.com"], "subject": "Hello", "body": "Quarterly review is Tuesday.", "archived": True}


@pytest.fixture(scope="session")
def ria():
    return load_packs([ROOT / "packs" / "ria"], FIRM)


@pytest.fixture(scope="session")
def dev():
    return load_packs([ROOT / "packs" / "dev_default"])


@pytest.fixture
def trader():
    return Principal(user="agent7", agent="portfolio-assistant", roles=("trader",),
                     claims={"assigned_accounts": ["A1", "A2"], "approved_templates": ["T1"]})


def call(tool: str, args: dict, principal: Principal, **kw) -> ToolCall:
    return ToolCall(tool=tool, args=args, principal=principal, **kw)


@pytest.fixture
def mk(trader):
    return lambda tool, args, p=None, **kw: call(tool, args, p or trader, **kw)
