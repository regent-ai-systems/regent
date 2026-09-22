"""Four fake MCP servers for the RIA demo, one process each, selected by argv[1]:

    python demo_servers.py custodian | crm | email | esign

They do nothing real — each tool returns a JSON echo — but they expose the exact
tool names the RIA pack governs, so the gateway + PDS path is exercised end to end.
"""
from __future__ import annotations

import json
import sys

from mcp.server.fastmcp import FastMCP

which = sys.argv[1] if len(sys.argv) > 1 else "custodian"
mcp = FastMCP(which)


def _ok(**kw) -> str:
    return json.dumps({"server": which, "ok": True, **kw})


if which == "custodian":

    @mcp.tool()
    def place_trade(account: str, security_id: str, notional_usd: float,
                    order_terms: dict,                       # {side, quantity, order_type: market|limit, limit_price?, tif: day|gtc}
                    discretionary: bool,                     # firm holds trading discretion over this account
                    recommended_by: str,                     # person or model that recommended (204-2(a)(3))
                    placed_by: str,                          # "<agent-id> on behalf of <user>"
                    executing_broker: str,                   # executing broker/dealer or venue
                    client_instruction_id: str | None = None,  # required when discretionary is False
                    security_type: str = "equity",           # equity | etf | mutual_fund | option | margin | fixed_income
                    account_options_approved: bool = False,  # custodian options approval on the *account*
                    account_type: str = "client",            # client | employee | access_person | proprietary
                    capacity: str = "agency",                # agency | principal | agency_cross
                    client_consent_id: str | None = None,    # §206(3) per-transaction consent (principal)
                    cross_confirmation_id: str | None = None,  # 206(3)-2 per-transaction confirmation (agency cross)
                    model_deviation_pct: float | None = None,  # deviation from the account's model after this order
                    post_trade_concentration_pct: float | None = None,
                    is_first_trade_in_account: bool = False) -> str:
        """Place an order with the custodian. The argument set is the Rule 204-2(a)(3) order
        memorandum: the Regent RIA pack denies orders missing discretionary / recommended_by /
        placed_by / executing_broker / order_terms (RIA-REC-019)."""
        return _ok(order_id="ORD-DEMO-1", account=account, security_id=security_id, order_terms=order_terms,
                   notional_usd=notional_usd, executing_broker=executing_broker, discretionary=discretionary)

    @mcp.tool()
    def debit_fee(account: str, period: str, fee_bps: float, schedule_fee_bps: float, change_vs_prior_period_pct: float,
                  amount_usd: float) -> str:
        """Deduct the advisory fee for a billing period (fee deduction is custody)."""
        return _ok(fee_id="FEE-DEMO-1", account=account, amount_usd=amount_usd)

    @mcp.tool()
    def transfer_funds(account: str, amount_usd: float,
                       destination_type: str,                  # first_party | third_party
                       transfer_type: str,                     # journal | ach | wire
                       destination: str,
                       like_titled: bool = False,              # same-titled account at the same custodian
                       sloa_id: str | None = None,             # standing letter of authorization on file
                       sloa_all_seven_conditions_met: bool = False,
                       instructions_changed_days_ago: int | None = None) -> str:
        """Move money out of a client account (tiered by the RIA pack: journal/ACH like-titled flows,
        first-party wire held, third-party four-eyes with SLOA, recent instruction change always held)."""
        return _ok(transfer_id="TRF-DEMO-1", amount_usd=amount_usd, destination=destination)

    @mcp.tool()
    def get_positions(account: str) -> str:
        """Read positions (no rule in the RIA pack → deny by default; shows up as a coverage gap)."""
        return _ok(account=account, positions=[])

elif which == "crm":

    @mcp.tool()
    def get_contact(contact_id: str) -> str:
        """Read one contact."""
        return _ok(contact_id=contact_id)

    @mcp.tool()
    def export(segment: str, format: str = "csv") -> str:
        """Bulk-export client records."""
        return _ok(rows=1234, segment=segment)

    @mcp.tool()
    def delete_contact(contact_id: str) -> str:
        """Delete a contact (never allowed through an agent)."""
        return _ok(deleted=contact_id)

elif which == "email":

    @mcp.tool()
    def send(to: list[str], subject: str, body: str, archived: bool = True,
             audience: str = "client",                          # client | prospect
             offers_services: bool = False, contains_performance: bool = False, contains_testimonial: bool = False,
             recipient_is_email_of_record: bool = False, channel: str = "smtp") -> str:
        """Send an email through the firm's archived channel."""
        return _ok(message_id="MSG-DEMO-1", to=to)

elif which == "esign":

    @mcp.tool()
    def send_envelope(template_id: str, signer_email: str, adv_delivery_receipt_id: str | None = None) -> str:
        """Send an e-sign envelope."""
        return _ok(envelope_id="ENV-DEMO-1", template_id=template_id)

    @mcp.tool()
    def void_envelope(envelope_id: str, envelope_status: str = "sent") -> str:
        """Void an envelope (denied for sent/completed envelopes; drafts may be voided)."""
        return _ok(voided=envelope_id)

else:
    raise SystemExit(f"unknown server {which}")

if __name__ == "__main__":
    mcp.run("stdio")
