"""Generic webhook + Slack/Teams incoming-webhook notifiers.

All three post the hold; approvals come back through the PDS admin API
(``POST /v1/holds/{id}/approve``). Interactive Slack buttons (Block Kit
callbacks) are the weeks-2–4 item and land in slack.py when the Slack app
exists; the incoming-webhook path below needs no app install.
"""
from __future__ import annotations

import json

import aiohttp

from regent.core.models import Hold


def _summary(hold: Hold, admin_url: str) -> str:
    a = hold.approval
    lines = [f"*Regent approval required* `{hold.id}`",
             f"tool `{hold.call.tool}` · requester `{hold.call.principal.user}` · agent `{hold.call.principal.agent}`",
             f"rule `{hold.rule_id}` · workflow `{a.workflow}` · approvers `{', '.join(a.approvers) or 'any'}`",
             f"args: `{json.dumps(hold.call.args)[:400]}`"]
    if a.attest:
        lines.append(f"attestation on approve: _{a.attest}_")
    lines.append(f"resolve: `regent approve {hold.id} --as <you> --role <role> --attest --pds {admin_url}`")
    return "\n".join(lines)


class WebhookNotifier:
    name = "webhook"

    def __init__(self, url: str, admin_url: str = "http://localhost:9100", headers: dict[str, str] | None = None):
        self.url, self.admin_url, self.headers = url, admin_url, headers or {}

    async def notify(self, hold: Hold) -> None:
        from regent.stores.sqlite import hold_to_dict
        async with aiohttp.ClientSession() as s:
            async with s.post(self.url, json={"hold": hold_to_dict(hold), "admin_url": self.admin_url},
                              headers=self.headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                r.raise_for_status()


class SlackNotifier(WebhookNotifier):
    name = "slack"

    async def notify(self, hold: Hold) -> None:
        async with aiohttp.ClientSession() as s:
            async with s.post(self.url, json={"text": _summary(hold, self.admin_url)},
                              timeout=aiohttp.ClientTimeout(total=10)) as r:
                r.raise_for_status()


class TeamsNotifier(WebhookNotifier):
    name = "teams"

    async def notify(self, hold: Hold) -> None:
        async with aiohttp.ClientSession() as s:
            async with s.post(self.url, json={"text": _summary(hold, self.admin_url).replace("*", "**")},
                              timeout=aiohttp.ClientTimeout(total=10)) as r:
                r.raise_for_status()
