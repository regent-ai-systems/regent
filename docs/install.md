# Install and run (Stage 0: local, self-hosted)

## Requirements

* Python 3.11 or 3.12
* An [agentgateway](https://github.com/agentgateway/agentgateway/releases) binary (v1.5.0 is what v0.1 was verified against) — or none, for the in-process / stdio-shim paths
* MCP servers you want to govern (stdio or HTTP), federated through agentgateway

## 1. Install Regent

```bash
git clone <this repo> regent && cd regent
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
regent --version
regent lint packs/ria packs/dev_default
```

## 2. Compile the pack for your gateway

Describe your MCP targets (names must match what you give agentgateway):

```yaml
# targets.yaml
- name: custodian
  stdio: { cmd: python3, args: ["path/to/custodian_server.py"] }
- name: email
  mcp:   { host: https://mcp.example.com/email }
```

```bash
regent compile --pack packs/ria --firm-overlay packs/ria/firm.yaml --dialect cel --full --targets-file targets.yaml \
    --pds localhost:9000 -o agentgateway.yaml --validate ./agentgateway
```

The emitted config carries an `mcpAuthorization` allow-list (native, cheap rules), an `extAuthz` block pointing at the Regent PDS with `includeRequestBody`, and a `jwtAuth` block **you must fill in** with your IdP's issuer/audience/JWKS. Without JWT auth the PDS sees every call as `anonymous`, which the RIA pack denies (no assigned accounts).

Claims the RIA pack expects on the token: `sub` (user), `azp` or `agent` (workload), `roles` (list), `assigned_accounts` (list), `approved_templates` (list). Options approval is an attribute of the *account* (`args.account_options_approved`), not of the principal. Rename in the pack if your IdP uses different claim names.

The RIA pack also needs a **firm overlay** — copy `packs/ria/firm.example.yaml` to `packs/ria/firm.yaml` (git-ignored) and set the thresholds, restricted list and secure channels; every command below accepts `--firm-overlay <file>` instead.

## 3. Run the PDS

```bash
regent serve --pack packs/ria --firm-overlay packs/ria/firm.yaml --db /var/lib/regent/regent.db \
    --grpc-port 9000 --http-port 9100 \
    --target custodian --target email          # agentgateway target names, for tool-name splitting
    # --slack-webhook https://hooks.slack.com/services/…   optional hold announcements
```

Bind `--host` to a private interface. The PDS trusts the gateway; nothing else should be able to reach ports 9000/9100. Set `REGENT_DEBUG=1` to log every ext_authz check.

## 4. Run agentgateway

```bash
./agentgateway -f agentgateway.yaml
```

Point agents at `http://<gateway>:3000/mcp` with a bearer token. Calls that need approval come back as HTTP 403 with a JSON body `{"verdict": "hold", "hold_id": …, "retry_after_s": 5}`; the agent (or its harness) re-issues the identical call after approval.

## 5. Approve holds

```bash
regent approve --list
regent approve hold_… --as maria --role trading_supervisor --attest
```

Or `POST /v1/holds/{id}/approve` on the admin port from a Slack/Teams action handler.

## 6. Audit stream and evidence

Have agentgateway export traces/logs to Regent's OTLP receiver, or feed it JSONL:

```bash
regent ingest --pack packs/ria --db /var/lib/regent/regent.db --source otlp --port 4318
# agentgateway.yaml:  config: { tracing: { otlpEndpoint: http://localhost:4318 } }   (check your version's key)
```

Then, per period:

```bash
regent verify   --db /var/lib/regent/regent.db
regent evidence --db /var/lib/regent/regent.db --pack packs/ria --from 2026-07-01 --to 2026-10-01 \
    --firm "Your RIA LLC" --reachable tools.txt -o q3-evidence
```

`tools.txt` is one tool per line (`target.tool`) — everything reachable through the gateway. Regent reports the ones no rule governs as coverage gaps.

## No gateway

* In-process (any Python host, the AGT plugin seam): `regent.runtimes.agt_plugin.RegentGuard` — see `examples/agt-inprocess-demo/`.
* stdio shim between a client and one server: `regent shim --pack packs/dev_default -- npx -y @modelcontextprotocol/server-filesystem /data`

## Upgrading agentgateway

Re-run `regent compile … --validate ./agentgateway` and the test suite with `AGENTGATEWAY=./agentgateway pytest -q`. The CEL variables, ext_authz field placement and filter-metadata delivery are the things most likely to move between gateway versions; the tests cover all three.
