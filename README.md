# agentgateway + Prisma AIRS: proof of integration

Enterprise agentgateway (v2026.9.1) sends every LLM prompt and response to Prisma AIRS
AI Runtime (API Intercept) through the agentgateway Guardrail Webhook API. The AIRS verdict
is enforced at the gateway: allow passes, block rejects with 403, AIRS DLP masking rewrites
the content. If AIRS is unreachable, the gateway fails closed (503).

```
client -> agentgateway --(promptGuard webhook)--> airs-adapter --(x-pan-token)--> Prisma AIRS
                |                                                    /v1/scan/sync/request
                +--> LLM (Claude Haiku)  only if AIRS allows / after masking
```

## Files
- `airs-adapter.py`: webhook -> AIRS adapter, stdlib Python, about 150 lines. Scans the newest
  user turn as `prompt` (earlier turns as `context`) and each response choice as `response`.
- `mock-airs.py`: stand-in for the AIRS scan API with the documented request/response shape.
  Crude regex detection (injection phrases, SSN, card numbers, bad URLs).
- `manifests/airs-policy.yaml`: the integration itself, one `EnterpriseAgentgatewayPolicy`.
- `up.sh` / `test.sh`: build a kind cluster, then run the five checks.
- `demo.sh` / `demo_fmt.py`: the step-by-step live demo (see below).

## Run
Needs kind, kubectl, helm, an Anthropic API key, and a Solo Enterprise for agentgateway license.

    export ANTHROPIC_API_KEY=...
    export AGENTGATEWAY_LICENSE_KEY=...
    ./up.sh
    ./test.sh

Tear down: `kind delete cluster --name airs-poc`

## Live demo
`demo.sh` walks an audience through the integration one step at a time (press Enter to advance):

1. The gateway policy that wires in Prisma AIRS
2. A normal prompt: allowed and answered
3. A prompt injection: blocked with a 403, the model is never called
4. An SSN in the prompt: masked before the model sees it
5. A card number in the model's answer: masked before the client sees it
6. The audit trail: each prompt scan carries the calling user
7. AIRS taken down: the gateway fails closed, then AIRS is restored

Each step shows the request, what the client got back, and the AIRS verdict behind it.

    ./demo.sh                 # interactive
    DEMO_AUTO=1 ./demo.sh     # run straight through
    PORT=18999 ./demo.sh      # if the default local port (18765) is taken

## Go live against real Prisma AIRS
1. In Strata Cloud Manager, onboard an API Intercept app and create a security profile. Get the API key.
2. `kubectl -n prisma-airs create secret generic airs-api-key --from-literal=token=<x-pan-token> --dry-run=client -o yaml | kubectl apply -f -`
3. Set `AIRS_URL=https://service.api.aisecurity.paloaltonetworks.com` (or the regional
   endpoint) and `AIRS_PROFILE=<profile name>` on the `airs-adapter` Deployment. Delete `mock-airs`.
4. Allow egress from the adapter to the AIRS endpoint.

## Not covered yet
- Streaming (`promptGuard.streaming: Enabled`). Reject works on streams; mask does not.
- MCP tool calls (`tool_event` scanning). That goes through agentgateway's ExtMCP guardrail, a separate gRPC hook.
- Real AIRS. The masked-data field shape (`prompt_masked_data.data`) comes from PANW docs and has not been checked against a live tenant.
- AIRS field limits (prompt 10K chars, response 20K, context 100K, per pan.dev). Long histories get cut to the last 100K chars of context.
