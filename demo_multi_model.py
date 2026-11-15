"""
End-to-End Verification & Multi-Model Handoff Demo for RelayVault.
1. Starts the FastAPI REST server in-process via httpx.ASGITransport (zero network flake).
2. Simulates Agent 1 (Claude Opus 4.7) hitting a 5-hour usage cap and committing a task checkpoint
   containing sample Stripe/OpenAI credentials and an example customer email.
3. Proves that RelayVault scrubs all secrets into deterministic <RV_VAULT:...> tokens before storage.
4. Hands off the checkpoint to Agent 2 (Gemini 3.1 Pro / DeepSeek V4 / OpenAI).
   - When RELAYVAULT_DEMO_LIVE=1, uses configured provider API keys for live calls.
   - Always runs the full HTTP REST + SQLite Vault round-trip and verifies local secret rehydration.
"""

import asyncio
import json
import os
import tempfile
import httpx


async def call_live_openai_compatible(
    api_key: str, base_url: str, model: str, handoff_prompt: str, tools: list
) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "Continue the engineering task from the RelayVault handoff. Preserve <RV_VAULT:...> tokens verbatim.",
                    },
                    {"role": "user", "content": handoff_prompt},
                ],
                "temperature": 0.1,
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


async def call_live_anthropic(api_key: str, model: str, handoff_prompt: str) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 600,
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Continue the engineering task from this RelayVault checkpoint. "
                            "Write the Python webhook retry function preserving all <RV_VAULT:...> tokens verbatim:\n\n"
                            + handoff_prompt
                        ),
                    }
                ],
            },
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]


async def call_live_gemini(api_key: str, model: str, handoff_prompt: str) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
            json={
                "contents": [
                    {
                        "parts": [
                            {
                                "text": (
                                    "Continue the engineering task from this RelayVault checkpoint. "
                                    "Write the Python webhook retry function preserving all <RV_VAULT:...> tokens verbatim:\n\n"
                                    + handoff_prompt
                                )
                            }
                        ]
                    }
                ]
            },
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]


async def main() -> None:
    api_key = os.environ.setdefault("RELAYVAULT_API_KEY", "relayvault-demo-only-key")
    headers = {"Authorization": f"Bearer {api_key}"}
    rehydrate_headers = {**headers, "X-RelayVault-Local-Intent": "rehydrate"}
    if "RELAYVAULT_REHYDRATE_KEY" in os.environ:
        rehydrate_headers["X-RelayVault-Rehydrate-Key"] = os.environ["RELAYVAULT_REHYDRATE_KEY"]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://relayvault.local") as client:
        print("=== STEP 1: Verify Multi-Model Function-Calling Schemas (OpenAI/Claude/Gemini) ===")
        schema_resp = await client.get("/v1/schemas/tools")
        assert schema_resp.status_code == 200
        schemas = schema_resp.json()
        print("Exported schema families:", list(schemas.keys()))

        print("\n=== STEP 2: Model A (Claude Opus 4.7) Commits Task State Before 5-Hour Cap ===")
        raw_stripe_secret = "sk_" + "live_" + "51Nz9aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
        raw_openai_secret = "sk-proj-99887766554433221100aabbccddeeff"
        raw_email = "vip-billing-alerts@acme-corp.internal"
        raw_ip = "10.42.19.88"

        commit_payload = {
            "workspace_id": "acme-billing-webhook",
            "source_model": "claude-opus-4.7",
            "objective": f"Fix idempotent retry handler for Stripe webhooks targeting internal node {raw_ip} and alerting {raw_email}.",
            "locked_decisions": [
                "Use exponential backoff with full jitter on HTTP 429 and 503.",
                "Store idempotency keys in Redis with 24h TTL.",
            ],
            "failed_approaches": [
                "Do NOT use synchronous time.sleep() inside the FastAPI event loop (caused worker starvation)."
            ],
            "artifacts": {
                "config.py": (
                    f"STRIPE_API_KEY = '{raw_stripe_secret}'\n"
                    f"FALLBACK_LLM_KEY = '{raw_openai_secret}'\n"
                    f"INTERNAL_WEBHOOK_HOST = 'http://{raw_ip}:8080/hooks'\n"
                    f"ALERT_RECIPIENT = '{raw_email}'\n"
                )
            },
            "next_steps": [
                "Write async dispatch_webhook() using config.py constants without exposing raw credentials."
            ],
            "branch": "main",
        }

        commit_resp = await client.post("/v1/checkpoints/commit", headers=headers, json=commit_payload)
        assert commit_resp.status_code == 200, commit_resp.text
        commit_data = commit_resp.json()
        print(json.dumps(commit_data, indent=2))
        assert commit_data["redactions_applied"] == 6, "Expected all 6 secret/PII occurrences to be vaulted!"

        print("\n=== STEP 3: Model B (DeepSeek V4 Pro / Gemini 3.1 Pro) Checks Out Redacted Handoff ===")
        checkout_resp = await client.post(
            "/v1/checkpoints/checkout",
            headers=headers,
            json={"workspace_id": "acme-billing-webhook", "branch": "main", "target_model": "deepseek-v4-pro"},
        )
        assert checkout_resp.status_code == 200
        handoff = checkout_resp.json()
        handoff_prompt = handoff["synthesized_handoff_prompt"]
        print(handoff_prompt)

        # Guarantee zero raw secrets exist in the handoff payload sent to Model B
        assert raw_stripe_secret not in handoff_prompt
        assert raw_openai_secret not in handoff_prompt
        assert raw_email not in handoff_prompt
        assert raw_ip not in handoff_prompt
        print("\n[VERIFIED] Zero raw secrets or PII exist in the cross-model handoff payload.")

        # Execute live calls if provider API keys are configured in environment
        live_outputs = []
        if os.environ.get("RELAYVAULT_DEMO_LIVE") == "1" and os.environ.get("ANTHROPIC_API_KEY"):
            out = await call_live_anthropic(os.environ["ANTHROPIC_API_KEY"], "claude-3-7-sonnet-latest", handoff_prompt)
            live_outputs.append(("Anthropic Claude", out))
        if os.environ.get("RELAYVAULT_DEMO_LIVE") == "1" and os.environ.get("GEMINI_API_KEY"):
            out = await call_live_gemini(os.environ["GEMINI_API_KEY"], "gemini-2.5-flash", handoff_prompt)
            live_outputs.append(("Google Gemini", out))
        if os.environ.get("RELAYVAULT_DEMO_LIVE") == "1" and os.environ.get("OPENAI_API_KEY"):
            out = await call_live_openai_compatible(
                os.environ["OPENAI_API_KEY"], "https://api.openai.com/v1", "gpt-4o-mini", handoff_prompt, schemas["openai_deepseek_kimi_grok"]
            )
            live_outputs.append(("OpenAI", out))
        if os.environ.get("RELAYVAULT_DEMO_LIVE") == "1" and os.environ.get("DEEPSEEK_API_KEY"):
            out = await call_live_openai_compatible(
                os.environ["DEEPSEEK_API_KEY"], "https://api.deepseek.com/v1", "deepseek-chat", handoff_prompt, schemas["openai_deepseek_kimi_grok"]
            )
            live_outputs.append(("DeepSeek", out))

        if live_outputs:
            for provider_name, model_code in live_outputs:
                print(f"\n=== Live Output from {provider_name} (Using Vault Tokens) ===\n{model_code[:400]}...")
                rehydrate_resp = await client.post(
                    "/v1/vault/rehydrate",
                    headers=rehydrate_headers,
                    json={"workspace_id": "acme-billing-webhook", "text_with_vault_tokens": model_code},
                )
                rehydrated = rehydrate_resp.json()
                print(f"[{provider_name}] Rehydrated {rehydrated['tokens_rehydrated']} vaulted secrets locally.")
        else:
            # Deterministic verification of Model B output containing the vaulted tokens from config.py
            redacted_config_artifact = handoff["artifacts"]["config.py"]
            model_b_generated_code = (
                "import httpx\n\n"
                + redacted_config_artifact
                + "\nasync def dispatch_webhook(payload: dict):\n"
                + "    async with httpx.AsyncClient() as c:\n"
                + "        return await c.post(INTERNAL_WEBHOOK_HOST, headers={'Authorization': f'Bearer {STRIPE_API_KEY}'}, json=payload)\n"
            )
            print("\n=== STEP 4: Local Rehydration of Model B Output ===")
            rehydrate_resp = await client.post(
                "/v1/vault/rehydrate",
                headers=rehydrate_headers,
                json={"workspace_id": "acme-billing-webhook", "text_with_vault_tokens": model_b_generated_code},
            )
            assert rehydrate_resp.status_code == 200
            rehydrated_data = rehydrate_resp.json()
            print(f"Tokens Rehydrated Locally: {rehydrated_data['tokens_rehydrated']}")
            print("Final Rehydrated Code Ready for Local Execution:\n")
            print(rehydrated_data["rehydrated_text"])
            assert raw_stripe_secret in rehydrated_data["rehydrated_text"]
            assert raw_openai_secret in rehydrated_data["rehydrated_text"]
            assert raw_email in rehydrated_data["rehydrated_text"]
            assert raw_ip in rehydrated_data["rehydrated_text"]
            print("[VERIFIED] Local rehydration restored all 4 sample values accurately.")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="relayvault-demo-") as directory:
        os.environ["RELAYVAULT_HOME"] = directory
        from relayvault.rest_api import app, engine, get_universal_tool_schemas

        asyncio.run(main())
