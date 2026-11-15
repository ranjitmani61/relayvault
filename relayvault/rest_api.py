import hmac
import os
from typing import Any, Dict, List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from relayvault.engine import RelayVaultEngine

app = FastAPI(
    title="RelayVault Cross-Model State & Zero-Trust Redaction API",
    version="0.1.0",
    description=(
        "Git-like task state checkpointing and reversible local PII/secret vault for seamless handoffs "
        "across OpenAI (ChatGPT), Anthropic (Claude), Google (Gemini), xAI (Grok), DeepSeek, and Moonshot (Kimi)."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=True)
engine = RelayVaultEngine()


def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    expected_key = os.environ.get("RELAYVAULT_API_KEY")
    if not expected_key:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="RELAYVAULT_API_KEY is not configured")
    provided_key = credentials.credentials
    if not hmac.compare_digest(provided_key.encode("utf-8"), expected_key.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Bearer API Key",
        )
    return provided_key


class CommitCheckpointRequest(BaseModel):
    workspace_id: str = Field(..., description="Unique project or repo identifier, e.g. 'payments-service'")
    source_model: str = Field(..., description="Model creating the checkpoint, e.g. 'claude-opus-4.7' or 'gpt-5.5'")
    objective: str = Field(..., description="Core task objective and exact problem statement")
    locked_decisions: List[str] = Field(default_factory=list, description="Architectural choices already decided")
    failed_approaches: List[str] = Field(default_factory=list, description="Approaches tried and rejected")
    artifacts: Dict[str, str] = Field(default_factory=dict, description="Map of filename/label to code or spec snippet")
    next_steps: List[str] = Field(default_factory=list, description="Ordered list of immediate tasks for the next model")
    branch: str = Field(default="main", description="Task branch name")
    parent_hash: Optional[str] = Field(default=None, description="Optional parent checkpoint commit hash")


class CheckoutHandoffRequest(BaseModel):
    workspace_id: str = Field(..., description="Workspace identifier")
    branch: str = Field(default="main", description="Branch name")
    commit_hash: Optional[str] = Field(default=None, description="Specific commit hash, or None for branch HEAD")
    target_model: Optional[str] = Field(default=None, description="Model receiving the handoff, e.g. 'deepseek-v4' or 'gemini-3.1-pro'")


class RehydrateRequest(BaseModel):
    workspace_id: str = Field(..., description="Workspace identifier")
    text_with_vault_tokens: str = Field(..., description="Text or code containing <RV_VAULT:TYPE:HASH> tokens")


@app.get("/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok", "service": "relayvault", "version": "0.1.0"}


@app.post("/v1/checkpoints/commit", dependencies=[Depends(verify_api_key)])
def api_commit_checkpoint(req: CommitCheckpointRequest) -> Dict[str, Any]:
    return engine.commit_checkpoint(
        workspace_id=req.workspace_id,
        source_model=req.source_model,
        objective=req.objective,
        locked_decisions=req.locked_decisions,
        failed_approaches=req.failed_approaches,
        artifacts=req.artifacts,
        next_steps=req.next_steps,
        branch=req.branch,
        parent_hash=req.parent_hash,
    )


@app.post("/v1/checkpoints/checkout", dependencies=[Depends(verify_api_key)])
def api_checkout_handoff(req: CheckoutHandoffRequest) -> Dict[str, Any]:
    res = engine.checkout_handoff(
        workspace_id=req.workspace_id,
        branch=req.branch,
        commit_hash=req.commit_hash,
        target_model=req.target_model,
    )
    if not res:
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    return res


@app.post("/v1/vault/rehydrate", dependencies=[Depends(verify_api_key)])
def api_rehydrate_output(
    req: RehydrateRequest,
    request: Request,
    x_relayvault_local_intent: Optional[str] = Header(default=None),
    x_relayvault_rehydrate_key: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if x_relayvault_local_intent != "rehydrate":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Explicit local rehydration intent is required")
    rehydrate_key = os.environ.get("RELAYVAULT_REHYDRATE_KEY")
    if rehydrate_key is not None:
        if not rehydrate_key:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="RELAYVAULT_REHYDRATE_KEY must not be empty")
        if x_relayvault_rehydrate_key is None or not hmac.compare_digest(
            x_relayvault_rehydrate_key.encode("utf-8"), rehydrate_key.encode("utf-8")
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid rehydration key")
    else:
        proxy_headers = ("x-forwarded-for", "x-real-ip", "forwarded", "cf-connecting-ip", "true-client-ip", "x-client-ip")
        if any(header in request.headers for header in proxy_headers):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Proxied requests require RELAYVAULT_REHYDRATE_KEY to be configured")
        if request.client is None or request.client.host not in ("127.0.0.1", "::1", "testclient"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Rehydration is restricted to loopback clients")
    restored, count = engine.rehydrate_text(req.workspace_id, req.text_with_vault_tokens)
    return {
        "workspace_id": req.workspace_id,
        "tokens_rehydrated": count,
        "rehydrated_text": restored,
    }


@app.get("/v1/checkpoints/{workspace_id}", dependencies=[Depends(verify_api_key)])
def api_list_checkpoints(workspace_id: str, branch: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
    return {
        "workspace_id": workspace_id,
        "checkpoints": engine.list_checkpoints(workspace_id=workspace_id, branch=branch, limit=limit),
    }


def get_universal_tool_schemas() -> Dict[str, Any]:
    """
    Exports native function-calling schemas compatible with:
    1. OpenAI / DeepSeek / Moonshot (Kimi) / xAI (Grok) Chat Completions & Responses API
    2. Anthropic Claude Messages API (tools input_schema)
    3. Google Gemini API (function_declarations)
    """
    commit_schema = CommitCheckpointRequest.model_json_schema()
    checkout_schema = CheckoutHandoffRequest.model_json_schema()
    for s in (commit_schema, checkout_schema):
        s.pop("title", None)

    tools_meta = [
        (
            "relayvault_commit_checkpoint",
            "Commit a redacted, content-addressable task state checkpoint before switching AI models or hitting rate limits.",
            commit_schema,
        ),
        (
            "relayvault_checkout_handoff",
            "Checkout the latest task state checkpoint and synthesized handoff briefing from a previous AI model.",
            checkout_schema,
        ),
    ]

    return {
        "openai_deepseek_kimi_grok": [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": desc,
                    "parameters": schema,
                },
            }
            for name, desc, schema in tools_meta
        ],
        "anthropic_claude": [
            {
                "name": name,
                "description": desc,
                "input_schema": schema,
            }
            for name, desc, schema in tools_meta
        ],
        "google_gemini": [
            {
                "function_declarations": [
                    {
                        "name": name,
                        "description": desc,
                        "parameters": schema,
                    }
                    for name, desc, schema in tools_meta
                ]
            }
        ],
    }


@app.get("/v1/schemas/tools")
def api_get_tool_schemas() -> Dict[str, Any]:
    return get_universal_tool_schemas()
