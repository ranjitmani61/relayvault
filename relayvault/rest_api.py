from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Security, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from relayvault.access import Principal, authenticate, verify_rehydration_key
from relayvault.engine import IntegrityError, RelayVaultEngine

app = FastAPI(
    title="RelayVault Task Checkpoints & Pattern Redaction API",
    version="0.2.0",
    description=(
        "Git-like task state checkpointing and reversible local PII/secret vault for seamless handoffs "
        "across OpenAI (ChatGPT), Anthropic (Claude), Google (Gemini), xAI (Grok), DeepSeek, and Moonshot (Kimi)."
    ),
)

security = HTTPBearer(auto_error=True)
engine = RelayVaultEngine()


def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> Principal:
    try:
        principal = authenticate(credentials.credentials)
    except (RuntimeError, ValueError, OSError):
        raise HTTPException(
            status_code=503, detail="HTTP authentication is not configured correctly"
        ) from None
    if principal is None:
        raise HTTPException(status_code=401, detail="Invalid Bearer API Key")
    return principal


@app.exception_handler(PermissionError)
async def permission_error(request, exc):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(ValueError)
async def validation_error(request, exc):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
async def request_error(request, exc):
    # Do not echo raw request values, which may contain credentials.
    return JSONResponse(status_code=422, content={"detail": "Invalid request schema"})


@app.exception_handler(IntegrityError)
async def integrity_error(request, exc):
    return JSONResponse(
        status_code=409, content={"detail": "Vault integrity check failed; local recovery required"}
    )


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CommitCheckpointRequest(StrictRequest):
    workspace_id: str = Field(..., description="Unique project or repo identifier, e.g. 'payments-service'")
    source_model: str = Field(
        ..., description="Model creating the checkpoint, e.g. 'claude-opus-4.7' or 'gpt-5.5'"
    )
    objective: str = Field(..., description="Core task objective and exact problem statement")
    locked_decisions: List[str] = Field(
        default_factory=list, description="Architectural choices already decided"
    )
    failed_approaches: List[str] = Field(default_factory=list, description="Approaches tried and rejected")
    artifacts: Dict[str, str] = Field(
        default_factory=dict, description="Map of filename/label to code or spec snippet"
    )
    next_steps: List[str] = Field(
        default_factory=list, description="Ordered list of immediate tasks for the next model"
    )
    branch: str = Field(default="main", description="Task branch name")
    parent_hash: Optional[str] = Field(default=None, description="Optional parent checkpoint commit hash")


class CheckoutHandoffRequest(StrictRequest):
    workspace_id: str = Field(..., description="Workspace identifier")
    branch: str = Field(default="main", description="Branch name")
    commit_hash: Optional[str] = Field(
        default=None, description="Specific commit hash, or None for branch HEAD"
    )
    target_model: Optional[str] = Field(
        default=None, description="Model receiving the handoff, e.g. 'deepseek-v4' or 'gemini-3.1-pro'"
    )


class RehydrateRequest(StrictRequest):
    workspace_id: str = Field(..., description="Workspace identifier")
    text_with_vault_tokens: str = Field(
        ..., description="Text or code containing RV_VAULT placeholder tokens"
    )


@app.get("/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok", "service": "relayvault", "version": "0.2.0"}


@app.post("/v1/checkpoints/commit", dependencies=[Depends(verify_api_key)])
def api_commit_checkpoint(
    req: CommitCheckpointRequest, principal: Principal = Depends(verify_api_key)
) -> Dict[str, Any]:
    principal.authorize(req.workspace_id, "write")
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
def api_checkout_handoff(
    req: CheckoutHandoffRequest, principal: Principal = Depends(verify_api_key)
) -> Dict[str, Any]:
    principal.authorize(req.workspace_id, "read")
    res = engine.checkout_handoff(
        workspace_id=req.workspace_id,
        branch=req.branch,
        commit_hash=req.commit_hash,
        target_model=req.target_model,
    )
    if not res:
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    return res


@app.post("/v1/vault/rehydrate", include_in_schema=False)
def api_rehydrate_output(
    req: RehydrateRequest,
    principal: Principal = Depends(verify_api_key),
    x_relayvault_local_intent: Optional[str] = Header(default=None),
    x_relayvault_rehydrate_key: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if x_relayvault_local_intent != "rehydrate":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Explicit local rehydration intent is required"
        )
    principal.authorize(req.workspace_id, "read")
    verify_rehydration_key(x_relayvault_rehydrate_key)
    restored, count = engine.rehydrate_text(req.workspace_id, req.text_with_vault_tokens)
    return {
        "workspace_id": req.workspace_id,
        "tokens_rehydrated": count,
        "rehydrated_text": restored,
    }


@app.get("/v1/checkpoints/{workspace_id}", dependencies=[Depends(verify_api_key)])
def api_list_checkpoints(
    workspace_id: str,
    branch: Optional[str] = None,
    limit: int = 20,
    principal: Principal = Depends(verify_api_key),
) -> Dict[str, Any]:
    principal.authorize(workspace_id, "read")
    return {
        "workspace_id": workspace_id,
        "checkpoints": engine.list_checkpoints(workspace_id=workspace_id, branch=branch, limit=limit),
    }


def get_universal_tool_schemas() -> Dict[str, Any]:
    """
    Exports native function-calling schemas compatible with:
    1. OpenAI / DeepSeek / Moonshot (Kimi) / xAI (Grok) Chat Completions API
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
