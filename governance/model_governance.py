"""Model governance: only LLMs approved in the MLflow Model Registry may serve traffic.

Each registered model version carries governance tags:
  ollama_model       runtime model the version maps to
  approval_status    approved | pending_review | rejected
  risk_tier          low | medium | high
  eval_passed        true | false   (offline evaluation gate)
  approved_by        accountable approver
The `production` alias selects the serving version. The gate checks the alias target
(or an explicitly requested model) and refuses anything not fully approved.
"""
from __future__ import annotations

import time

import httpx

from .config import settings

REQUIRED = {"approval_status": "approved", "eval_passed": "true"}
ALLOWED_RISK = {"low", "medium"}

_cache: dict = {"at": 0.0, "versions": None}


def _client():
    import mlflow
    from mlflow import MlflowClient
    mlflow.set_tracking_uri(settings.mlflow_uri)
    mlflow.set_registry_uri(settings.mlflow_uri)
    return MlflowClient()


def registry_versions(force: bool = False) -> list[dict]:
    if force or _cache["versions"] is None or time.time() - _cache["at"] > 30:
        c = _client()
        rm = c.get_registered_model(settings.registered_model)
        aliases = {v: a for a, v in (rm.aliases or {}).items()}
        vs = c.search_model_versions(f"name='{settings.registered_model}'")
        _cache["versions"] = sorted(
            [{"version": v.version, "alias": aliases.get(v.version, ""), **dict(v.tags)} for v in vs],
            key=lambda d: int(d["version"]))
        _cache["at"] = time.time()
    return _cache["versions"]


def gate(requested_model: str | None = None) -> tuple[bool, str, dict]:
    """Return (approved, detail, evidence). `requested_model` is an Ollama model name;
    None means 'whatever the production alias points to'."""
    try:
        versions = registry_versions()
    except Exception as e:  # noqa: BLE001 - registry down => fail closed
        return False, f"model registry unavailable (fail-closed): {e.__class__.__name__}", {}
    if requested_model:
        mv = next((v for v in versions if v.get("ollama_model") == requested_model), None)
        if mv is None:
            return False, f"'{requested_model}' is not registered in the model registry", {"requested": requested_model}
    else:
        mv = next((v for v in versions if v["alias"] == settings.model_alias), None)
        if mv is None:
            return False, f"no version carries alias '{settings.model_alias}'", {}
    problems = [f"{k}={mv.get(k)!r} (need {want!r})" for k, want in REQUIRED.items() if mv.get(k) != want]
    if mv.get("risk_tier") not in ALLOWED_RISK:
        problems.append(f"risk_tier={mv.get('risk_tier')!r} not in {sorted(ALLOWED_RISK)}")
    evidence = {"model": settings.registered_model, **mv}
    if problems:
        return False, f"v{mv['version']} ({mv.get('ollama_model')}) not approved: " + "; ".join(problems), evidence
    return True, f"v{mv['version']} ({mv['ollama_model']}) approved by {mv.get('approved_by', '?')}", evidence


def set_approval(version: str, status: str, approver: str) -> None:
    """Governance-board action (used from the dashboard by admins)."""
    c = _client()
    c.set_model_version_tag(settings.registered_model, version, "approval_status", status)
    c.set_model_version_tag(settings.registered_model, version, "approved_by", approver)
    registry_versions(force=True)


def healthy() -> bool:
    try:
        registry_versions()
        return True
    except Exception:  # noqa: BLE001
        return False


def ollama_models() -> list[str]:
    try:
        r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3)
        return [m["name"] for m in r.json().get("models", [])]
    except Exception:  # noqa: BLE001
        return []
