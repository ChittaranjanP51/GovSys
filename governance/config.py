"""Central configuration. Every value can be overridden via environment / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
# Keep all governance data on-prem: opt out of third-party usage telemetry.
os.environ.setdefault("MLFLOW_DISABLE_TELEMETRY", "true")
os.environ.setdefault("DO_NOT_TRACK", "1")


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    mode: str = _env("GOVSYS_MODE", "local")              # local | docker

    # --- Postgres ---
    pg_host: str = _env("PG_HOST", "127.0.0.1")
    pg_port: int = int(_env("PG_PORT", "5433"))
    pg_db: str = _env("PG_DB", "govsys")
    pg_superuser: str = _env("PG_SUPERUSER", "postgres")
    pg_superpass: str = _env("PG_SUPERPASS", "govsys_admin_pw")
    # One credential per least-privilege role.
    role_passwords: dict = field(default_factory=lambda: {
        "agent_order": _env("PG_PW_AGENT_ORDER", "order_pw"),
        "agent_billing": _env("PG_PW_AGENT_BILLING", "billing_pw"),
        "agent_admin": _env("PG_PW_AGENT_ADMIN", "admin_pw"),
        "gov_audit_writer": _env("PG_PW_AUDIT_WRITER", "audit_pw"),
        "gov_reader": _env("PG_PW_READER", "reader_pw"),
    })

    # --- Identity ---
    identity_provider: str = _env("IDENTITY_PROVIDER", "local")   # local | keycloak
    keycloak_url: str = _env("KEYCLOAK_URL", "http://localhost:8080")
    keycloak_realm: str = _env("KEYCLOAK_REALM", "govsys")
    keycloak_client_id: str = _env("KEYCLOAK_CLIENT_ID", "govsys-app")
    trust_domain: str = _env("SPIFFE_TRUST_DOMAIN", "govsys.local")
    token_ttl_s: int = int(_env("TOKEN_TTL_S", "3600"))
    agent_token_ttl_s: int = int(_env("AGENT_TOKEN_TTL_S", "120"))

    # --- Policy ---
    opa_url: str = _env("OPA_URL", "http://127.0.0.1:8181")

    # --- Model governance ---
    mlflow_uri: str = _env("MLFLOW_TRACKING_URI", f"sqlite:///{(ROOT / 'data' / 'mlflow.db').as_posix()}")
    registered_model: str = _env("GOVERNED_MODEL_NAME", "govsys-chat-llm")
    model_alias: str = _env("GOVERNED_MODEL_ALIAS", "production")

    # --- LLM runtime ---
    ollama_url: str = _env("OLLAMA_URL", "http://127.0.0.1:11434")
    llm_enabled: bool = _bool("LLM_ENABLED", True)
    llm_timeout_s: float = float(_env("LLM_TIMEOUT_S", "90"))

    # --- Observability ---
    langfuse_host: str = _env("LANGFUSE_HOST", "")
    langfuse_public_key: str = _env("LANGFUSE_PUBLIC_KEY", "")
    langfuse_secret_key: str = _env("LANGFUSE_SECRET_KEY", "")

    # --- Paths ---
    data_dir: Path = ROOT / "data"
    logs_dir: Path = ROOT / "logs"
    reports_dir: Path = ROOT / "reports"
    opa_policy_dir: Path = ROOT / "infra" / "opa" / "policies"

    def dsn(self, role: str | None = None) -> str:
        if role is None:
            user, pw = self.pg_superuser, self.pg_superpass
        else:
            user, pw = role, self.role_passwords[role]
        return f"host={self.pg_host} port={self.pg_port} dbname={self.pg_db} user={user} password={pw}"


settings = Settings()
for _d in (settings.data_dir, settings.logs_dir, settings.reports_dir):
    _d.mkdir(parents=True, exist_ok=True)
