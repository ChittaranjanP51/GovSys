"""One-time setup (idempotent). Works for local and docker mode.

  1. (local) initialise + start the portable Postgres cluster
  2. create database, schema, least-privilege roles, seed data
  3. build the local IdP user store + signing keys
  4. register governed models in the MLflow Model Registry
  5. check Ollama has the approved model
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import psycopg  # noqa: E402

from governance import identity, model_governance  # noqa: E402
from governance.config import settings  # noqa: E402

SQL_DIR = ROOT / "infra" / "postgres"

MODEL_VERSIONS = [
    {
        "ollama_model": "phi3:latest",
        "tags": {"approval_status": "approved", "risk_tier": "medium", "eval_passed": "true",
                 "approved_by": "ai-governance-board", "intended_use": "internal staff assistant",
                 "eval_groundedness": "0.91", "eval_toxicity": "0.00", "license": "MIT",
                 "data_residency": "on-prem (Ollama)"},
        "card": "Phi-3 Mini 3.8B served locally via Ollama. Approved for internal support/billing/admin "
                "assistance. Not approved for customer-facing use or autonomous decisions.",
    },
    {
        "ollama_model": "gemma3:270m",
        "tags": {"approval_status": "rejected", "risk_tier": "high", "eval_passed": "false",
                 "approved_by": "ai-governance-board", "intended_use": "experimentation only",
                 "eval_groundedness": "0.48", "eval_toxicity": "0.01", "license": "Gemma ToU",
                 "rejection_reason": "groundedness below 0.80 threshold"},
        "card": "Gemma 3 270M. Rejected: hallucination rate too high on the order/billing eval set.",
    },
]


def step(msg: str) -> None:
    print(f"\n==> {msg}")


def reset_business_data() -> None:
    """Restore demo business data (orders, invoices, refunds). The audit log is never touched."""
    with psycopg.connect(settings.dsn(), autocommit=True) as c:
        c.execute("TRUNCATE billing.refunds, billing.invoices, sales.orders, sales.customers RESTART IDENTITY CASCADE")
        c.execute((SQL_DIR / "03_seed.sql").read_text(encoding="utf-8"))
    print("  business data restored to seed state (audit log preserved)")


def setup_database() -> None:
    admin = settings.dsn().replace(f"dbname={settings.pg_db}", "dbname=postgres")
    with psycopg.connect(admin, autocommit=True) as c:
        if not c.execute("SELECT 1 FROM pg_database WHERE datname = %s", (settings.pg_db,)).fetchone():
            c.execute(f'CREATE DATABASE "{settings.pg_db}"')
            print(f"  created database {settings.pg_db}")
    with psycopg.connect(settings.dsn(), autocommit=True) as c:
        for f in sorted(SQL_DIR.glob("*.sql")):
            c.execute(f.read_text(encoding="utf-8"))
            print(f"  applied {f.name}")
        for role, pw in settings.role_passwords.items():
            c.execute(psycopg.sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                psycopg.sql.Identifier(role), psycopg.sql.Literal(pw)))
        print(f"  set passwords for {len(settings.role_passwords)} least-privilege roles")


def setup_identity() -> None:
    identity.build_user_store()
    identity._idp_key()
    identity._workload_key()
    print("  IdP user store (PBKDF2) + RS256 signing keys ready in data/")


def setup_models() -> None:
    import mlflow
    from mlflow import MlflowClient
    mlflow.set_tracking_uri(settings.mlflow_uri)
    mlflow.set_registry_uri(settings.mlflow_uri)
    c = MlflowClient()
    name = settings.registered_model
    try:
        c.get_registered_model(name)
        print(f"  registered model '{name}' already exists - leaving approvals untouched")
        return
    except mlflow.exceptions.MlflowException:
        pass
    c.create_registered_model(name, description="LLMs permitted to serve GovSys agents. Governance tags gate runtime use.",
                              tags={"owner": "ai-governance-board", "system": "govsys"})
    mlflow.set_experiment("govsys-model-evaluations")
    for spec in MODEL_VERSIONS:
        with mlflow.start_run(run_name=f"eval-{spec['ollama_model']}") as run:
            mlflow.log_params({"ollama_model": spec["ollama_model"]})
            mlflow.log_metrics({"groundedness": float(spec["tags"]["eval_groundedness"]),
                                "toxicity": float(spec["tags"]["eval_toxicity"])})
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / "model_card.md"
                p.write_text(f"# Model card: {spec['ollama_model']}\n\n{spec['card']}\n", encoding="utf-8")
                mlflow.log_artifact(str(p), artifact_path="model_card")
            mv = c.create_model_version(name, source=f"{run.info.artifact_uri}/model_card", run_id=run.info.run_id,
                                        tags={"ollama_model": spec["ollama_model"], **spec["tags"]},
                                        description=spec["card"])
            print(f"  v{mv.version}: {spec['ollama_model']} -> {spec['tags']['approval_status']}")
    c.set_registered_model_alias(name, settings.model_alias, "1")
    print(f"  alias '{settings.model_alias}' -> v1")


def check_ollama() -> None:
    have = model_governance.ollama_models()
    if not have:
        print("  WARNING: Ollama not reachable - answers will use the deterministic template.")
        return
    for spec in MODEL_VERSIONS:
        print(f"  {spec['ollama_model']:<14} {'present' if spec['ollama_model'] in have else 'MISSING (ollama pull ' + spec['ollama_model'] + ')'}")


def main() -> None:
    if settings.mode == "local":
        step("Starting local Postgres")
        from scripts.services import start_postgres
        start_postgres()
    if "--reset-data" in sys.argv:
        step("Resetting demo business data")
        reset_business_data()
        return
    step("Database, schemas, least-privilege roles, seed data")
    setup_database()
    step("Identity provider")
    setup_identity()
    step("MLflow model registry")
    setup_models()
    step("Ollama runtime")
    check_ollama()
    print("\nBootstrap complete.")


if __name__ == "__main__":
    main()
