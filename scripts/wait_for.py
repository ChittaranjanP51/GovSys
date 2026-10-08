"""Docker mode: wait until Keycloak, OPA and MLflow answer before bootstrapping."""
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from governance.config import settings  # noqa: E402

targets = {"OPA": f"{settings.opa_url}/health", "MLflow": f"{settings.mlflow_uri}/health"}
if settings.identity_provider == "keycloak":
    targets["Keycloak"] = f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/.well-known/openid-configuration"

deadline = time.time() + 300
for name, url in targets.items():
    while True:
        try:
            if httpx.get(url, timeout=3).status_code == 200:
                print(f"{name} ready")
                break
        except httpx.HTTPError:
            pass
        if time.time() > deadline:
            sys.exit(f"{name} not ready at {url}")
        time.sleep(3)
