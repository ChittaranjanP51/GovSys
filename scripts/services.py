"""Local (no-Docker) service manager: Postgres, OPA, MLflow UI, Streamlit dashboard.

    python scripts/services.py start [postgres|opa|mlflow|dashboard|all]
    python scripts/services.py stop  [...|all]
    python scripts/services.py status
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from governance.config import settings  # noqa: E402

BIN = ROOT / "bin"
PG_BIN = BIN / "pgsql" / "bin"
PG_DATA = settings.data_dir / "pg"
RUN = settings.data_dir / "run"
RUN.mkdir(parents=True, exist_ok=True)
EXE = ".exe" if os.name == "nt" else ""
PY = sys.executable


def _pg(tool: str) -> str:
    local = PG_BIN / f"{tool}{EXE}"
    return str(local) if local.exists() else (shutil.which(tool) or tool)


def _opa() -> str:
    local = BIN / f"opa{EXE}"
    return str(local) if local.exists() else (shutil.which("opa") or "opa")


def _spawn(name: str, args: list[str]) -> None:
    log = open(settings.logs_dir / f"{name}.log", "a", encoding="utf-8")
    flags = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS) if os.name == "nt" else 0
    try:   # outlive the launching terminal's job object when Windows allows it
        p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT, stdin=subprocess.DEVNULL,
                             creationflags=flags | (subprocess.CREATE_BREAKAWAY_FROM_JOB if os.name == "nt" else 0),
                             start_new_session=os.name != "nt")
    except OSError:
        p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT, stdin=subprocess.DEVNULL,
                             creationflags=flags, start_new_session=os.name != "nt")
    (RUN / f"{name}.pid").write_text(str(p.pid))
    print(f"  started {name} (pid {p.pid}) -> logs/{name}.log")


def _kill(name: str) -> None:
    pidf = RUN / f"{name}.pid"
    if not pidf.exists():
        return
    pid = pidf.read_text().strip()
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", pid, "/T", "/F"], capture_output=True)
    else:
        subprocess.run(["kill", pid], capture_output=True)
    pidf.unlink(missing_ok=True)
    print(f"  stopped {name}")


def _alive(name: str) -> bool:
    pidf = RUN / f"{name}.pid"
    if not pidf.exists():
        return False
    pid = int(pidf.read_text().strip())
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- postgres
def pg_init() -> None:
    if (PG_DATA / "PG_VERSION").exists():
        return
    print("  initialising Postgres cluster in data/pg ...")
    pw = settings.data_dir / "run" / "pgpw.tmp"
    pw.write_text(settings.pg_superpass)
    try:
        subprocess.run([_pg("initdb"), "-D", str(PG_DATA), "-U", settings.pg_superuser, f"--pwfile={pw}",
                        "--auth=scram-sha-256", "-E", "UTF8", "--no-locale"], check=True, capture_output=True)
    finally:
        pw.unlink(missing_ok=True)
    # Listen on localhost only.
    with open(PG_DATA / "postgresql.conf", "a", encoding="utf-8") as f:
        f.write(f"\nlisten_addresses = 'localhost'\nport = {settings.pg_port}\n")


def pg_running() -> bool:
    r = subprocess.run([_pg("pg_ctl"), "status", "-D", str(PG_DATA)], capture_output=True, text=True)
    return r.returncode == 0


def start_postgres() -> None:
    pg_init()
    if pg_running():
        print("  postgres already running")
        return
    # No pipes: on Windows the server inherits them and run() would never return.
    subprocess.run([_pg("pg_ctl"), "start", "-D", str(PG_DATA), "-w", "-l", str(settings.logs_dir / "postgres.log")],
                   check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"  started postgres on localhost:{settings.pg_port}")


def stop_postgres() -> None:
    if pg_running():
        subprocess.run([_pg("pg_ctl"), "stop", "-D", str(PG_DATA), "-m", "fast", "-w"],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("  stopped postgres")


# ------------------------------------------------------------------ others
HEALTH = {"opa": "http://127.0.0.1:8181/health", "mlflow": "http://127.0.0.1:5000/health",
          "dashboard": "http://127.0.0.1:8501/_stcore/health"}


def _healthy(name: str) -> bool:
    """Ask the service itself; PID files go stale when Windows reuses a PID."""
    import httpx
    try:
        return httpx.get(HEALTH[name], timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def _start(name: str, args: list[str]) -> None:
    if _healthy(name):
        print(f"  {name} already running")
        return
    _kill(name)   # clear a stale PID file / half-dead process
    _spawn(name, args)


def start_opa() -> None:
    _start("opa", [_opa(), "run", "--server", "--addr", "127.0.0.1:8181", "--watch", str(settings.opa_policy_dir)])


def start_mlflow() -> None:
    _start("mlflow", [PY, "-m", "mlflow", "server", "--backend-store-uri", settings.mlflow_uri,
                      "--host", "127.0.0.1", "--port", "5000"])


def start_dashboard() -> None:
    _start("dashboard", [PY, "-m", "streamlit", "run", str(ROOT / "app" / "streamlit_app.py"),
                         "--server.port", "8501", "--server.address", "127.0.0.1", "--server.headless", "true"])


STARTERS = {"postgres": start_postgres, "opa": start_opa, "mlflow": start_mlflow, "dashboard": start_dashboard}
STOPPERS = {"postgres": stop_postgres, "opa": lambda: _kill("opa"), "mlflow": lambda: _kill("mlflow"),
            "dashboard": lambda: _kill("dashboard")}


def status() -> dict:
    from governance import data_governance, model_governance, policy
    st = {
        "postgres": data_governance.healthy(),
        "opa": policy.healthy(),
        "mlflow_registry": model_governance.healthy(),
        "ollama": bool(model_governance.ollama_models()),
        "mlflow_ui": _healthy("mlflow"),
        "dashboard": _healthy("dashboard"),
    }
    return st


def main(argv: list[str]) -> None:
    cmd = argv[0] if argv else "status"
    targets = argv[1:] or ["all"]
    if "all" in targets:
        targets = ["postgres", "opa", "mlflow", "dashboard"]
    if cmd == "start":
        for t in targets:
            STARTERS[t]()
        time.sleep(8)   # MLflow and Streamlit take a few seconds to answer
    elif cmd == "stop":
        for t in reversed(targets):
            STOPPERS[t]()
        return
    for k, v in status().items():
        print(f"  {k:<16} {'UP' if v else 'down'}")


if __name__ == "__main__":
    main(sys.argv[1:])
