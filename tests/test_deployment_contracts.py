from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SIGNED_EVIDENCE_POLICY_ENV = {
    "DEPLOYMENT_APPROVAL_PATH",
    "DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_PATH",
    "DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_SHA256",
    "COVARIANCE_EVIDENCE_PATH",
    "COVARIANCE_EXECUTION_PRICES_PATH",
    "COVARIANCE_CORPORATE_ACTIONS_PATH",
    "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH",
    "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_SHA256",
    "COVARIANCE_PROVIDER_ID",
    "COVARIANCE_VENUE_ID",
    "BORROW_EVIDENCE_PATH",
    "BORROW_TERMS_PATH",
    "BORROW_GOVERNANCE_PUBLIC_KEYS_PATH",
    "BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256",
    "BORROW_PROVIDER_ID",
    "BORROW_VENUE_ID",
    "BORROW_MAX_TERM_AGE_SECONDS",
    "MAX_LIVE_ANNUAL_BORROW_RATE",
}

SIGNED_EVIDENCE_PATH_ENV = {
    name
    for name in SIGNED_EVIDENCE_POLICY_ENV
    if name.endswith("_PATH")
}


def _bot_compose_source() -> str:
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    return compose.split("  operations-dashboard:", maxsplit=1)[0]


def _compose_command() -> list[str] | None:
    docker = shutil.which("docker")
    if docker is not None:
        candidate = [docker, "compose"]
        probe = subprocess.run(
            [*candidate, "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if probe.returncode == 0:
            return candidate
    legacy = shutil.which("docker-compose")
    if legacy is not None:
        return [legacy]
    return None


def test_compose_source_forwards_every_signed_evidence_policy_and_seals_bind() -> None:
    bot = _bot_compose_source()
    example_environment = {
        line.split("=", maxsplit=1)[0]
        for line in (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    }
    declared_evidence_policy = {
        name
        for name in example_environment
        if name.startswith(("COVARIANCE_", "BORROW_"))
        or name == "MAX_LIVE_ANNUAL_BORROW_RATE"
        or name
        in {
            "DEPLOYMENT_APPROVAL_PATH",
            "DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_PATH",
            "DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_SHA256",
        }
    }
    assert declared_evidence_policy == SIGNED_EVIDENCE_POLICY_ENV

    for name in SIGNED_EVIDENCE_POLICY_ENV:
        assert re.search(
            rf"^      {re.escape(name)}: \$\{{{re.escape(name)}:-[^}}]*\}}$",
            bot,
            flags=re.MULTILINE,
        ), name

    deployment_bind = re.search(
        r"(?ms)^      - type: bind\n"
        r"        source: \$\{DEPLOYMENT_GOVERNANCE_HOST_DIR:-[^\n]+\}\n"
        r"        target: /app/deployment\n"
        r"        read_only: true\n"
        r"        bind:\n"
        r"          create_host_path: false$",
        bot,
    )
    assert deployment_bind is not None


def test_rendered_compose_preserves_policy_and_noncreating_read_only_bind(
    tmp_path: Path,
) -> None:
    command = _compose_command()
    if command is None:
        pytest.skip("Docker Compose is unavailable; source-level contract still runs.")

    host_governance = tmp_path / "governance"
    environment = os.environ.copy()
    environment.update(
        {
            "BOT_ENV_FILE": str(PROJECT_ROOT / ".env.example"),
            "DEPLOYMENT_GOVERNANCE_HOST_DIR": str(host_governance),
            "DOCKER_CONFIG": str(tmp_path / "docker-config"),
        }
    )
    (tmp_path / "docker-config").mkdir()
    for name in SIGNED_EVIDENCE_POLICY_ENV:
        environment[name] = (
            "137"
            if name == "BORROW_MAX_TERM_AGE_SECONDS"
            else "0.013"
            if name == "MAX_LIVE_ANNUAL_BORROW_RATE"
            else f"rendered-{name.lower()}"
        )

    completed = subprocess.run(
        [
            *command,
            "--env-file",
            str(PROJECT_ROOT / ".env.example"),
            "config",
            "--format",
            "json",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = json.loads(completed.stdout)
    bot = rendered["services"]["bot"]

    assert bot["read_only"] is True
    for name in SIGNED_EVIDENCE_POLICY_ENV:
        assert bot["environment"][name] == environment[name], name

    deployment_mounts = [
        mount
        for mount in bot["volumes"]
        if mount.get("target") == "/app/deployment"
    ]
    assert len(deployment_mounts) == 1
    mount = deployment_mounts[0]
    assert mount["type"] == "bind"
    assert Path(mount["source"]).resolve() == host_governance.resolve()
    assert mount["read_only"] is True
    # Compose renders an explicit false as either false or an omitted/default-false
    # field. Short-syntax auto-creating binds render this field as true.
    assert mount.get("bind", {}).get("create_host_path", False) is False


def test_systemd_governance_policy_is_separate_root_controlled_read_only_input() -> None:
    unit = (PROJECT_ROOT / "deploy/quant-auto-trader.service").read_text(
        encoding="utf-8"
    )
    governance = (PROJECT_ROOT / "deploy/governance.env.example").read_text(
        encoding="utf-8"
    )

    assert (
        "EnvironmentFile=/opt/quant-auto-trader/deployment/governance.env" in unit
    )
    assert "User=quantbot" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadOnlyPaths=/opt/quant-auto-trader/deployment" in unit
    writable = next(
        line for line in unit.splitlines() if line.startswith("ReadWritePaths=")
    )
    assert "/opt/quant-auto-trader/deployment" not in writable
    assert "root:quantbot" in governance
    assert "mode 0640" in governance

    configured = {
        line.split("=", maxsplit=1)[0]: line.split("=", maxsplit=1)[1]
        for line in governance.splitlines()
        if line and not line.startswith("#") and "=" in line
    }
    assert SIGNED_EVIDENCE_POLICY_ENV.issubset(configured)
    for name in SIGNED_EVIDENCE_PATH_ENV:
        assert configured[name].startswith("/opt/quant-auto-trader/deployment/"), name
        assert "/runtime/" not in configured[name], name
