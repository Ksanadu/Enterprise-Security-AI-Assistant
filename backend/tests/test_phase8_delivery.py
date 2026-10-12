"""Deliverable verification must reject corruption and preserve failed external gates."""

import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture
def delivery(tmp_path, monkeypatch):
    tool = module("phase8_delivery", ROOT / "scripts/phase8-delivery.py")
    runtime = module("phase8_runtime", ROOT / "scripts/ops-release.py")
    root = tmp_path / "source"
    root.mkdir()
    declaration = json.loads((ROOT / "docs/PHASE8_ACCEPTANCE.json").read_bytes())
    source = {
        name: b"synthetic-fixture"
        for item in declaration["criteria"]
        for name in item["implementation"] + item["checks"]
    }
    source.update({item["runbook"]: b"synthetic-runbook" for item in declaration["blocked_gates"]})
    source["docs/PHASE8_ACCEPTANCE.json"] = json.dumps(declaration).encode()
    source["PRODUCT_SPEC.md"] = (ROOT / "PRODUCT_SPEC.md").read_bytes()
    source["backend/evaluation/frozen-v1.json"] = b'{"synthetic":"dataset"}'
    dataset_hash = tool.digest(source["backend/evaluation/frozen-v1.json"])
    source["backend/evaluation/thresholds-v1.json"] = json.dumps(
        {"dataset_sha256": dataset_hash}
    ).encode()
    for name, body in source.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    names = [
        "backend: ruff",
        "backend: mypy",
        "ops: ruff",
        "backend: pytest",
        "frontend: typecheck",
        "frontend: eslint",
        "frontend: vitest",
        "repo: secrets",
    ]
    gate = root / "gate.log"
    gate.write_text(
        "3 passed, 1 skipped, 1 warning in 0.1s\nTotal coverage: 94.86%\nTests 1 passed\n"
        + "\n".join("  ok   " + name for name in names)
        + "\nAll checks passed.\n"
    )
    evidence = {
        "backend/gate-junit.xml": b'<testsuites><testsuite tests="4" skipped="1" failures="0" errors="0"/></testsuites>',
        "logs/phase0/phase7-retention-demo.log": b"71/71 checks passed",
        "logs/phase7/release-rollback-drill-3/report.json": b'{"status":"passed"}',
        "logs/phase7/retention-cli-drill/report.json": b'{"status":"passed"}',
        "logs/phase7/notification-ui-desktop.png": b"synthetic-image-fixture",
        "logs/phase7/notification-ui-mobile.png": b"synthetic-image-fixture",
    }
    for name in ["validation-first", "validation-regression-observed"]:
        evidence[f"logs/phase6/{name}/report.json"] = json.dumps(
            {
                "status": "failed",
                "dataset_sha256": dataset_hash,
                "metrics": {},
                "results": [{"synthetic_private": "must-not-copy"}],
            }
        ).encode()
    for name, body in evidence.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    artifact = tmp_path / "runtime.zip"
    content = {"backend/app/ai/intent_classifier.py": source["backend/app/ai/intent_classifier.py"]}
    hashes = {name: runtime.digest(body) for name, body in content.items()}
    with zipfile.ZipFile(artifact, "w") as archive:
        for name, body in content.items():
            archive.writestr(name, body)
        archive.writestr(
            "release-manifest.json",
            json.dumps(
                {
                    "format": runtime.FORMAT,
                    "files": hashes,
                    "source_sha256": runtime.digest(json.dumps(hashes, sort_keys=True).encode()),
                }
            ),
        )
    monkeypatch.setattr(tool, "ROOT", root)
    monkeypatch.setattr(tool, "sources", lambda _: source)
    monkeypatch.setattr(tool, "runtime_tool", lambda: runtime)
    destination = tmp_path / "delivery"
    result = tool.build(destination, artifact, gate)
    return tool, destination, result


def rewrite_hashes(tool, directory):
    path = directory / "manifest.json"
    data = json.loads(path.read_bytes())
    data["files"] = {name: tool.digest((directory / name).read_bytes()) for name in data["files"]}
    path.write_text(json.dumps(data))


def test_local_bundle_is_verified_unsigned_and_preserves_quality_failures(delivery):
    tool, folder, result = delivery
    assert result["status"] == "integrity_verified" and result["final_acceptance"] is False
    assert len(result["blocked_gates"]) == 4
    assert tool.verify(folder) == result
    for name in ["quality-first", "quality-regression"]:
        data = json.loads((folder / f"evidence/{name}.json").read_bytes())
        assert data["status"] == "failed" and "results" not in data
    with pytest.raises(FileExistsError):
        tool.build(folder, folder / "runtime.zip", folder / "evidence/engineering.log")


@pytest.mark.parametrize(
    "change",
    [
        "tamper",
        "missing",
        "extra",
        "signed",
        "hide_blocker",
        "quality_pass",
        "junit_failure",
        "source_mismatch",
    ],
)
def test_corruption_or_false_completion_is_rejected(delivery, change):
    tool, folder, _ = delivery
    if change == "tamper":
        (folder / "evidence/demo.log").write_text("changed")
    elif change == "missing":
        (folder / "evidence/rollback.json").unlink()
    elif change == "extra":
        (folder / "unexpected.txt").write_text("synthetic")
    elif change in {"signed", "hide_blocker"}:
        file = folder / "acceptance.json"
        data = json.loads(file.read_bytes())
        if change == "signed":
            data["signed_off"] = True
        else:
            data["blocked_gates"].pop()
        file.write_text(json.dumps(data))
        rewrite_hashes(tool, folder)
    elif change == "quality_pass":
        file = folder / "evidence/quality-regression.json"
        data = json.loads(file.read_bytes())
        data["status"] = "passed"
        file.write_text(json.dumps(data))
        rewrite_hashes(tool, folder)
    elif change == "junit_failure":
        (folder / "evidence/junit.xml").write_text(
            '<testsuites><testsuite tests="4" skipped="1" failures="1" errors="0"/></testsuites>'
        )
        rewrite_hashes(tool, folder)
    else:
        with zipfile.ZipFile(folder / "source.zip") as archive:
            bodies = {name: archive.read(name) for name in archive.namelist()}
        bodies["backend/app/ai/intent_classifier.py"] = b"changed source"
        with zipfile.ZipFile(folder / "source.zip", "w") as archive:
            for name, body in bodies.items():
                archive.writestr(name, body)
        file = folder / "manifest.json"
        data = json.loads(file.read_bytes())
        data["sources"] = {name: tool.digest(body) for name, body in bodies.items()}
        data["source_sha256"] = tool.digest(json.dumps(data["sources"], sort_keys=True).encode())
        file.write_text(json.dumps(data))
        rewrite_hashes(tool, folder)
    with pytest.raises(ValueError):
        tool.verify(folder)


def test_runtime_data_and_unsafe_source_paths_are_excluded(delivery):
    tool, _, _ = delivery
    for name in [
        ".env",
        "backend/app/.env.private",
        "backend/data/app.db",
        "frontend/node_modules/pkg/file.js",
        "logs/phase7/report.json",
        "KIMI.md",
        "backend/.venv/lib/sample.py",
        "backend/app/private.key",
    ]:
        assert not tool.source_allowed(name)
    assert tool.source_allowed(".env.example")
    assert tool.source_allowed("backend/evaluation/frozen-v1.sha256")
    for name in [
        "../escape",
        "backend/../escape",
        "backend/NUL.txt",
        "backend//file",
        "backend/file.",
    ]:
        with pytest.raises(ValueError):
            tool.safe_path(name)


def test_require_final_cli_returns_two_for_valid_local_delivery(delivery):
    _, folder, _ = delivery
    # Runtime verifier is loaded from this real repository; only the bundle is synthetic.
    result = subprocess.run(  # noqa: S603 -- fixed local script, temporary fixture only
        [
            sys.executable,
            str(ROOT / "scripts/phase8-delivery.py"),
            "verify",
            "--output",
            str(folder),
            "--require-final",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["final_acceptance"] is False
