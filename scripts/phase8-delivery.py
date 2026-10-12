"""Freeze and verify a local handoff; external acceptance remains explicitly pending."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "esaa-phase8-local-delivery-v1"
STATUS = "local_delivery_ready_external_acceptance_pending"
BLOCKERS = {"docker", "live_models", "independent_quality", "formal_operations"}
MAX_BYTES = 100 * 1024 * 1024
FILES = {
    "source.zip",
    "runtime.zip",
    "acceptance.json",
    "evidence/engineering.log",
    "evidence/junit.xml",
    "evidence/demo.log",
    "evidence/rollback.json",
    "evidence/retention-cli.json",
    "evidence/quality-first.json",
    "evidence/quality-regression.json",
    "evidence/demo-desktop.png",
    "evidence/demo-mobile.png",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(name: str) -> None:
    parts = PurePosixPath(name).parts
    if (
        not parts
        or PurePosixPath(name).as_posix() != name
        or name.startswith("/")
        or ".." in parts
        or ":" in name
        or "\\" in name
        or any(
            part.endswith((".", " "))
            or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)
            for part in parts
        )
    ):
        raise ValueError("Unsafe artifact path.")


def source_allowed(name: str) -> bool:
    if name in {
        ".env.example",
        ".gitignore",
        ".gitattributes",
        "LICENSE",
        "backend/Dockerfile",
        "frontend/Dockerfile",
        "backend/.dockerignore",
        "frontend/.dockerignore",
        "frontend/.env.example",
    }:
        return True
    if any(
        part.startswith(".env") or part in {"__pycache__", "node_modules", ".venv", "dist"}
        for part in PurePosixPath(name).parts
    ):
        return False
    if name in {"KIMI.md", "KIMI_ANS.md"}:
        return False
    return Path(name).suffix.lower() in {
        ".py",
        ".md",
        ".json",
        ".txt",
        ".toml",
        ".ini",
        ".tsx",
        ".ts",
        ".css",
        ".html",
        ".svg",
        ".yml",
        ".yaml",
        ".ps1",
        ".sh",
        ".conf",
        ".sha256",
        ".mako",
        ".js",
    } and (
        "/" not in name
        or name.startswith(
            (
                "docs/",
                "scripts/",
                ".github/",
                "backend/app/",
                "backend/tests/",
                "backend/scripts/",
                "backend/migrations/",
                "backend/evaluation/",
                "backend/knowledge_base/",
                "frontend/",
            )
        )
        or name
        in {
            "backend/pyproject.toml",
            "backend/alembic.ini",
            "backend/pytest.ini",
            "backend/requirements.txt",
            "backend/requirements-dev.txt",
            "backend/retention-policy.example.json",
        }
    )


def sources(root: Path) -> dict[str, bytes]:
    listed = subprocess.run(  # noqa: S603 -- read-only fixed git inventory, no shell
        ["git", "ls-files", "-co", "--exclude-standard"],  # noqa: S607 -- fixed read-only git inventory
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    result = {}
    for name in sorted(set(listed.splitlines())):
        if not source_allowed(name):
            continue
        safe_path(name)
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Source link or escaped source refused.")
        result[name] = path.read_bytes()
    if sum(map(len, result.values())) > MAX_BYTES:
        raise ValueError("Unsupported source size.")
    return result


def check_acceptance(data: dict) -> None:
    if (
        data.get("version") != 1
        or data.get("overall_status") != STATUS
        or data.get("signed_off") is not False
    ):
        raise ValueError("Current handoff must remain explicitly unsigned and pending.")
    if [item["id"] for item in data["criteria"]] != list(range(1, 14)):
        raise ValueError("All thirteen specification criteria are required in order.")
    if {item["id"] for item in data["blocked_gates"]} != BLOCKERS or len(
        data["blocked_gates"]
    ) != 4:
        raise ValueError("Required external gates cannot be removed.")
    if (
        data["criteria"][9]["status"] != "actual_docker_acceptance_pending"
        or "quality_gate_failed" not in data["criteria"][2]["status"]
    ):
        raise ValueError("Unaccepted Docker and quality outcomes cannot be marked passed.")


def runtime_tool():
    spec = importlib.util.spec_from_file_location(
        "delivery_release", ROOT / "scripts/ops-release.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def engineering(log: bytes, junit: bytes) -> dict:
    text = log.decode("utf-8-sig")
    if not text.rstrip().endswith("All checks passed.") or "  FAIL " in text:
        raise ValueError("Engineering gate has not passed.")
    names = (
        "backend: ruff",
        "backend: mypy",
        "ops: ruff",
        "backend: pytest",
        "frontend: typecheck",
        "frontend: eslint",
        "frontend: vitest",
        "repo: secrets",
    )
    if not all("ok   " + name in text for name in names):
        raise ValueError("Incomplete engineering gate.")
    counts = re.search(r"(\d+) passed, (\d+) skipped, .*?warnings? in", text)
    coverage = re.search(r"Total coverage: ([\d.]+)%", text)
    frontend = re.search(r"Tests\s+(\d+) passed", text)
    if not counts or not coverage or not frontend:
        raise ValueError("Gate totals or coverage are absent.")
    tree = ElementTree.fromstring(junit)  # noqa: S314 -- bounded local pytest-generated report
    suites = list(tree.iter("testsuite"))
    if not suites or any(int(s.get("failures", 0)) or int(s.get("errors", 0)) for s in suites):
        raise ValueError("JUnit records an unsuccessful gate.")
    passed, skipped = map(int, counts.groups())
    if (
        sum(int(s.get("tests", 0)) for s in suites) != passed + skipped
        or sum(int(s.get("skipped", 0)) for s in suites) != skipped
    ):
        raise ValueError("JUnit and gate totals differ.")
    return {
        "backend_passed": passed,
        "backend_skipped": skipped,
        "backend_coverage": float(coverage[1]),
        "frontend_passed": int(frontend[1]),
        "exit_code": 0,
    }


def quality_summary(path: Path) -> bytes:
    data = json.loads(path.read_bytes())
    keys = (
        "dataset_sha256",
        "split",
        "mode",
        "purpose",
        "status",
        "single_turn_count",
        "multi_turn_count",
        "annotation_review",
        "answer_support_review",
        "metrics",
    )
    return json.dumps({key: data[key] for key in keys if key in data}, sort_keys=True).encode()


def build(output: Path, runtime: Path, gate: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise FileExistsError("Delivery requires a fresh directory.")
    source = sources(ROOT)
    acceptance = json.loads(source["docs/PHASE8_ACCEPTANCE.json"])
    check_acceptance(acceptance)
    specification = source["PRODUCT_SPEC.md"].decode()
    section = specification.split("## 9.", 1)[1].split("## 10.", 1)[0]
    requirements = re.findall(r"^\d+\.\s+(.+)$", section, re.MULTILINE)
    if len(requirements) != 13:
        raise ValueError("Specification differs from the mapped thirteen criteria.")
    for item, requirement in zip(acceptance["criteria"], requirements, strict=True):
        item["requirement"] = requirement
        for name in item["implementation"] + item["checks"]:
            if name not in source:
                raise ValueError("Acceptance mapping points to an absent source file.")
    for blocker in acceptance["blocked_gates"]:
        if blocker["runbook"] not in source:
            raise ValueError("A required closure runbook is absent.")
    runtime_summary = runtime_tool().verify(runtime)
    with zipfile.ZipFile(runtime) as archive:
        runtime_manifest = json.loads(archive.read("release-manifest.json"))
        for name, expected in runtime_manifest["files"].items():
            current = ROOT / name
            if digest(current.read_bytes()) != expected:
                raise ValueError("Runtime artifact differs from current application/build.")
    payloads = {
        "runtime.zip": runtime.read_bytes(),
        "acceptance.json": json.dumps(acceptance, ensure_ascii=False, indent=2).encode(),
        "evidence/engineering.log": gate.read_bytes(),
        "evidence/junit.xml": (ROOT / "backend/gate-junit.xml").read_bytes(),
        "evidence/demo.log": (ROOT / "logs/phase0/phase7-retention-demo.log").read_bytes(),
        "evidence/rollback.json": (
            ROOT / "logs/phase7/release-rollback-drill-3/report.json"
        ).read_bytes(),
        "evidence/retention-cli.json": (
            ROOT / "logs/phase7/retention-cli-drill/report.json"
        ).read_bytes(),
        "evidence/quality-first.json": quality_summary(
            ROOT / "logs/phase6/validation-first/report.json"
        ),
        "evidence/quality-regression.json": quality_summary(
            ROOT / "logs/phase6/validation-regression-observed/report.json"
        ),
        "evidence/demo-desktop.png": (
            ROOT / "logs/phase7/notification-ui-desktop.png"
        ).read_bytes(),
        "evidence/demo-mobile.png": (ROOT / "logs/phase7/notification-ui-mobile.png").read_bytes(),
    }
    gate_summary = engineering(payloads["evidence/engineering.log"], payloads["evidence/junit.xml"])
    if "71/71 checks passed" not in payloads["evidence/demo.log"].decode("utf-8-sig"):
        raise ValueError("Actual demo was not accepted.")
    for name in ("evidence/rollback.json", "evidence/retention-cli.json"):
        if json.loads(payloads[name])["status"] != "passed":
            raise ValueError("A local operations drill has not passed.")
    if any(
        json.loads(payloads[name])["status"] != "failed"
        for name in ("evidence/quality-first.json", "evidence/quality-regression.json")
    ):
        raise ValueError("Frozen quality failures must remain represented.")
    output.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(output / "source.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in source.items():
            archive.writestr(name, body)
    payloads["source.zip"] = (output / "source.zip").read_bytes()
    for name, body in payloads.items():
        if name == "source.zip":
            continue
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    hashes = {name: digest(body) for name, body in source.items()}
    manifest = {
        "format": FORMAT,
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "overall_status": STATUS,
        "sources": hashes,
        "source_sha256": digest(json.dumps(hashes, sort_keys=True).encode()),
        "files": {name: digest(body) for name, body in payloads.items()},
        "engineering": gate_summary,
        "runtime": runtime_summary,
        "specification_sha256": digest(source["PRODUCT_SPEC.md"]),
        "evidence_scope": "synthetic local evidence; quality failures retained; external gates pending",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return verify(output)


def verify(output: Path) -> dict:
    manifest_path = output / "manifest.json"
    if manifest_path.stat().st_size > 256000:
        raise ValueError("Unsupported manifest size.")
    manifest = json.loads(manifest_path.read_bytes())
    if (
        manifest.get("format") != FORMAT
        or manifest.get("overall_status") != STATUS
        or set(manifest["files"]) != FILES
    ):
        raise ValueError("Incomplete or unsupported local delivery.")
    paths = [path for path in output.rglob("*") if path.is_file() or path.is_symlink()]
    if {path.relative_to(output).as_posix() for path in paths} != FILES | {"manifest.json"}:
        raise ValueError("Unexpected or missing delivery files.")
    for path in paths:
        if (
            path.is_symlink()
            or any(
                parent.is_symlink() or parent.is_junction()
                for parent in (path.parent, *path.parents)
            )
            or not path.resolve().is_relative_to(output.resolve())
        ):
            raise ValueError("Linked or escaped delivery file.")
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("Unsupported delivery file size.")
    for name, expected in manifest["files"].items():
        safe_path(name)
        if digest((output / name).read_bytes()) != expected:
            raise ValueError("Delivery integrity check failed.")
    with zipfile.ZipFile(output / "source.zip") as archive:
        infos = archive.infolist()
        if (
            len({i.filename.casefold() for i in infos}) != len(infos)
            or sum(i.file_size for i in infos) > MAX_BYTES
        ):
            raise ValueError("Duplicate or oversized source archive.")
        actual = {}
        for info in infos:
            safe_path(info.filename)
            if (
                not source_allowed(info.filename)
                or info.is_dir()
                or stat.S_ISLNK(info.external_attr >> 16)
            ):
                raise ValueError("Unexpected source archive member.")
            actual[info.filename] = digest(archive.read(info))
        if (
            actual != manifest["sources"]
            or digest(json.dumps(actual, sort_keys=True).encode()) != manifest["source_sha256"]
        ):
            raise ValueError("Source snapshot differs from its manifest.")
        if actual["PRODUCT_SPEC.md"] != manifest["specification_sha256"]:
            raise ValueError("Specification snapshot differs.")
        source_acceptance = json.loads(archive.read("docs/PHASE8_ACCEPTANCE.json"))
        dataset_hash = digest(archive.read("backend/evaluation/frozen-v1.json"))
        if (
            json.loads(archive.read("backend/evaluation/thresholds-v1.json"))["dataset_sha256"]
            != dataset_hash
        ):
            raise ValueError("Frozen thresholds and dataset differ.")
    check_acceptance(json.loads((output / "acceptance.json").read_bytes()))
    acceptance = json.loads((output / "acceptance.json").read_bytes())
    for item in acceptance["criteria"]:
        item.pop("requirement", None)
    if acceptance != source_acceptance:
        raise ValueError("Acceptance record differs from its source declaration.")
    if "71/71 checks passed" not in (output / "evidence/demo.log").read_text(encoding="utf-8-sig"):
        raise ValueError("Demo evidence was not accepted.")
    for name in ("rollback", "retention-cli"):
        if json.loads((output / ("evidence/" + name + ".json")).read_bytes())["status"] != "passed":
            raise ValueError("Operations evidence was not accepted.")
    for name in ("quality-first", "quality-regression"):
        quality = json.loads((output / ("evidence/" + name + ".json")).read_bytes())
        if quality["status"] != "failed" or quality["dataset_sha256"] != dataset_hash:
            raise ValueError("Quality evidence differs from the frozen failure record.")
    if (
        engineering(
            (output / "evidence/engineering.log").read_bytes(),
            (output / "evidence/junit.xml").read_bytes(),
        )
        != manifest["engineering"]
    ):
        raise ValueError("Engineering summary differs from its evidence.")
    if runtime_tool().verify(output / "runtime.zip") != manifest["runtime"]:
        raise ValueError("Runtime summary differs from its artifact.")
    with zipfile.ZipFile(output / "runtime.zip") as archive:
        for name, expected in json.loads(archive.read("release-manifest.json"))["files"].items():
            if not name.startswith("frontend/dist/") and actual.get(name) != expected:
                raise ValueError("Runtime and source snapshots differ.")
    return {
        "status": "integrity_verified",
        "overall_status": STATUS,
        "source_sha256": manifest["source_sha256"],
        "source_file_count": len(actual),
        "engineering": manifest["engineering"],
        "final_acceptance": False,
        "blocked_gates": sorted(BLOCKERS),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--gate", type=Path)
    parser.add_argument("--require-final", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "build":
            if args.runtime is None or args.gate is None:
                raise ValueError("Runtime and accepted engineering gate are required.")
            result = build(args.output.resolve(), args.runtime.resolve(), args.gate.resolve())
        else:
            result = verify(args.output.resolve())
        print(json.dumps(result))
        return 2 if args.require_final else 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
