"""Artifact integrity, path safety and immutable local activation inputs."""

import importlib.util
import json
import stat
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def releases():
    source = Path(__file__).resolve().parents[2] / "scripts" / "ops-release.py"
    spec = importlib.util.spec_from_file_location("esaa_release", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def artifact(module, path, contents, *, stale_hash=False, extra=None):
    hashes = {name: module.digest(body) for name, body in contents.items()}
    manifest = {
        "format": module.FORMAT,
        "files": hashes,
        "source_sha256": module.digest(json.dumps(hashes, sort_keys=True).encode()),
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in contents.items():
            archive.writestr(name, b"tampered" if stale_hash else body)
        if extra is not None:
            archive.writestr(extra, b"synthetic")
        archive.writestr("release-manifest.json", json.dumps(manifest))


def test_packaging_excludes_runtime_cache_and_never_overwrites(releases, tmp_path, monkeypatch):
    source = tmp_path / "source"
    for folder in [
        "backend/app",
        "backend/knowledge_base",
        "backend/migrations",
        "backend/scripts",
        "frontend/dist",
    ]:
        (source / folder).mkdir(parents=True)
        (source / folder / "synthetic.txt").write_text("synthetic-release")
    for name in [
        "backend/requirements.txt",
        "backend/alembic.ini",
        "backend/Dockerfile",
        "frontend/Dockerfile",
        "frontend/nginx.conf",
        "docker-compose.yml",
    ]:
        (source / name).write_text("synthetic")
    cache = source / "backend/app/__pycache__"
    cache.mkdir()
    (cache / "sample.pyc").write_bytes(b"cache")
    monkeypatch.setattr(releases, "ROOT", source)
    output = tmp_path / "version.zip"
    report = releases.package(output)
    assert report["file_count"] == 11
    with pytest.raises(FileExistsError):
        releases.package(output)
    destination = tmp_path / "activated"
    assert releases.verify(output, destination)["artifact_sha256"] == report["artifact_sha256"]
    assert (destination / "backend/app/synthetic.txt").read_text() == "synthetic-release"
    assert not (destination / "backend/app/__pycache__").exists()
    with pytest.raises(FileExistsError):
        releases.verify(output, destination)
    (source / "backend/app/.env.private").write_text("synthetic-secret")
    with pytest.raises(ValueError, match="Runtime data"):
        releases.package(tmp_path / "forbidden.zip")


@pytest.mark.parametrize(
    "unsafe",
    [
        "../escape",
        "backend/../escape",
        "backend/C:/escape",
        "backend\\escape",
        "backend/NUL.txt",
        "backend/file.",
        "backend//file",
        "frontend/Dockerfile-extra",
    ],
)
def test_unsafe_archive_cannot_create_destination(releases, tmp_path, unsafe):
    output = tmp_path / "unsafe.zip"
    artifact(releases, output, {unsafe: b"synthetic"})
    destination = tmp_path / "destination"
    with pytest.raises(ValueError):
        releases.verify(output, destination)
    assert not destination.exists()


@pytest.mark.parametrize("mode", ["tamper", "extra", "duplicate", "link", "oversize"])
def test_corrupt_release_is_rejected_before_extraction(releases, tmp_path, monkeypatch, mode):
    output = tmp_path / "corrupt.zip"
    artifact(
        releases,
        output,
        {"backend/app/sample.py": b"synthetic"},
        stale_hash=mode == "tamper",
        extra="backend/app/extra.py" if mode == "extra" else None,
    )
    if mode in {"duplicate", "link"}:
        with zipfile.ZipFile(output, "a") as archive:
            name = "BACKEND/APP/SAMPLE.PY" if mode == "duplicate" else "backend/app/link"
            info = zipfile.ZipInfo(name)
            if mode == "link":
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "synthetic")
    if mode == "oversize":
        monkeypatch.setattr(releases, "MAX_BYTES", 1)
    destination = tmp_path / "destination"
    with pytest.raises(ValueError):
        releases.verify(output, destination)
    assert not destination.exists()
