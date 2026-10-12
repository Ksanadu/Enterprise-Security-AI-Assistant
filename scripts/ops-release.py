"""Package and verify a local backend/frontend release; no runtime data or secrets."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "esaa-local-release-v1"
MAX_BYTES = 100 * 1024 * 1024
ASSET_FILES = {
    "frontend/Dockerfile",
    "frontend/nginx.conf",
    "docker-compose.yml",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package(output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise FileExistsError("Use a fresh release destination.")
    sources = []
    for folder in (
        "backend/app",
        "backend/knowledge_base",
        "backend/migrations",
        "backend/scripts",
        "frontend/dist",
    ):
        directory = ROOT / folder
        if not directory.is_dir():
            raise FileNotFoundError("Required release assets missing; build frontend first.")
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError("Release sources must not contain links.")
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix not in {".pyc", ".pyo"}
            ):
                if path.name.startswith(".env") or path.suffix in {".db", ".log"}:
                    raise ValueError("Runtime data found in release source.")
                sources.append(path)
    sources += [
        ROOT / name
        for name in (
            "backend/requirements.txt",
            "backend/alembic.ini",
            "backend/Dockerfile",
            "frontend/Dockerfile",
            "frontend/nginx.conf",
            "docker-compose.yml",
        )
    ]
    contents = {}
    for path in sorted(sources):
        if not path.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("Release source escaped its root.")
        contents[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    if sum(map(len, contents.values())) > MAX_BYTES:
        raise ValueError("Release exceeds supported size.")
    files = {name: digest(body) for name, body in contents.items()}
    manifest = {
        "format": FORMAT,
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "files": files,
        "source_sha256": digest(json.dumps(files, sort_keys=True).encode()),
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in contents.items():
            archive.writestr(name, body)
        archive.writestr("release-manifest.json", json.dumps(manifest, sort_keys=True))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as target:
        target.write(stream.getvalue())
        target.flush()
        os.fsync(target.fileno())
    result = verify(output)
    return {"status": "release_packaged", **result}


def verify(path: Path, destination: Path | None = None) -> dict:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("Unsupported artifact size.")
    raw = path.read_bytes()
    contents = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if len(names) != len({name.casefold() for name in names}):
            raise ValueError("Duplicate release paths.")
        if sum(info.file_size for info in archive.infolist()) > MAX_BYTES:
            raise ValueError("Expanded artifact exceeds supported size.")
        for info in archive.infolist():
            name = info.filename
            parts = PurePosixPath(name).parts
            if (
                not parts
                or name.startswith("/")
                or ".." in parts
                or ":" in name
                or "\\" in name
                or PurePosixPath(name).as_posix() != name
                or any(
                    part.endswith((".", " "))
                    or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)
                    for part in parts
                )
            ):
                raise ValueError("Unsafe release path.")
            if stat.S_ISLNK(info.external_attr >> 16) or info.is_dir():
                raise ValueError("Release members must be regular files.")
            if (
                name != "release-manifest.json"
                and name not in ASSET_FILES
                and not name.startswith(("backend/", "frontend/dist/"))
            ):
                raise ValueError("Unexpected release member.")
            contents[name] = archive.read(info)
    manifest = json.loads(contents.pop("release-manifest.json"))
    if manifest.get("format") != FORMAT or set(manifest["files"]) != set(contents):
        raise ValueError("Unsupported/incomplete release manifest.")
    actual = {name: digest(body) for name, body in contents.items()}
    if (
        actual != manifest["files"]
        or digest(json.dumps(actual, sort_keys=True).encode()) != manifest["source_sha256"]
    ):
        raise ValueError("Release integrity check failed.")
    if destination is not None:
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("Extraction requires a fresh directory.")
        destination.mkdir(parents=True, exist_ok=False)
        root = destination.resolve()
        for name, body in contents.items():
            target = destination / name
            if not target.resolve().is_relative_to(root):
                raise ValueError("Extraction escaped destination.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as file:
                file.write(body)
    return {
        "artifact_sha256": digest(raw),
        "source_sha256": manifest["source_sha256"],
        "file_count": len(actual),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("package", "verify", "extract"))
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "extract" and args.destination is None:
            raise ValueError("Extraction destination required.")
        result = (
            package(args.artifact)
            if args.action == "package"
            else verify(args.artifact, args.destination if args.action == "extract" else None)
        )
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
