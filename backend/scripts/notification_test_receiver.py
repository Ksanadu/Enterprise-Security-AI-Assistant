"""Temporary TLS receiver for local acceptance; no external messages or trust-store changes."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import sqlite3
import ssl
import threading
import time
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def temporary_certificates(directory: Path) -> tuple[Path, Path, Path]:
    now = dt.datetime.now(dt.UTC)
    root_key, server_key = (
        ec.generate_private_key(ec.SECP256R1()),
        ec.generate_private_key(ec.SECP256R1()),
    )
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ESAA synthetic test CA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, None, None), critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(root_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    ca, cert, key = (
        directory / "temporary-ca.crt",
        directory / "temporary-server.crt",
        directory / "temporary-server-key.pem",
    )
    ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    descriptor = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return ca, cert, key


@contextmanager
def receiver(directory: Path, secret: str):
    directory.mkdir(parents=True, exist_ok=False)
    ca, cert, key = temporary_certificates(directory)
    database = directory / "receipts.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "CREATE TABLE receipts (id TEXT PRIMARY KEY, channel TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        connection.commit()
    state = {"fail": False, "requests": 0, "signature_errors": 0, "ca_file": str(ca)}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):  # noqa: N802 -- stdlib handler protocol
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                self.send_error(400)
                return
            body = self.rfile.read(length)
            timestamp = self.headers.get("X-ESAA-Timestamp", "")
            expected = hmac.new(
                secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
            ).hexdigest()
            if (
                not timestamp.isdecimal()
                or abs(time.time() - int(timestamp)) > 300
                or not hmac.compare_digest(expected, self.headers.get("X-ESAA-Signature", ""))
            ):
                state["signature_errors"] += 1
                self.send_error(403)
                return
            event = json.loads(body)
            state["requests"] += 1
            if state["fail"]:
                self.send_error(503)
                return
            if (
                set(event)
                != {
                    "event_id",
                    "kind",
                    "ticket_reference",
                    "severity",
                    "resource_path",
                    "created_at",
                }
                or self.headers.get("Idempotency-Key") != event["event_id"]
            ):
                self.send_error(400)
                return
            with closing(sqlite3.connect(database, timeout=5)) as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO receipts VALUES (?, ?, ?)",
                    (event["event_id"], self.path, body.decode()),
                )
                connection.commit()
            self.send_response(202)
            self.send_header("X-ESAA-Accepted-Event", event["event_id"])
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    state["primary_url"] = f"https://127.0.0.1:{server.server_port}/primary"
    state["lead_url"] = f"https://127.0.0.1:{server.server_port}/lead"
    state["database"] = database
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
