"""Actual evaluator pipelines must isolate recipients as well as database files."""

from scripts.evaluate_models import evaluate
from scripts.evaluate_quality import run

from app import main


def test_evaluators_disable_inherited_notification_channels(settings, monkeypatch, tmp_path):
    parent_url = "https://synthetic-operator-receiver.invalid"
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_URL", parent_url)
    monkeypatch.setenv("NOTIFICATION_LEAD_WEBHOOK_URL", parent_url + "/lead")
    monkeypatch.setenv(
        "NOTIFICATION_SIGNING_SECRET", "synthetic-inherited-signing-secret-long-enough"
    )
    monkeypatch.setenv("NOTIFICATION_POLL_INTERVAL_SECONDS", "1")
    monkeypatch.setenv("RETENTION_POLICY_FILE", "synthetic-operator-policy-must-not-be-used.json")
    monkeypatch.setenv("RETENTION_BACKUP_DIR", "synthetic-operator-backups-must-not-be-used")
    original = main.create_app
    inspected = []

    def isolated_app(config):
        inspected.append(config)
        assert config.notification_webhook_url == config.notification_lead_webhook_url == ""
        assert config.notification_signing_secret == config.notification_ca_bundle_file == ""
        assert config.notification_poll_interval_seconds == 0
        assert config.retention_policy_file == config.retention_backup_dir == ""
        assert config.database_url != settings.database_url
        return original(config)

    monkeypatch.setattr(main, "create_app", isolated_app)
    evaluate("offline", tmp_path / "models", max_cases=1, max_network_calls=None)
    run("development", tmp_path / "quality", limit=1)
    assert len(inspected) == 2
    # Explicit isolation is scoped to the run and does not erase operator config.
    import os

    assert os.environ["NOTIFICATION_WEBHOOK_URL"] == parent_url
    assert os.environ["NOTIFICATION_POLL_INTERVAL_SECONDS"] == "1"
