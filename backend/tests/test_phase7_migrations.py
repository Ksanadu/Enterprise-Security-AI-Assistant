"""Existing data upgrades, unknown drift is preserved, and rollback cannot drop rows."""

import pytest
from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.core.enums import Role
from app.db.migrations import configuration, current_revision, head_revision, upgrade_database
from app.db.models import User
from app.db.session import get_engine, init_db


def add_user(engine):
    with Session(engine) as session:
        session.add(
            User(
                email="upgrade@example.com",
                full_name="Synthetic Upgrade",
                password_hash="synthetic-no-real-password",
                role=Role.EMPLOYEE,
            )
        )
        session.commit()


def test_existing_unversioned_data_adopted_without_loss(settings):
    engine = get_engine(settings)
    upgrade_database(engine, "20261012_01")
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE alembic_version")
    add_user(engine)
    upgrade_database(engine)
    assert current_revision(engine) == head_revision()
    with engine.connect() as connection:
        assert connection.execute(text("SELECT email FROM users")).scalar() == "upgrade@example.com"
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []


def test_drift_is_refused_without_dropping_development_data(settings):
    engine = get_engine(settings)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE users (id INTEGER PRIMARY KEY, legacy_note TEXT)")
        connection.exec_driver_sql("INSERT INTO users VALUES (1, 'simulated preserved data')")
    with pytest.raises(RuntimeError, match="schema drift"):
        init_db(settings)
    with engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT legacy_note FROM users").scalar()
            == "simulated preserved data"
        )
    assert current_revision(engine) is None


def test_production_requires_operator_migration(settings):
    production = settings.model_copy(update={"app_env": "production"})
    with pytest.raises(RuntimeError, match="migration required"):
        init_db(production)
    engine = get_engine(settings)
    upgrade_database(engine)
    init_db(production)
    assert current_revision(engine) == head_revision()


def test_baseline_downgrade_guard_preserves_business_rows(settings):
    engine = get_engine(settings)
    upgrade_database(engine)
    add_user(engine)
    config = configuration()
    with (
        pytest.raises(RuntimeError, match="business data exists"),
        engine.connect() as connection,
        connection.begin(),
    ):
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.downgrade(config, "base")
    assert current_revision(engine) == head_revision()
    assert "users" in inspect(engine).get_table_names()


def test_empty_schema_can_roll_back_and_upgrade_again(settings):
    engine = get_engine(settings)
    upgrade_database(engine)
    config = configuration()
    with engine.connect() as connection, connection.begin():
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.downgrade(config, "base")
    assert current_revision(engine) is None
    upgrade_database(engine)
    assert current_revision(engine) == head_revision()
