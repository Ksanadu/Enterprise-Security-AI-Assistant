"""Unicode credential values must not enter persisted or provider-bound text."""

import pytest
from sqlalchemy import select

from app.db.models import Message, Ticket, WorkflowTask
from app.db.session import session_scope
from app.security.redaction import redact_credentials


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("密码是春天花园2026，已经提交到钓鱼页。", "春天花园2026"),
        ("API密钥是模拟中文密钥123。", "模拟中文密钥123"),
        ("My password is café au lait on a phishing page.", "café au lait"),
        ("密码是“春天 花园 月光”。", "春天 花园 月光"),
        ("口令是「模拟中文口令」。", "模拟中文口令"),
        ("password=“春天 花园 月光”", "春天 花园 月光"),
        ("password=café au lait on the fake page.", "café au lait"),
        ("password=correct horse battery staple on the fake page.", "correct horse battery staple"),
        ('{"password": "春天 花园 月光"}', "春天 花园 月光"),
        ('"password": “春天 花园 月光”', "春天 花园 月光"),
    ],
)
def test_unicode_values_masked_with_idempotent_redaction(text, value):
    redacted = redact_credentials(text)
    assert value not in redacted
    assert all(part not in redacted for part in value.split())
    assert "***REDACTED***" in redacted
    assert redact_credentials(redacted) == redacted


@pytest.mark.parametrize(
    "question", ["公司密码是多少位？", "密码要求是什么？", "公司的 password 最小长度 是多少？"]
)
def test_chinese_policy_words_are_preserved(question):
    assert redact_credentials(question) == question


def test_unicode_disclosure_does_not_persist_value_in_incident(client, employee_headers):
    created = client.post("/api/v1/chat/conversations", headers=employee_headers, json={})
    cid = created.json()["id"]
    value = "春天花园模拟值2026"
    response = client.post(
        f"/api/v1/chat/conversations/{cid}/messages",
        headers=employee_headers,
        json={"content": f"我在钓鱼页面输入了密码，密码是{value}。"},
    )
    assert response.status_code == 200
    payload = response.json()["assistant_message"]["payload"]
    assert payload["human_escalation"] and payload["ticket_reference"]
    assert value not in response.text
    with session_scope() as session:
        messages = session.scalars(select(Message).where(Message.conversation_id == cid)).all()
        tickets = session.scalars(select(Ticket).where(Ticket.conversation_id == cid)).all()
        tasks = session.scalars(
            select(WorkflowTask).where(WorkflowTask.conversation_id == cid)
        ).all()
        stored = (
            repr([(row.content, row.payload) for row in messages])
            + repr([(row.title, row.description, row.related_query) for row in tickets])
            + repr([row.snapshot for row in tasks])
        )
    assert value not in stored
