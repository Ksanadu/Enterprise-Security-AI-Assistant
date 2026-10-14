"""Chromium acceptance against the actual container SPA; only simulated accounts.

No response bodies, tokens, HAR or browser storage are exported. Screenshots and
bounded result metadata are the evidence. Missing Playwright/browser fails closed.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit


def check_browser(url: str, output: Path) -> dict:
    from playwright.sync_api import expect, sync_playwright

    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("Browser acceptance only targets this run's loopback instance.")
    output.mkdir(parents=True, exist_ok=False)
    result = {"status": "failed", "mode": "mock_tfidf", "checks": [], "screenshots": []}
    current_check = "browser_startup"

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        result["browser_version"] = browser.version
        try:
            for layout, viewport in (
                ("desktop", {"width": 1440, "height": 1000}),
                ("mobile", {"width": 390, "height": 844}),
            ):
                context = browser.new_context(viewport=viewport, locale="zh-CN")
                context.add_init_script(
                    "window.esaaCspViolations = []; "
                    "document.addEventListener('securitypolicyviolation', "
                    "e => window.esaaCspViolations.push(e.effectiveDirective));"
                )
                page = context.new_page()
                page.set_default_timeout(30000)
                errors = []
                page.on("pageerror", lambda _error, _errors=errors: _errors.append("pageerror"))

                def completed(name: str, _layout: str = layout) -> None:
                    result["checks"].append(f"{_layout}:{name}")

                def screenshot(name: str, _layout: str = layout, _page=page) -> None:
                    path = output / f"{_layout}-{name}.png"
                    _page.screenshot(path=path, full_page=True)
                    result["screenshots"].append(path.name)

                def login(role: str, page=page) -> None:
                    response = page.goto(url)
                    assert response and response.ok
                    assert response.headers.get("content-security-policy")
                    page.get_by_label("Work email", exact=True).fill(f"{role}@example.com")
                    page.get_by_label("Password", exact=True).fill("Demo@12345")
                    page.get_by_role("button", name="Sign in", exact=True).click()
                    expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
                    expect(page.locator(".session__scope strong")).to_have_text(
                        {"employee": "7", "it": "10", "security": "12"}[role]
                    )

                def ask(question: str, page=page) -> dict:
                    before = page.locator(".bubble--assistant").count()
                    page.get_by_label("Ask a security question", exact=True).fill(question)
                    with page.expect_response(
                        lambda response: response.request.method == "POST"
                        and urlsplit(response.url).path.endswith("/messages")
                    ) as received:
                        page.get_by_role("button", name="Send", exact=True).click()
                    assert received.value.ok
                    payload = received.value.json()["assistant_message"]["payload"]
                    expect(page.locator(".bubble--assistant")).to_have_count(before + 1)
                    expect(page.get_by_role("button", name="Send", exact=True)).to_be_visible()
                    return payload

                def fresh_conversation(page=page) -> None:
                    page.get_by_role("button", name="New conversation", exact=True).click()
                    expect(page.locator(".bubble--assistant")).to_have_count(0)

                try:
                    current_check = f"{layout}:employee_policy"
                    login("employee")
                    assert page.get_by_role("button", name="Dashboard", exact=True).count() == 0
                    policy = ask("公司密码有什么要求？")
                    assert "KB-001" in {s["document_id"] for s in policy["source_documents"]}
                    assert policy["offline"] and policy["grounded"]
                    bubble = page.locator(".bubble--assistant").last
                    bubble.locator("summary").first.click()
                    expect(bubble.locator(".source__snippet").first).to_be_visible()
                    completed("policy_and_expanded_citation")

                    current_check = f"{layout}:employee_rbac"
                    denied = ask("What is the malware response procedure?")
                    assert "KB-004" not in {s["document_id"] for s in denied["source_documents"]}
                    completed("employee_restricted_sources_and_dashboard")

                    current_check = f"{layout}:phishing_escalation"
                    fresh_conversation()
                    suspicious = ask("我点击了可疑邮件里的链接。")
                    confirmed = ask("是的，我输入了验证码。")
                    reference = confirmed["ticket_reference"]
                    assert reference and reference == suspicious["ticket_reference"]
                    assert confirmed["risk_level"] == "high" and confirmed["human_escalation"]
                    expect(page.locator(".bubble--assistant").last).to_contain_text(reference)
                    completed("multi_turn_same_ticket_escalation")

                    current_check = f"{layout}:layout"
                    result.setdefault("layout", {})[layout] = page.evaluate(
                        "({viewport: document.documentElement.clientWidth, "
                        "scroll: document.documentElement.scrollWidth, "
                        "overflow: Array.from(document.querySelectorAll('body *'))"
                        ".filter(e => e.getBoundingClientRect().right > document.documentElement.clientWidth + 1)"
                        ".slice(0, 12).map(e => ({tag: e.tagName, class: e.className, "
                        "right: Math.round(e.getBoundingClientRect().right)}))})"
                    )
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
                    ), "Horizontal page overflow"
                    screenshot("employee-escalation")
                    completed("viewport_no_horizontal_overflow")

                    current_check = f"{layout}:it_rbac"
                    page.get_by_role("button", name="Sign out", exact=True).click()
                    login("it")
                    it_answer = ask(
                        "The VPN is not connecting. What troubleshooting steps can IT take?"
                    )
                    assert "KB-005" in {s["document_id"] for s in it_answer["source_documents"]}
                    assert page.get_by_role("button", name="Dashboard", exact=True).count() == 0
                    completed("it_authorized_vpn_and_dashboard_boundary")

                    current_check = f"{layout}:security_rbac"
                    page.get_by_role("button", name="Sign out", exact=True).click()
                    login("security")
                    security_answer = ask("What is the malware response procedure?")
                    assert "KB-004" in {
                        s["document_id"] for s in security_answer["source_documents"]
                    }
                    completed("security_internal_sop")

                    current_check = f"{layout}:human_response"
                    page.get_by_role("button", name="Tickets", exact=True).click()
                    page.locator(".ticket-row").filter(has_text=reference).click()
                    detail = page.get_by_role("region", name="Ticket detail", exact=True)
                    expect(detail).to_contain_text("Awaiting acknowledgment")
                    detail.get_by_label("Note (optional)", exact=True).fill(
                        "Synthetic browser acceptance: security team takes ownership."
                    )
                    with page.expect_response(
                        lambda response, _reference=reference: response.request.method == "PATCH"
                        and urlsplit(response.url).path.endswith("/" + _reference)
                    ) as acknowledged:
                        detail.get_by_role("button", name="Move to in progress", exact=True).click()
                    assert acknowledged.value.ok and acknowledged.value.json()["human_acknowledged"]
                    expect(detail).to_contain_text("Accepted by a person")
                    screenshot("human-response")
                    completed("human_acknowledgment_and_timeline")

                    current_check = f"{layout}:dashboard"
                    page.get_by_role("button", name="Dashboard", exact=True).click()
                    expect(page.get_by_role("region", name="Headline numbers")).to_be_visible()
                    screenshot("dashboard")
                    completed("security_dashboard")

                    current_check = f"{layout}:deep_link"
                    page.goto(url + "/?ticket=" + reference)
                    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
                    page.get_by_label("Work email", exact=True).fill("security@example.com")
                    page.get_by_label("Password", exact=True).fill("Demo@12345")
                    page.get_by_role("button", name="Sign in", exact=True).click()
                    expect(page.locator(".ticket-detail__ref")).to_have_text(reference)
                    completed("refresh_logout_and_authenticated_ticket_deep_link")
                    assert not errors, "Browser page errors"
                    assert not page.evaluate("window.esaaCspViolations"), "Browser CSP violation"
                    completed("browser_runtime_and_csp")
                except Exception as exc:
                    result["failed_check"] = current_check
                    result["error_type"] = type(exc).__name__
                    screenshot("failure")
                    raise
                finally:
                    context.close()
            result["status"] = "passed"
        finally:
            browser.close()
            (output / "browser-acceptance.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
            )
    return result
