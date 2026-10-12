"""Chinese domain facts and lexical support shared by classification and RAG.

These rules describe observed actions separately from questions and requests.
They supplement English rules; they never grant access to a document.
"""
# ruff: noqa: RUF001 -- punctuation in Chinese language patterns is intentional.

from __future__ import annotations

import re

from app.core.enums import Intent, RiskLevel

CJK = re.compile(r"[\u4e00-\u9fff]+")
DOMAIN_ALIASES = {
    "密码": "password",
    "口令": "password",
    "邮件": "email",
    "邮箱": "mailbox",
    "钓鱼": "phishing",
    "附件": "attachment",
    "弹窗": "popup",
    "奇怪窗口": "popup",
    "异常": "unusual",
    "电脑": "computer",
    "笔记本": "laptop",
    "设备": "device",
    "验证码": "verification code",
    "恶意软件": "malware",
    "病毒": "virus malware response",
    "勒索": "ransomware",
    "虚拟专用网络": "vpn",
    "连接": "connection",
    "故障": "troubleshooting",
    "排查": "troubleshooting",
    "要求": "requirements",
    "策略": "policy",
    "规定": "policy",
    "泄露": "leaked",
    "安全团队": "security team",
    "远程办公": "remote work",
    "访问控制": "access control",
    "数据": "data",
}


def cjk_terms(text: str) -> list[str]:
    return [
        span[i : i + size]
        for span in CJK.findall(text)
        for size in (2, 3)
        for i in range(max(0, len(span) - size + 1))
    ]


def lexical_aliases(text: str) -> str:
    aliases = [value for key, value in DOMAIN_ALIASES.items() if key in text]
    if re.search(
        r"\bfake\b.{0,35}\b(?:login|support|page|email)\b|\b(?:login|page)\b.{0,25}\bfake\b",
        text,
        re.I,
    ):
        aliases.append("phishing suspicious email")
    # Common descriptions of unexpected symptoms should share the policy term.
    if re.search(r"\b(?:strange|odd|weird)\b", text, re.I):
        aliases.append("unexpected")
    if re.search(r"\bstrong\s+(?:password|passphrase)\b", text, re.I):
        aliases.append("password requirements")
    if re.search(r"\b(?:working|work)\s+from\s+home\b", text, re.I):
        aliases.append("remote work security policy")
    return " ".join(aliases)


def chinese_intent(text: str) -> Intent | None:
    if not CJK.search(text):
        return None
    if re.search(
        r"(?:(?:异常|奇怪|不正常)(?:的)?弹窗|奇怪窗口|弹出.*窗口|勒索|感染|被入侵|被盗|遭到攻击|数据.*泄露|恶意软件)",
        text,
    ):
        return Intent.SECURITY_INCIDENT
    if re.search(
        r"钓鱼|可疑.*(?:邮件|链接)|陌生.*邮件|邮件.{0,40}(?:登录|验证|链接)|发邮件.{0,30}验证", text
    ):
        return Intent.PHISHING
    if re.search(r"虚拟专用网络|vpn|连不上|连接失败|账号.*锁定", text, re.I):
        return Intent.IT_SUPPORT
    if re.search(r"密码|口令|多因素|双因素", text):
        return Intent.SECURITY_FAQ
    if re.search(r"政策|策略|规定|允许|远程办公|访问控制", text):
        return Intent.POLICY_QUESTION
    return None


_NEGATED = re.compile(r"(?:没有|没|未|不曾|从未|并未|尚未|还没).{0,6}$")
_REQUESTED = re.compile(r"(?:要求|让|叫|请|希望|需要|建议).{0,5}$")


def _observed(text: str, match: re.Match[str]) -> bool:
    prefix = text[max(0, match.start() - 16) : match.start()]
    prefix = re.split(r"但是|但|后来|随后|[，。；]|\bbut\b", prefix, flags=re.I)[-1]
    return not (
        _NEGATED.search(prefix)
        or _REQUESTED.search(prefix)
        or re.search(r"没有|未|从未|不曾", match.group(0))
    )


def chinese_risk(text: str) -> tuple[RiskLevel, str] | None:
    patterns = (
        (
            RiskLevel.CRITICAL,
            "ransomware",
            r"(?:文件|数据).{0,12}(?:被加密|遭到加密)|(?:出现|收到|遭遇).{0,8}勒索",
        ),
        (
            RiskLevel.CRITICAL,
            "data_exfiltration",
            r"(?:公司数据|客户数据|客户记录).{0,15}(?:泄露|被盗|被公开|被出售)",
        ),
        (RiskLevel.HIGH, "malware_symptoms", r"(?:异常弹窗|奇怪窗口|不断弹出|不停弹窗)"),
        (
            RiskLevel.HIGH,
            "credentials_submitted",
            r"(?:输入|提交|填入|填进|提供|交给|告诉|发送).{0,12}(?:密码|口令|验证码|验证代码|MFA|OTP)",
        ),
        (
            RiskLevel.HIGH,
            "credentials_submitted",
            r"(?:密码|口令|验证码|验证代码).{0,12}(?:填进|提交给|发给|告诉了|泄露|填入)",
        ),
        (
            RiskLevel.HIGH,
            "attachment_executed",
            r"(?:打开|运行|执行).{0,12}(?:邮件|陌生|可疑).{0,6}附件",
        ),
        (
            RiskLevel.MEDIUM,
            "clicked_link",
            r"(?:点击了|点开了|点了|已经点击|已点击|点击).{0,12}(?:链接|网址)",
        ),
    )
    found: list[tuple[RiskLevel, str]] = []
    for level, label, pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            if not _observed(text, match):
                continue
            if label == "credentials_submitted" and re.search(
                r"(?:要求|让我|叫我).{0,6}$", text[: match.start()]
            ):
                continue
            found.append((level, label))
    return max(found, key=lambda item: item[0].rank) if found else None


def routine_activity(text: str) -> bool:
    """Explicit trusted activity with no contrary incident evidence."""
    from app.core.policy_facts import affirmative, normalized

    if affirmative(
        normalized(text),
        r"fake|phish|suspicious|compromis|stolen|unexpected|malware|attacker|ransom|encrypt|"
        r"exfil|leak|unauthor|infect|hacker|keylogger|virus|trojan|rootkit|strange|someone|"
        r"not\s+(?:me|mine)|did\s+not\s+(?:request|initiate)|假的|钓鱼|可疑|泄露|异常|陌生|入侵|勒索|病毒|感染|恶意|被盗",
    ):
        return False
    return bool(
        re.search(
            r"official\s+(?:company|corporate)\s+(?:portal|website)|"
            r"trusted\s+(?:corporate|company)\s+(?:vpn|portal)|"
            r"approved\s+(?:document|file)|批准.{0,8}(?:文档|文件)|公司官方.*(?:门户|登录)|正常登录",
            text,
            re.I,
        )
    )


def no_disclosure(text: str) -> bool:
    return bool(
        re.search(
            r"\b(?:did\s+not|didn't|never|have\s+not)\s+(?:give|enter|submit|provide|type)\b"
            r"|(?:没有|未|没|从未).{0,4}(?:输入|提交|提供|交给)",
            text,
            re.I,
        )
    ) and not re.search(
        r"\bbut\s+(?:i\s+)?(?:did|entered|gave|submitted)|但是.*(?:输入了|提交了)", text, re.I
    )


def resolve_credential_followup(text: str) -> tuple[str, str]:
    """Resolve only an active credential question; status can remain ambiguous."""
    if re.search(r"\bboth\b|两个都|都做了|两种情况都有", text, re.I):
        return text, "ambiguous"
    from app.core.policy_facts import affirmative, normalized

    if affirmative(
        normalized(text),
        r"\b(?:gave|submitted|entered|typed|provided|supplied|disclosed|sent)\b.{0,30}\b(?:code|otp|password|credentials)\b|\b(?:code|otp|password|credentials)\b.{0,20}\bsubmitted\b",
    ):
        return (
            "I entered my credentials or verification code on the suspicious phishing page.",
            "resolved",
        )
    if re.search(r"^(?:no\b|没有|没输入|未输入)|\bi\s+did\s+not\b", text.strip(), re.I):
        return (
            "I did not enter any credentials or code on the phishing page.",
            "resolved",
        )
    if re.search(
        r"^(?:yes[,\s]+)?i\s+did\b|(?:是的|确实).{0,8}输入|"
        r"(?:只|已经|我)?输入了.{0,4}(?:验证码|密码)|"
        r"\b(?:gave|submitted|entered|typed|provided)\b.{0,25}\b(?:code|password|credentials)\b",
        text,
        re.I,
    ):
        return (
            "I entered my credentials or verification code on the suspicious phishing page.",
            "resolved",
        )
    return text, "pending"
