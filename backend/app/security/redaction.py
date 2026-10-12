"""Redaction of credential-like material from stored text.

Users paste secrets into chat. A user reporting "I entered my password hunter2"
is doing exactly what they should, but the *value* must not then be copied into a
ticket body, a note, or an audit detail where it lives on for months and gets
read by more people than the original conversation.

This module extends the log redactor with a pattern for the conversational form -
a credential noun followed by a bare value - which the log patterns deliberately
do not cover, because log lines are usually ``key=value``.

The heuristic errs towards masking: a false positive costs a reader one
``***REDACTED***`` in a ticket, a false negative leaves a password on record.
"""

from __future__ import annotations

import re

from app.core.logging import redact as redact_assignments

#: Nouns that introduce a credential value in ordinary prose.
CREDENTIAL_NOUNS = (
    r"(?:password|passwd|passphrase|credential|secret|token|api[\s-]?key|otp|"
    r"one[\s-]?time\s+(?:code|password|pin)|recovery\s+code|verification\s+code|pin|API\s*密钥|密码|口令|验证码|密钥)"
)
_CREDENTIAL_PREFIX = rf"(?i)(?<![A-Za-z])(?P<noun>[\"']?{CREDENTIAL_NOUNS}[\"']?)(?![A-Za-z])"

#: "my password hunter2" / "the token abc123def" / "password: hunter2"
_PROSE_CREDENTIAL = re.compile(
    _CREDENTIAL_PREFIX + r"(?P<sep>\s*(?:is|was|是|为|=|:)?\s*)"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9!@#$%^&*_\-.]*"
    r"(?:\s+(?!(?:on|in|to|into|at|for|from|with|after|before|and|but|because|then|through)\b)"
    r"[A-Za-z0-9][A-Za-z0-9!@#$%^&*_\-.]*){0,7})"
)

#: A quoted value after a credential noun is the secret almost by definition, so
#: it is masked regardless of shape: `passphrase "correct horse battery staple"`.
_QUOTED_CREDENTIAL = re.compile(
    _CREDENTIAL_PREFIX + r"(?P<sep>\s*(?:is|was|是|为|=|:)?\s*)"
    r"(?P<q>[\"'])(?P<value>[^\"']{1,})(?P=q)"
)

#: One-time codes are short, so the length rule above would miss them.
#: "otp 918273" and "recovery code 483920" must still be masked.
#: Note the single braces: this fragment is a plain raw string, not an f-string.
_SHORT_CODE = re.compile(
    _CREDENTIAL_PREFIX + r"(?P<sep>\s*(?:is|was|是|为|=|:)?\s*)" r"(?P<value>\d{4,10})\b"
)

#: Values that are clearly not secrets, so masking them would only confuse the
#: reader: the words people use when describing the *concept*.
_NOT_A_SECRET = frozenset(
    """
    requirement requirements policy policies guideline guidelines manager management
    strength complexity rotation expiry expired changed changing reset resets
    authentication authorisation authorization protection compromised breached
    something anything anything nothing everything problem question incident
    on in to into at for from with after before and but because then through
    is was are be been a an the my your our their should must can could would will
    not never without required mandatory optional expired enabled disabled
    changes change reset resetting entered submitted secure safe good weak strong
    """.split()
)

_REDACTED = "***REDACTED***"

# Explicit separators or whitespace identify Unicode values, without treating
# every Chinese character after a bare noun (e.g. 密码要求) as a credential.
_UNICODE_PROSE = re.compile(
    _CREDENTIAL_PREFIX + r"(?P<sep>\s*(?:is\b|was\b|是|为|=|:|：)\s*|\s+)"
    r"(?P<value>[^\s，。；！？、,;!?\"']+"
    r"(?:\s+(?!(?:on|in|to|into|at|for|from|with|after|before|and|but|because|then|through)\b)"
    r"[^\s，。；！？、,;!?\"']+){0,7})"
)
_UNICODE_QUOTES = tuple(
    re.compile(
        _CREDENTIAL_PREFIX
        + r"(?P<sep>\s*(?:is|was|是|为|=|:|：)?\s*)"
        + rf"(?P<open>{re.escape(opening)})(?P<value>[^{re.escape(closing)}]+)(?P<close>{re.escape(closing)})"
    )
    for opening, closing in (("“", "”"), ("\u2018", "\u2019"), ("「", "」"), ("『", "』"))
)
_CHINESE_CONCEPTS = frozenset(
    {
        "多少位",
        "什么要求",
        "多少个字符",
        "多长",
        "长度要求",
        "最小长度",
        "要求",
        "规则",
        "政策",
        "策略",
    }
)


def _looks_like_a_secret(value: str) -> bool:
    """Mask short/plain values too; preserve recognizable policy vocabulary."""
    lowered = value.lower().split()[0]
    return lowered not in _NOT_A_SECRET


def redact_credentials(text: str) -> str:
    """Mask credential-like values in ``text``.

    Applies the assignment and quoted patterns used for logs, then the
    conversational patterns above. Quoted values and short numeric codes are
    masked unconditionally; unquoted prose values only when they look like a
    secret, so an ordinary sentence about password policy is left alone.
    """
    if not text:
        return text

    cleaned = text

    def _mask_unconditional(match: re.Match[str]) -> str:
        quote = match.groupdict().get("q") or ""
        return f"{match.group('noun')}{match.group('sep')}{quote}{_REDACTED}{quote}"

    def _mask_if_secret(match: re.Match[str]) -> str:
        value = match.group("value")
        if not _looks_like_a_secret(value):
            return match.group(0)
        if value.endswith("."):
            # Keep a sentence-ending period outside the mask.
            return f"{match.group('noun')}{match.group('sep')}{_REDACTED}."
        return f"{match.group('noun')}{match.group('sep')}{_REDACTED}"

    def _unicode_value(match: re.Match[str]) -> str:
        value = match.group("value")
        if _REDACTED in value or not any(ord(character) > 127 for character in value):
            return match.group(0)
        if value in _CHINESE_CONCEPTS or re.fullmatch(
            r"(?:最小|最低)?长度\s*(?:是多少|有什么要求)?", value
        ):
            return match.group(0)
        return _mask_if_secret(match)

    for pattern in _UNICODE_QUOTES:
        cleaned = pattern.sub(
            lambda match: f"{match.group('noun')}{match.group('sep')}{match.group('open')}{_REDACTED}{match.group('close')}",
            cleaned,
        )
    cleaned = _QUOTED_CREDENTIAL.sub(_mask_unconditional, cleaned)
    cleaned = _UNICODE_PROSE.sub(_unicode_value, cleaned)
    cleaned = _PROSE_CREDENTIAL.sub(_mask_if_secret, cleaned)
    cleaned = _SHORT_CODE.sub(_mask_unconditional, cleaned)
    return redact_assignments(cleaned)
