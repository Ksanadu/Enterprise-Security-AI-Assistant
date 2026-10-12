"""Bilingual observed facts mapped to the simulated KB-009 severity policy.

The normalization is internal to rules. It is never sent to a model, stored as
the user's statement, or used to decide document permissions.
"""

from __future__ import annotations

import re

from app.core.enums import Intent, RiskLevel

TERMS = {
    "确认了": " approved ",
    "多因素认证": " mfa ",
    "页面": " page ",
    "已点开": " opened ",
    "邮箱": " mailbox ",
    "文件": " files ",
    "数据": " data ",
    "客户": " customer ",
    "泄露": " leaked ",
    "盗取": " stole ",
    "未经授权": " unauthorized ",
    "被别人登录": " accessed by someone else ",
    "进入": " accessed ",
    "点开": " opened ",
    "攻击者": " attacker ",
    "控制了": " took control ",
    "恶意": " malicious ",
    "发件人": " sender ",
    "链接": " link ",
    "网址": " link ",
    "影响了": " affected ",
    "批准": " approved ",
    "输入": " entered ",
    "尚未确认": " unconfirmed ",
    "未确认": " unconfirmed ",
    "无法确认": " unconfirmed ",
    "没有": " did not ",
    "未": " not ",
    "没有异常": " normal ",
    "提交给": " submitted to ",
    "提交了": " submitted ",
    "提交到": " submitted to ",
    "提交": " submitted ",
    "给了": " gave ",
    "收到了": " received ",
    "收到": " received ",
    "输入了": " entered ",
    "告诉了": " gave ",
    "提供了": " provided ",
    "发送了": " sent ",
    "填进了": " entered ",
    "填入了": " entered ",
    "点开了": " opened ",
    "点击了": " clicked ",
    "已点击": " clicked ",
    "已打开": " opened ",
    "运行了": " ran ",
    "执行了": " executed ",
    "启用了": " enabled ",
    "被执行了": " executed ",
    "已经运行": " ran ",
    "运行": " running ",
    "已经提交": " submitted ",
    "已经": " already ",
    "已确认": " confirmed ",
    "确认": " confirmed ",
    "被控制": " compromised ",
    "被入侵": " compromised ",
    "被攻击者控制": " compromised by attacker ",
    "失陷": " compromised ",
    "感染": " infected ",
    "恶意软件": " malware ",
    "恶意程序": " malware ",
    "病毒": " malware ",
    "勒索软件": " ransomware ",
    "勒索": " ransom ",
    "被加密": " encrypted ",
    "加密": " encrypted ",
    "远程擦除": " remote wipe ",
    "已成功": " succeeded ",
    "成功": " succeeded ",
    "已擦除": " wiped ",
    "丢失": " lost ",
    "被偷走": " stolen ",
    "特权": " privileged ",
    "管理员": " admin ",
    "账号": " account ",
    "帐号": " account ",
    "服务器": " server ",
    "电脑": " computers ",
    "终端": " endpoints ",
    "笔记本": " laptop ",
    "设备": " device ",
    "一次性验证码": " one-time code ",
    "验证码": " verification code ",
    "密码": " password ",
    "口令": " password ",
    "钓鱼": " phishing ",
    "假的": " fake ",
    "陌生": " suspicious ",
    "可疑": " suspicious ",
    "冒充": " impersonating ",
    "骗子": " phishing caller ",
    "附件": " attachment ",
    "安装程序": " installer ",
    "安装包": " installer ",
    "宏程序": " macro ",
    "宏": " macro ",
    "上传": " uploaded ",
    "公开资料": " public information ",
    "非敏感": " non-sensitive ",
    "未授权": " unapproved ",
    "未经批准": " unapproved ",
    "云存储": " cloud storage ",
    "云盘": " cloud storage ",
    "不受支持": " unsupported ",
    "未管理": " unmanaged ",
    "尝试访问": " attempted access ",
    "尝试接入": " attempted access ",
    "批准了": " approved ",
    "并非自己发起": " unexpected ",
}


def normalized(text: str) -> str:
    for source in sorted(TERMS, key=len, reverse=True):
        text = text.replace(source, TERMS[source])
    for word, number in (
        ("four", 4),
        ("five", 5),
        ("six", 6),
        ("seven", 7),
        ("eight", 8),
        ("nine", 9),
    ):
        text = re.sub(
            rf"\b{word}\s+(?=computers?|workstations?|endpoints?|devices?)",
            str(number) + " ",
            text,
            flags=re.I,
        )
    for word, number in (("四", 4), ("五", 5), ("六", 6), ("七", 7), ("八", 8), ("九", 9)):
        text = re.sub(
            rf"{word}(?:台|个)?\s*(?=computers|endpoints|device)", str(number) + " ", text
        )
    return re.sub(r"([\u4e00-\u9fff]+)", r" \1 ", text)


def observed(text: str, start: int) -> bool:
    prefix = re.split(
        r"\b(?:but|however|then)\b|[.;!?。；！？，]|但是|但|后来|随后",
        text[max(0, start - 55) : start],
        flags=re.I,
    )[-1]
    return not re.search(
        r"(?:\b(?:not|no|never|without|unconfirmed|hypothetical|if|didn't|haven't)\b|没有|未|没|从未|要求|让我|叫我|如果|会不会|是否)[\s\w]{0,28}$",
        prefix,
        re.I,
    )


def affirmative(text: str, pattern: str) -> bool:
    # A negated noun-first match must not consume the later affirmative verb:
    # “No password, but I submitted the code.” contains overlapping candidates.
    return any(
        observed(text, match.start())
        and not re.search(r"\b(?:not|no|never|unconfirmed|didn't|haven't)\b", match.group(1), re.I)
        for match in re.finditer(f"(?=({pattern}))", text, re.I)
    )


def policy_fact(description: str) -> tuple[RiskLevel, str] | None:
    text = normalized(description)
    if affirmative(
        text,
        r"\bransomware\b.{0,45}\bencrypted\b|\bfiles?\b.{0,35}\bencrypted\b.{0,40}\b(?:malware|ransom)\b",
    ):
        return RiskLevel.CRITICAL, "ransomware"
    if affirmative(
        text, r"\b(?:customer\s+data|data|records)\b.{0,60}\b(?:leaked|exfiltrated|stolen)\b"
    ):
        return RiskLevel.CRITICAL, "data_exfiltration"
    if re.search(
        r"^(?:what|how|which|if|如果|咨询).{0,55}(?:future|hypothetical|将来|目前没有|没有实际事件)",
        description,
        re.I,
    ):
        return RiskLevel.LOW, "hypothetical_information"
    malware = affirmative(
        text,
        r"\binfected\b.{0,28}\bmalware\b|\bmalware\b.{0,20}\b(?:running|ran|executed)\b|\b(?:confirmed|running)\b.{0,35}\b(?:malware|infection)\b|\bmalware\b.{0,25}\baffected\b",
    )
    if malware and re.search(r"\bserver\b", text, re.I):
        return RiskLevel.CRITICAL, "server_malware"
    if malware and re.search(
        r"\b(?:[4-9]|[1-9]\d+)\s+(?:computers?|endpoints?|devices?|workstations?)\b", text, re.I
    ):
        return RiskLevel.CRITICAL, "multiple_systems"
    if affirmative(
        text,
        r"\b(?:admin|privileged)\b.{0,35}\baccount\b.{0,40}\b(?:compromised|hacked|controlled|breached|失陷)\b|\b(?:attacker|hacker)\b.{0,35}\b(?:accessed|took\s+control)\b.{0,35}\b(?:admin|privileged)\b",
    ):
        return RiskLevel.CRITICAL, "privileged_account_compromise"
    lost = affirmative(text, r"\blost\b|\bstolen\b")
    encrypted = re.search(r"\b(?:fully\s+)?encrypted\b", text, re.I) and not re.search(
        r"\b(?:not\s+encrypted|unencrypted)\b", text, re.I
    )
    wiped = re.search(
        r"remote\s+wipe.{0,20}(?:succeeded|successful)|successful\s+remote\s+wipe|confirmed.{0,15}remotely\s+wiped",
        text,
        re.I,
    )
    wipe_unknown = re.search(
        r"unconfirmed.{0,25}(?:remote\s+wipe|wiped)|(?:remote\s+wipe|wiped).{0,25}unconfirmed|not\s+been\s+confirmed\s+remotely\s+wiped",
        text,
        re.I,
    )
    if lost and (wipe_unknown or re.search(r"\b(?:not\s+encrypted|unencrypted)\b", text, re.I)):
        return RiskLevel.CRITICAL, "lost_device_unprotected"
    disclosure = affirmative(
        text,
        r"\b(?:submitted|gave|provided|entered|typed|shared|supplied|disclosed|sent)\b.{0,50}\b(?:password|credentials?|(?:verification|one-time|mfa)\s+code|otp)\b(?!\s+(?:reset|policy|requirements?|request|manager|rules|length))|\b(?:password|credentials?|(?:verification|one-time)\s+code|otp)\b.{0,22}\b(?:submitted|gave|provided|sent|disclosed)\b",
    )
    if disclosure and re.search(
        r"phish|fake|caller|impersonat|suspicious|verification|one-time|otp", text, re.I
    ):
        return RiskLevel.HIGH, "credentials_submitted"
    if re.search(r"fake|phish|impersonat", text, re.I) and affirmative(
        text, r"\breplied\b.{0,55}\bwith\b.{0,15}\b(?:password|code|otp)\b"
    ):
        return RiskLevel.HIGH, "credentials_submitted"
    if re.search(r"phish|fake|impersonat", text, re.I) and affirmative(
        text,
        r"\b(?:sender|caller|page|site)\b.{0,25}\b(?:received|got)\b.{0,25}\b(?:password|code|otp)\b",
    ):
        return RiskLevel.HIGH, "credentials_submitted"
    if affirmative(
        text,
        r"\b(?:ran|executed|opened)\b.{0,40}\b(?:malicious|suspicious)\b.{0,30}\b(?:installer|attachment|program)\b|\b(?:malicious|suspicious)\b.{0,30}\b(?:installer|attachment|macro)\b.{0,35}\b(?:ran|running|executed)\b|\benabled\b.{0,50}\bmacro\b",
    ) and re.search(r"malicious|suspicious|phish", text, re.I):
        return RiskLevel.HIGH, "malware_executed"
    if malware:
        return RiskLevel.HIGH, "confirmed_endpoint_malware"
    if affirmative(
        text,
        r"\b(?:account|mailbox)\b.{0,45}\b(?:accessed\s+by\s+(?:someone\s+else|another\s+person)|took\s+control)\b|\bsomeone\s+else\b.{0,20}\b(?:access|accessed)\b.{0,25}\b(?:account|mailbox)\b|\bunauthorized\b.{0,30}\baccessed\b.{0,25}\b(?:account|mailbox)\b",
    ):
        return RiskLevel.HIGH, "account_takeover"
    if affirmative(
        text, r"\b(?:approved|accepted)\b.{0,45}\b(?:mfa|multi-factor|authentication)\b"
    ) and re.search(
        r"unexpected|suspicious|not\s+initiat|not\s+request|没有主动登录|did not.{0,10}主动登录",
        text,
        re.I,
    ):
        return RiskLevel.HIGH, "unexpected_mfa_approved"
    if re.search(
        r"impossible[ -]travel|不可能旅行|异地登录|距离很远.{0,20}连续登录|logged\s+in.{0,25}distant\s+countries",
        description,
        re.I,
    ):
        if affirmative(
            text, r"\bconfirmed\b.{0,15}\bdata\s+access\b|\bdata\s+access\b.{0,15}\bconfirmed\b"
        ):
            return RiskLevel.HIGH, "account_anomaly_with_data_access"
        return RiskLevel.MEDIUM, "account_activity_anomaly"
    if re.search(r"phish|fake|suspicious|邮件", text, re.I) and affirmative(
        text,
        r"\b(?:clicked|opened)\b.{0,40}\b(?:link|page)\b|\b(?:link|page)\b.{0,20}(?:clicked|opened)",
    ):
        return RiskLevel.MEDIUM, "clicked_link"
    if (
        re.search(r"unapproved|unauthorized|unauthorised", text, re.I)
        and re.search(r"cloud|storage", text, re.I)
        and re.search(r"upload", text, re.I)
        and re.search(r"non-sensitive|public|普通公开|不含受限", text, re.I)
    ):
        return RiskLevel.MEDIUM, "unapproved_public_upload"
    if re.search(r"\b(?:unsupported|unmanaged)\b.{0,12}\bdevice\b", text, re.I) and re.search(
        r"attempt|tried|尝试", text, re.I
    ):
        return RiskLevel.MEDIUM, "unsupported_device_access"
    if re.search(r"popup|pop-up|弹窗|奇怪窗口", text, re.I) and re.search(
        r"do\s+not\s+know|unconfirmed|不知道原因|原因不明|did not.{0,15}发现|没有发现|no\s+malicious",
        text,
        re.I,
    ):
        return RiskLevel.MEDIUM, "unconfirmed_popups"
    if lost and encrypted and wiped and not wipe_unknown:
        return RiskLevel.LOW, "lost_device_wiped"
    if (
        re.search(r"\b(?:approved|authorized|authorised)\b", text, re.I)
        and re.search(r"encrypted", text, re.I)
        and not affirmative(text, r"\b(?:ransomware|malware|attacker)\b")
    ):
        return RiskLevel.LOW, "authorized_encryption"
    if (
        re.search(r"approved|authorized|authorised|批准", text, re.I)
        and re.search(r"(?:simulated|controlled|training|drill|演练|模拟|培训)", text, re.I)
        and not affirmative(text, r"\b(?:infected|compromised|stolen|attacker)\b")
    ):
        return RiskLevel.LOW, "authorized_training"
    if re.search(
        r"\b(?:malware|malicious)\b[^.!?;]{0,20}\battachment\b[^.!?;]{0,25}\bquarantined\b[^.!?;]{0,20}\bbefore\b[^.!?;]{0,20}\bopened\b",
        description,
        re.I,
    ):
        return RiskLevel.LOW, "attachment_blocked_without_execution"
    if re.search(
        r"\b(?:no|not|never)\b.{0,25}\b(?:ransomware|encrypted|ran|run|running|executed|execute|opened|open)\b|(?:没有|未).{0,12}(?:加密|执行|运行|打开)",
        text + " " + description,
        re.I,
    ):
        return RiskLevel.LOW, "denied_activity"
    if (
        re.search(r"^(?:may|can|should)\s+i\b", description.strip(), re.I)
        and re.search(r"\b(?:give|share|reuse)\b.{0,50}\bpassword\b", description, re.I)
        and not affirmative(text, r"\b(?:gave|submitted|provided|sent|disclosed)\b")
    ):
        return RiskLevel.LOW, "credential_policy_question"
    return None


def domain_intent(text: str) -> Intent | None:
    fact = policy_fact(text)
    if fact:
        if fact[1] == "credential_policy_question":
            return (
                Intent.POLICY_QUESTION
                if re.search(r"\breuse\b", text, re.I)
                else Intent.SECURITY_FAQ
            )
        if fact[1] == "denied_activity":
            return (
                Intent.SECURITY_INCIDENT
                if re.search(r"malicious|malware|ransom|勒索|恶意|可疑附件", text, re.I)
                else None
            )
        if fact[1] == "unexpected_mfa_approved":
            return Intent.PHISHING
        if fact[1] == "credentials_submitted" or fact[1] == "clicked_link":
            return Intent.PHISHING
        if fact[1] == "authorized_encryption":
            return Intent.POLICY_QUESTION
        if fact[1] == "authorized_training":
            return Intent.POLICY_QUESTION
        if fact[1] != "hypothetical_information":
            return Intent.SECURITY_INCIDENT
    if re.search(
        r"(?:approved|批准).{0,30}(?:software|application|installation|软件|应用)|(?:安装|部署).{0,25}(?:批准|approved)",
        text,
        re.I,
    ):
        return Intent.IT_SUPPORT
    if re.search(
        r"(?:fake|假的).{0,30}(?:login|登录)|(?:phish|suspicious).{0,25}(?:invoice|email)|可疑.{0,12}(?:登录|网址)|邮件.{0,12}陌生|(?:冒充|骗子|impersonat).{0,35}(?:password|密码|code|验证码)",
        text,
        re.I,
    ):
        return Intent.PHISHING
    if re.search(r"数据分类|按敏感性|requesting\s+access.{0,20}(?:system|company)", text, re.I):
        return Intent.POLICY_QUESTION
    if re.search(r"\b(?:working|work)\s+from\s+home\b", text, re.I):
        return Intent.POLICY_QUESTION
    if re.search(
        r"(?:安全团队|security\s+team).{0,20}(?:联系|报告流程)|联系.{0,15}安全团队", text, re.I
    ):
        return Intent.SECURITY_FAQ
    if re.search(
        r"病毒|恶意安装|可疑.{0,12}安装|特权账号|设备.{0,12}丢失|笔记本.{0,8}丢失|丢失.{0,8}设备",
        text,
    ):
        return Intent.SECURITY_INCIDENT
    return None
