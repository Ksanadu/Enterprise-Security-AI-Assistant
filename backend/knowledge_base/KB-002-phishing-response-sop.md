---
document_id: KB-002
title: Phishing Response SOP
category: sop
allowed_roles:
  - employee
  - it
  - security
version: "2.4"
last_reviewed: "2024-02-02"
owner: Security Operations
summary: >-
  What every employee should do when they receive a suspicious email, and what
  to do if they already clicked a link or entered credentials.
---

# Phishing Response SOP (Employee Procedure)

## 中文摘要：可疑邮件与钓鱼响应

收到邮件要求点击链接重新登录公司邮箱或重新验证账号时，应视为钓鱼邮件警告，不要点击链接或提交密码、验证码。未交互时使用邮件客户端的钓鱼报告按钮报告；核对发件人和链接真实目的地。

如果点击了可疑链接但没有输入信息，应关闭页面、用受管理的终端保护工具扫描设备并报告事件。如果已经在钓鱼页面输入密码或验证码，应立即用另一台可信设备更改密码、退出全部会话并联系安全团队，保留原邮件供调查。打开可疑附件后应断开网络并报告。

> **Simulated content.** Fictional sample documentation for a demonstration
> system.

## 1. Recognise the signs

Treat an email as suspicious when it shows any of these signals:

* it asks you to **click a link and log in** to "re-verify", "unlock" or
  "restore" your account;
* the sender address is *almost* right (`it-support@company-helpdesk.net`);
* the greeting is generic, or the tone is urgent and threatening ("your account
  will be closed in 24 hours");
* the link text and the real destination do not match — hover before you click;
* the message asks for a password, an MFA code, a payment or gift cards;
* an unexpected attachment, especially an invoice, shipping notice or résumé;
* a reply-to address that differs from the sender;
* it arrives in a thread you were not part of, or as a reply to a message you
  never sent.

## 2. If you have NOT clicked anything

1. **Do not reply** to the message and do not forward it to colleagues.
2. Use the **Report Phishing** button in the mail client. This sends the message
   to the security team with full headers.
3. Delete the message from your inbox after reporting.
4. If the "Report Phishing" button is unavailable, forward the message as an
   attachment to `phishing@example.com` and then delete it.

## 3. If you clicked a link but entered nothing

1. Close the browser tab immediately.
2. Run a full scan with the managed endpoint protection agent.
3. Report the event to the security team — a click alone is a low-risk event,
   but it must still be recorded.
4. Watch for follow-up emails that reference the first one.

## 4. If you entered your password

**This is a high-risk event. Act immediately.**

1. Change your password from a **different, known-good device** — do not use the
   machine you were on if you are unsure about it.
2. If MFA was approved, sign out of all sessions and re-enrol your second
   factor.
3. Report to the security team immediately by phone or the security hotline, not
   only by email.
4. Preserve the original message: do not delete or "clean" it before the
   security team has collected it.
5. Expect a call from the security team and follow their instructions until the
   account is confirmed clean.

The security team will open a security incident ticket, revoke active sessions,
review sign-in logs and mailbox rules for forwarding or delegation changes, and
verify that no mailbox rule was created to exfiltrate mail.

## 5. If you opened an attachment

1. Disconnect the device from the network (unplug the cable or disable Wi-Fi).
2. Do **not** keep working on the device and do not plug in USB storage.
3. Report immediately — an attachment may execute malware without any visible
   sign (see the Malware Incident Response SOP, available to the security team,
   and the Endpoint Security Guide for immediate containment steps).

## 6. Service desk and IT responsibilities

IT support must:

* confirm whether the reported sender domain is internal;
* check whether other mailboxes received the same message (search by subject
  and sender);
* if a credential was entered, escalate to the security team within 15 minutes;
* never ask a user to send their password or MFA code for "verification".

## 7. Response targets

| Situation | Target first response |
| --------- | --------------------- |
| Credentials entered, MFA approved, or attachment executed | 15 minutes, on-call security engineer |
| Clicked link, nothing entered | 4 business hours |
| Report only, no interaction | 1 business day (bulk triage) |
