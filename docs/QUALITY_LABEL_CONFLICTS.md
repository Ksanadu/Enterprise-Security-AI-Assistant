# 质量标签冲突记录（保留 v1 冻结结果）

2026-10-12，`validation-regression-observed` 的风险、送达、阻断及多轮均通过，意图 109/115（94.78%）仍低于冻结 95% 门槛，报告返回失败。剩余六题的差异为标签边界，不能通过下调门槛或静默修改冻结数据来消除。

| 事实族 | v1 标签 | 当前/既有回归约定 | 冲突依据 |
| --- | --- | --- | --- |
| password-reuse-3 | security_faq | policy_question | 原 40 题 `faq-004` 将“企业密码是否可复用至个人账号”定为 Policy；v1 对同一权限/复用问题定为 FAQ。 |
| unexpected-mfa-approved（五题） | security_incident | phishing | 原 40 题 `phish-005` 与分类器回归将未发起的 MFA 批准归入 Phishing；v1 将五种同类表达归入 Security Incident。 |

风险与人工升级约定一致，均不会因为该意图冲突丢失高风险工单。实现已统一 MFA 改写的分类，避免依据“request”或“initiate”的措辞差异改变标签。

需要统一意图定义，再创建有明确修订理由的新评测版本；v1 及首次失败记录保持不变。已有 v1 被用于修复，不能再作为全新的独立验收。独立标注审阅、新的未参与调优集合和真实模型质量验收仍待完成。
