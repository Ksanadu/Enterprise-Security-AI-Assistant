# Phase 8 当前交付记录

2026-10-13。本地原型可以交付演示与继续开发；完整方案尚未最终签收。本轮交付不等于正式上线，也不把离线结果当作真实模型或独立质量验收。

本轮工程门禁exit0：后端1803通过、7项Docker/POSIX环境条件跳过，覆盖率94.86%；前端81通过，全部类型/静态/秘密检查通过。交付/文档38项针对性检查及追加视觉证据后11项交付检查通过。实际本地包预检成功，最终输出目录为 `logs/phase8/local-delivery-20261013`；摘要以其manifest读取，避免将自引用摘要写入源码文档。

## 交付内容与对应版本

- 源码、设计文档、模拟知识库、测试/冻结评测数据、依赖清单及全部执行说明。
- 后端运行代码/知识库/迁移/脚本与预构建前端的本地运行包；依赖已安装的 Python，不是自包含 Docker镜像。
- 工程门禁、独立前后端 Demo、保留 CLI及两个制品回滚的证据；首次质量失败和调优后的回归摘要一起保留。
- 保存已有桌面/窄屏通知界面截图。它们是Phase7实际浏览器证据，前端源码本轮未改，不宣称重新执行了浏览器视觉验收。
- 机器可读的13项标准映射、四类外部门禁、源码/制品/证据 SHA-256 清单。摘要校验确认内容一致，正式可信签名和制品权限需部署方提供。

交付工具创建新目录，拒绝覆盖；目录包含 `source.zip`、`runtime.zip`、`acceptance.json`、`manifest.json` 和 `evidence/`。不包含 `.env`、业务数据库/备份、向量缓存、私钥、模拟登录令牌或无关 KIMI文件。证据中的质量摘要不复制问答正文。

```powershell
.\backend\.venv\Scripts\python.exe scripts/phase8-delivery.py build --output logs/phase8/local-delivery-20261013 --runtime logs/phase7/releases/retention-candidate.zip --gate logs/phase0/phase8-engineering-gate.log
.\backend\.venv\Scripts\python.exe scripts/phase8-delivery.py verify --output logs/phase8/local-delivery-20261013
.\backend\.venv\Scripts\python.exe scripts/phase8-delivery.py verify --output logs/phase8/local-delivery-20261013 --require-final
```

最后一个命令在外部门禁未完成时返回 exit 2，即使包的摘要一致也不允许称为最终通过。构建不会运行真实模型、迁移现有业务库或修改 `.env`。包内记录的源码摘要和门禁文件是本轮依据；历史提交仅说明工作树起点，当前未提交/推送版本。

## 启动、演示及验收

在完整源码工作目录按 [README](../README.md) 和 `scripts/setup-local.ps1`恢复依赖。当前恢复的是 ESAA 项目虚拟环境；系统 `python` 可能仍指向 Windows 应用别名，运行请使用 `backend/.venv/Scripts/python.exe`。源码包不携带虚拟环境和 npm缓存，依赖恢复需要网络或预置包。

本轮实际构建环境为 Python3.12.14、Node26.9.0、npm11.19.1；已安装Python包版本记录在 [PHASE8_ENVIRONMENT.json](PHASE8_ENVIRONMENT.json)，前端依赖依据package-lock。该摘要便于复现，不是跨平台锁文件，也未复制秘密配置。

`scripts/run-demo.ps1 -Fresh` 创建独立模拟数据，默认浏览器端口5180/API8110；端口占用时明确指定新端口，不终止其他实例。`-Check -DemoCheck` 自动验收并停止本次服务。演示使用 Mock+TF-IDF，不触达 `.env` 中的真实模型或通知/保留配置。

演示依次展示密码政策、钓鱼追问、密码/验证码泄露后的同一工单升级、员工/IT/Security权限差异，以及 Security后台和人工处理。界面接收确认与人工接手分别展示；已有桌面/窄屏视觉证据对应当前未改的前端。

运行配置见 `.env.example`；不要将密钥发到聊天或报告。真实模式需按 [质量入口](QUALITY_EVALUATION.md) 提供调用上限，再做答案/引用审阅。Docker按 [容器说明](CONTAINER_ACCEPTANCE.md) 执行；配置模板和 CI不等于实际容器通过。

## 原设计核查

[验收矩阵](ACCEPTANCE_MATRIX.md)逐项映射 PRODUCT_SPEC §9。§2 中文 A/B/C/D、§7权限/脱敏/审计/升级/结构化解析、§8七个必需字段和§10多轮演示均有本地自动验收。字段位于 `assistant_message.payload`，保留 `intent`、`risk_level`、`answer`、`recommended_actions`、`source_documents`、`human_escalation`、`create_ticket`，额外字段描述实际状态。

员工 VPN 使用可授权的 KB-012，内部 IT SOP KB-005仍受权限限制。`create_ticket`是决策，`ticket_created`/`workflow_status`反映实际结果；建单失败保持 pending 并由恢复 worker重试。`context_supplied`不代表语义引用支持已获审阅。

## 必须完成的四类门禁

| 门禁 | 当前事实 | 关闭条件 |
| --- | --- | --- |
| Docker | 本机缺少 CLI/Engine；7项工程测试依赖 Docker/POSIX shell被跳过 | 实际构建、启动、代理/卷、重启/故障及浏览器矩阵通过 |
| 真实 LLM/Embedding | 用户稍后配置；当前密钥未检测到 | 三模式实际执行、明确预算与调用记录、答案引用/安全建议审阅及费用依据 |
| 独立质量 | v1首次失败；调优回归意图109/115低于95%，六项标签冲突仍冻结 | 独立审阅边界和新未参与调优的冻结验收集；保留旧失败，不降低阈值 |
| 正式运维 | 本地迁移、共享预算、通知TLS、保全/恢复/回滚已有证据 | 正式入口TLS、收件/告警监督、批准政策/加密权限、秘密托管、正式镜像回滚及责任/RPO/RTO |

具体负责人尚未指定，机器清单使用责任角色。未完成事项是结项条件，不是可选优化。配置真实密钥不会自动使已记录的旧包变为最终签收，需执行缺失验收后生成新交付记录。

## 恢复与已知限制

生产先备份、显式迁移到 schema04，再用正式账号启动；拒绝已知活跃演示账号。保留政策默认不启用，不擅自规定真实期限。操作见 [账号](OPS_ACCOUNTS.md)、[迁移](OPS_MIGRATIONS.md)、[保留](OPS_RETENTION.md)、[备份](OPS_BACKUP.md)、[发布](OPS_RELEASE.md)、[通知](OPS_NOTIFICATIONS.md)、[巡检](OPS_MONITORING.md)。

恢复到新数据库文件，选择匹配构建及签名秘密；冻结写入并登记备份后的损失范围，核对外部通知去重和擦除/保全历史。字段清除不证明磁盘/WAL/旧备份不可恢复。单机 SQLite扩容、另一数据库驱动/迁移/事务、跨主机恢复与负载上限仍需专门验收。
