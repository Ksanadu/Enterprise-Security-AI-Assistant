# 运维状态、日志与外部巡检

目前具备实际 API 巡检和可接入告警系统的输出，尚未接入正式值班告警平台或生产进程监督器。

## 状态与告警条件

`GET /api/v1/operations/status` 只允许 Security 用户访问，查询持久化数据库和本进程的知识库就绪状态。输出没有工单编号、正文、账号、端点 URL 或秘密。它不是业务就绪接口；`/api/v1/ready` 仍独立检查知识库和事件/通知/共享预算存储，故障返回 503。

| 告警代码 | 条件 |
| --- | --- |
| `knowledge_unavailable` | 知识库未就绪 |
| `notification_receiver_unconfigured` | 没有事件接收端配置 |
| `workflow_backlog_over_5m` | 创建超过 5 分钟的 pending/processing 升级任务仍未完成 |
| `notification_backlog_over_5m` | 创建超过 5 分钟的 pending/processing 通知仍未确认 |
| `notification_retry_exhausted` | 存在重试耗尽或最终尝试结果不确定的通知 |
| `high_risk_notification_missing` | 未人工响应的当前 High/Critical 工单缺少本级别事件通知记录，包括升级前存量工单 |
| `high_risk_response_overdue` | 当前 High/Critical 非终结工单超过响应期限，没有自本次升级以来的人工响应 |
| `model_failures_last_hour` | 最近 60 分钟已记录回答中的模型网络失败或预算耗尽 |
| `workflow_failures_last_hour` | 最近 60 分钟存在升级失败审计 |

状态同时提供按状态的队列数量、超期数量和模型故障计数。故障后成功降级仍计模型失败；历史超过窗口的故障不持续触发。人工响应需为 IT/Security 的非自动状态变更或备注，升级以前的备注和自动 Escalated 不消除超时。

这些是 SQLite 单机试点的查询，不能代替负载容量、进程心跳和每个 worker 的健康度监控。模型计数来自已提交的回答审计，不包含未提交请求和进程启动失败；启动/未处理异常须同时由日志及外部存活探测观察。

人工响应超时直接查询工单及风险升级时间线，不依赖通知表是否有记录；最新当前级别升级以前的响应不能消除新升级告警。`notifications.missing_incident_count` 显示需补齐的存量记录，worker 每批最多补齐 500 条，按事件键去重。历史未响应告警会在升级后立即显现，不重新从迁移时刻计算期限。

## 巡检入口

从独立监控进程提供 `ESAA_MONITOR_BASE_URL`、`ESAA_MONITOR_EMAIL`、`ESAA_MONITOR_PASSWORD`，使用专门配置的 Security 巡检账号；密码从受限环境/秘密管理提供，不放在命令参数或版本库。必要时设置 `ESAA_MONITOR_CA_FILE`。本脚本读取进程环境，不自动读取应用 `.env`。

```powershell
backend/.venv/Scripts/python.exe scripts/ops-monitor.py --once
backend/.venv/Scripts/python.exe scripts/ops-monitor.py --interval 300
```

生产地址必须 HTTPS，HTTP 仅限 loopback；拒绝 URL 中的凭据、查询与片段，不跟随重定向，不使用系统代理，TLS 验证保持开启。每次实际访问 ready、登录、状态接口，最后撤销巡检会话。单次每个网络请求有 10 秒期限。连续模式最短间隔 60 秒，默认 300 秒，仅在状态/告警集合改变时输出 JSON；调用失败仍报告 `monitor_probe_failed`，不会把失败解释为健康。

单次退出码：0 无告警，1 有告警，2 配置/认证/网络/协议错误。标准输出只保留允许的告警代码、时间、耗时和异常类别，不打印上游响应或异常文本。将退出码/JSON 接入已有监控调度器，并监控巡检进程自身的退出和心跳；持续故障的重复通知、值班轮换和接收人由正式告警平台配置。没有实际安装调度器或接收人时，不能宣称告警已正式上线。

## 请求日志

应用配置 `LOG_FORMAT=json` 后，访问日志包含 `request_id`、`method`、`route`、`status`、`duration_ms`。路由使用模板，例如 `/api/v1/tickets/{reference}`，不记录实际编号、查询字符串、正文或 Authorization。找不到路由时标为 `<unmatched>`。请求 ID 在记录生成时保留，日志异步格式化后仍能关联。

日志接入平台后可按路由汇总请求数量、5xx/429 比例和耗时分位数；本仓库没有把日志文件冒充已部署的指标采集平台。就绪失败先查存储和知识库；任务积压先恢复数据库/worker；通知耗尽先核查接收端确认和去重，再授权重排。高风险超期必须由值班人员打开工单处理，重排通知不能消除人工响应告警。

## 本机证据

`tests/test_phase7_observability.py` 实际启动 loopback uvicorn，巡检通过真实网络登录并读取状态，验证员工拒绝和退出会话；实际数据库验证模型窗口、积压、未知接收端、未响应及其恢复。`logs/phase0/phase7-operations-accepted.log`：相关 21 项通过。

真实新建演示实例的独立 CLI 巡检输出见 `logs/phase7/monitor-live-demo.json`：`notification_receiver_unconfigured`，退出码 1。这是开发配置的真实告警，未改写为无告警成功。正式接收、调度/监督和持续通知能力尚待部署验收。

该 CLI 记录早于存量工单修复。后续隔离复现 `logs/phase7/legacy-notification-gap/report.json` 曾确认存量 High 漏计；修复后通知/监控/TLS/隔离 22 项通过，见 `phase7-legacy-notification-gate.log`。新版开发种子库可能同时报告存量通知缺失和未响应超时；这反映实际存量状态，不应隐藏。
