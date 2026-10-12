# 通知、人工响应与生产账号转换

适用范围：SQLite 单机试点；开发演示可以不配置接收端。实际正式收件渠道尚未验收。

## 事件与送达

High/Critical 工单创建或升级时，在同一个事务中保存 `notification_outbox`。业务请求不等待 HTTP；发送失败不丢失工单。数据库版本 `20261012_03` 增加队列表，生产必须先备份并执行 `alembic upgrade head`。有队列记录时该版本拒绝删除表回退。

默认每 30 秒扫描，单批最多发送 50 个事件。多个 worker 使用持久化租约和唯一事件键；单次发送总期限默认 5 秒，最多配置 15 秒，不跟随重定向、不使用系统代理。停止时完成正在发送的一条并保留剩余事件。失败默认最多尝试 10 次，按指数退避，间隔上限 300 秒；耗尽后由 Security 队列重排，保留累计尝试数。

状态 `delivered` 表示接收端已按协议确认入队，不能据此认定邮件/聊天最终抵达、值班人员看见或人工接手。人工响应依据工单时间线中 IT/Security 的非自动状态变更或备注。High 默认 1800 秒、Critical 默认 900 秒没有响应时，向值班负责人接收端产生提醒；之后每 900 秒再次检查。旧级别通知、已解决/关闭事件和已人工响应的待发送提醒会取消。

## 接收端协议

配置项见 `.env.example`：

| 配置 | 用途 |
| --- | --- |
| `NOTIFICATION_WEBHOOK_URL` | 事件接收端 |
| `NOTIFICATION_LEAD_WEBHOOK_URL` | 未接手事件的负责人接收端 |
| `NOTIFICATION_SIGNING_SECRET` | 双方约定的 HMAC 秘密，至少 32 字符 |
| `NOTIFICATION_CA_BUNDLE_FILE` | 可选 PEM CA 文件；为空使用系统受信 CA |
| `NOTIFICATION_POLL_INTERVAL_SECONDS` | 扫描间隔，生产必须大于 0 |
| `NOTIFICATION_TIMEOUT_SECONDS` / `NOTIFICATION_MAX_ATTEMPTS` | 总发送期限与自动重试次数 |
| `NOTIFICATION_HIGH_ACK_SECONDS` / `NOTIFICATION_CRITICAL_ACK_SECONDS` | 人工响应期限 |
| `NOTIFICATION_REMINDER_INTERVAL_SECONDS` | 重复未响应提醒间隔 |

生产要求两个 HTTPS 接收端、有效签名秘密和运行中的发送任务；缺少配置时启动失败。URL 禁止用户信息、查询参数和片段，秘密不能放入 URL。HTTP 仅在非生产的 loopback 开发接收端可用；自签名测试 CA 通过专用文件配置，没有关闭证书验证或修改系统信任。

POST JSON 只有六个字段：`event_id`、`kind`、`ticket_reference`、`severity`、`resource_path`、`created_at`。其中 `resource_path` 为 `/?ticket=<工单编号>`，接收端按部署时约定的前端 HTTPS origin 构造链接，登录后仍由后端检查访问权限。消息、原始报告、工单标题、正文、邮箱及凭据不发送。

请求头 `Idempotency-Key` 等于事件 ID；`X-ESAA-Timestamp` 为 Unix 秒；`X-ESAA-Signature` 为 `HMAC-SHA256(secret, timestamp + "." + 原始请求体字节)` 的十六进制值。接收端须在认证签名及时间窗口后**持久化按事件 ID 去重**，成功返回 HTTP 200/202 并提供 `X-ESAA-Accepted-Event: <同一事件 ID>`；只返回 2xx 不算确认。接收端应限制请求大小，并对下游聊天/邮件投递自行重试和监控。

这是至少一次传输：接收端已确认、发送者尚未提交数据库时发生崩溃，会重发同一 ID。最终尝试租约过期时记录 `delivery_uncertain_after_last_attempt`，不会伪造成功；人工核查接收端去重账本后再决定是否重排。

升级前已有的 High/Critical 非终结工单由 worker 每批最多补齐 500 条，使用相同唯一事件键，重启/多 worker 不重复创建。通知时间取当前风险级别的最新升级事件时间，缺少旧时间线时取工单创建时间；人工已在该时点后响应的存量事件标为取消，终结事件跳过。旧级别的人工响应不能免除后续 Critical 升级。超时统计独立查询工单/时间线，即使 worker 未完成补齐也会报警。

## 查看与重排

Security 用户在 Tickets 的“通知送达”面板查看分页、刷新、打开工单和重新安排发送。后端接口为 `GET /api/v1/operations/notifications` 和 `POST /api/v1/operations/notifications/{id}/retry`；其他角色及匿名用户无权操作。重排请求有审计，返回等待状态，不能作为送达证据。未配置的开发环境保留事件，界面如实显示。

## 原型账号转换

生产启动拒绝仍然活跃的四个已知演示账号。转换前先配置正式账号、备份及维护窗口；脚本不会重命名账号、修改其权限或删除业务历史。后端目录执行：

```powershell
.\.venv\Scripts\python.exe scripts/retire_prototype_users.py
.\.venv\Scripts\python.exe scripts/retire_prototype_users.py --apply --backup ../logs/operator-backups/fresh-retirement.db
```

第一条仅预览数量。第二条使用新的、未存在的备份目标，校验备份后停用演示账号并撤销其会话，保留工单和聊天历史。四个已知邮箱检查不能代替对全部账号、权限和凭据来源的正式审阅。生产还禁止关闭共享安全预算、定时维护及升级任务恢复。

## 实际证据与待办

2026-10-12：实际 loopback HTTP 验证签名、明确确认头、失败重试、并发租约、崩溃后同 ID 重发、超时、重试耗尽和停止保留；实际 TLS 验证未知 CA 拒绝及配置 CA 后成功，生产配置 worker 发送 Critical 事件和未响应提醒。生产备份恢复后，真实后台 worker 向本机 TLS 接收端确认送达，见 `logs/phase7/pilot-notification-recovery/report.json`。这些接收端和账号全部是模拟数据。

前端 81 项测试和覆盖率门禁通过；独立模拟实例 `run-86bfd5990a49` 的浏览器验证 High → 通知等待 → 重排 → 打开原工单，以及通知链接登录后定位工单。390 像素窄屏内容宽度/视口宽度均为 375（含滚动条）；截图 `logs/phase7/notification-ui-{desktop,mobile}.png`。

正式值班收件人、接收端到聊天/邮件的最终链路、负责人升级制度，以及生产前端 TLS、容器和发布回滚仍需对应实际环境验收。

后续已封闭演示/评测继承正式通知配置的缺口：演示、pytest、模型和质量评测显式清空通知配置；运维演练只配置自己的模拟接收端。实际向 `run-demo.ps1` 传入模拟 TLS 收件配置，71/71 检查通过、接收端请求数为 0，证据 `logs/phase7/demo-notification-isolation/report.json`。这不是通知送达验收，而是模拟事件隔离验收。
