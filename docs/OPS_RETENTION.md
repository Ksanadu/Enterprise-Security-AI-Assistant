# 业务数据保留与保全（单机 SQLite）

2026-10-13：已实现显式批准政策、预览、删除前校验备份、事务内重新检查、保全锁及后台执行。仅在模拟隔离数据库验证，没有对现有业务库执行清理，也没有代替数据负责人的期限审批。

## 政策与运行

复制 `backend/retention-policy.example.json` 到权限受限的独立政策文件。示例的 `state=example_not_approved` 会被拒绝。数据负责人填写政策编号、批准责任和期限后才可设为 `approved`；该字段是配置声明，不能代替组织审批流程或文件 ACL。

聊天、已关闭工单、已完成任务、审计、已结束通知和本工具备份分别配置天数；`null` 表示无限保留。没有默认业务删除期限。`batch_limit` 默认 200、最多 1000，按父记录计数；一个会话可能包含许多消息，大库必须另外验收负载和维护窗口。

在后端目录设置 `RETENTION_POLICY_FILE` 和 `RETENTION_BACKUP_DIR`。备份目录必须是专用空目录或已有本工具归属标记的目录，不能复用其他工具的备份目录。先备份并显式迁移到 `20261013_04`，再运行：

```powershell
.\.venv\Scripts\python.exe scripts/retention.py plan
.\.venv\Scripts\python.exe scripts/retention.py apply
```

预览不修改数据库或创建备份目录。实际运行由定时维护入口调用，共享持久化预算限制多个 worker 至少间隔 120 秒。配置为空则不启用业务清理。日志/CLI 只输出分类计数和校验结果，不输出聊天、审计详情或政策批准人。

## 删除与保全边界

- 未关闭工单、未完成任务、未完成通知、活动聊天请求及被保全记录排除；近期消息、任务或事件也会延后删除。没有关联已关闭工单的 Medium/High 会话保守保留。
- 聊天/消息、工单和审计清除业务字段并保留已擦除身份标记；普通 ORM 查询、API 和统计过滤这些记录。保留主键防止旧链接或旧请求键指向新记录。已完成任务和通知 UUID 记录可物理删行；工单序列不重置。
- 每次实际擦除先生成一致 WAL 快照并验证完整性、外键及摘要。事务取得写锁后重新检查，仅处理备份前已选中的候选。备份失败、并发新增保全或事务失败不会部分擦除。
- 对话删除同样保留不可复用身份；有保全锁时用户删除被拒绝。用户主动删除不产生自动恢复快照，沿用原删除入口的授权语义。
- 保全适用于 conversation、ticket、audit。工单锁关联保护会话、任务、通知及对应审计；任意活动保全锁会暂停所有本工具备份过期，避免历史副本丢失。

在后端运行保全工具，要求显式独立备份目录；`--case` 使用案件编号，勿放正文或凭据：

```powershell
.\.venv\Scripts\python.exe scripts/retention.py hold --resource conversation --id 123 --case CASE-2026-001 --backup-dir F:/Private/ESAA/hold-backups
.\.venv\Scripts\python.exe scripts/retention.py release --resource conversation --id 123 --case CASE-2026-001 --backup-dir F:/Private/ESAA/hold-backups
```

新增/释放保全先校验新快照，再提交记录与治理审计。已擦除记录不能靠新增保全复原；应走授权恢复流程。保全历史及 `retention.*` 治理审计保留，schema downgrade 遇到擦除或保全历史会拒绝。

## 备份过期与限制

只处理本工具专用目录、符合 UUID 命名且清单归属匹配的备份，每轮最多删除 100 份。未过期、摘要改变、链接文件或非本工具文件不会被误删；删除前在写锁内再次检查保全和文件状态。备份 TTL 为空则不删除。异常保留并在下轮重试，需由运维人员处置损坏文件。

擦除业务字段与普通 API 不可见不等于磁盘不可恢复。SQLite 空闲页、WAL、文件系统快照和先前备份可能仍含旧字节；本轮未声明安全介质擦除。数据盘/备份加密、权限、密钥生命周期、外部副本过期、账户身份保留、通知接收端账本保留及治理审计期限仍须明确执行政策。恢复旧备份可能重新引入已擦除数据，必须核对保全/擦除记录，按政策再次清理后才恢复访问。

## 验收证据

`logs/phase0/phase7-data-retention-accepted.log`：111 项相关回归通过。`phase7-retention-release-tests.log`：48 项保留、账号、发布包及迁移验收通过，包括超过 100 个较新 UUID 名称后旧备份仍能过期、篡改备份拒删、保全阻止备份过期、恢复原内容、统计排除和回退保护。最终全量门禁结果另见进度记录。

实际 CLI 验收通过：`logs/phase7/retention-cli-drill/report.json` 验证预览、保全/释放前备份、保全排除、擦除前备份及重复预览；新 schema 前后端独立 Demo 71/71 通过，日志 `phase7-retention-demo.log`。

完整门禁 `phase7-retention-full-gate.log` exit 0：1792 后端通过、7条件性跳过，覆盖率94.86%；81前端通过，全部静态/类型/秘密检查通过。
