# SQLite 备份与恢复

## 能力与边界

`scripts/ops-backup.py` 使用 SQLite 在线备份 API，以只读连接读取源数据库，包含已提交的 WAL 数据；不是直接复制正在运行的 `.db` 文件。备份和恢复均发布为新文件，拒绝覆盖已有目标。程序检查数据库完整性、外键、表数量、结构摘要和备份文件摘要。

工具只适用于当前 SQLite 单机部署。它不备份 `.env`、签名密钥、知识文件或供应商配置；这些配置需要另外的受控保存和恢复。摘要用于发现损坏或备份文件与清单不一致，不提供数字签名认证。备份包含完整业务数据，应放在仅运维人员可访问的目录；Windows 权限需由目录 ACL 管理。

## 执行

以下路径是占位示例，必须明确指定实际数据库和新的备份文件名，不存在自动寻找或重置业务数据库的行为。

```powershell
backend\.venv\Scripts\python.exe scripts/ops-backup.py backup --database "F:\ESAA-private\active.db" --output "F:\ESAA-private\backups\snapshot-20261012.db"
backend\.venv\Scripts\python.exe scripts/ops-backup.py restore --database "F:\ESAA-private\backups\snapshot-20261012.db" --output "F:\ESAA-private\restored-20261012.db"
```

备份同时生成 `<文件名>.manifest.json`。恢复时必须一同提供清单，工具从备份文件旁读取它；清单缺失、摘要不符、外键异常或目标已存在都会失败。成功状态分别为 `backup_verified` 和 `restore_verified`；失败返回 exit 1，仅显示错误类别，不输出业务 SQL 或记录值。

实际恢复部署需停止写入，完成校验后将 `DATABASE_URL` 指向新的恢复文件，并恢复对应签名秘密及配置。保留原数据库以便回退；不要把“复制校验通过”当作服务启动、迁移兼容和业务恢复均通过。

## 已执行演练

2026-10-12 在 `logs/phase7/backup-restore-drill-2` 使用当前 ESAA 表结构和模拟数据实际执行：

- 保持 WAL 写入连接开启，备份后恢复最新已提交消息。
- 核查全部表结构/行数、工单编号和待处理任务行。
- 拒绝向现有数据库恢复，确认源文件未改变。
- 修改备份文件而保持原清单，确认拒绝恢复且不创建目标数据库。
- 分别通过命令行执行备份和恢复，状态及退出码通过。

演练入口：

```powershell
backend\.venv\Scripts\python.exe scripts/ops-backup-drill.py --output logs/phase7/new-drill-directory
```

入口只创建新的专用目录，已有目录会拒绝，避免覆盖已有演练或业务文件。**演练最后会故意修改其备份文件用于校验失败测试，不能将该备份用于实际部署恢复。** 该演练未验证恢复后的完整应用启动；迁移、发布回滚、通知送达、共享限流、监控告警和保留策略仍未完成，Phase 7 尚未结项。

2026-10-13：备份核心迁入 `backend/app/db/backup.py`，根 CLI 保持入口，账号与保留工具可在后端发布包内直接调用。新 schema 04 的 WAL/任务/完整性/篡改拒绝演练重新通过，记录 `phase7-backup-retention-core.log`。完整应用恢复与两个制品实际回滚已有后续证据，见 [OPS_RELEASE.md](OPS_RELEASE.md)；上述段落记录最初文件级演练的范围。正式环境 ACL/加密、调度、跨主机及秘密托管仍未验收。
