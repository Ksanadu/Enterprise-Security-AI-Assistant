# 本地发布包校验与实际回滚演练

2026-10-13 已完成两个不同发布包的进程切换/故障/恢复演练。适用范围是单机模拟 SQLite、离线模型、实际 loopback HTTP API及本机 TLS 通知接收端；没有验证正式 Docker 镜像、公共前端 TLS、真实供应商或正式接收人。

## 构建与校验

先完成工程门禁并构建 `frontend/dist`，用仓库后端解释器在根目录运行：

```powershell
.\backend\.venv\Scripts\python.exe scripts/ops-release.py package --artifact F:/Private/ESAA/releases/release.zip
.\backend\.venv\Scripts\python.exe scripts/ops-release.py verify --artifact F:/Private/ESAA/releases/release.zip
.\backend\.venv\Scripts\python.exe scripts/ops-release.py extract --artifact F:/Private/ESAA/releases/release.zip --destination F:/Private/ESAA/releases/activated
```

生成/解压要求全新路径，不覆盖已有文件或目录。包内每个文件及源清单有 SHA-256，激活前重新检查完整性；拒绝路径穿越、大小写重复、Windows 保留名称、链接和过大文件。工具约束不等于 WORM 存储或签名认证，正式发布仍须权限受限、可信摘要来源和制品保管。

包包含后端运行代码/知识库/迁移/脚本、依赖清单及预构建前端文件，不包含 `.env`、数据库或缓存。它依赖已安装的 Python 运行环境；前端源码/npm 依赖没有全部打包，附带 Dockerfile 不能被理解为自包含 Docker 构建制品。正式容器发布应使用经验证的镜像 digest和对应部署配置。

## 实际演练

执行者必须提供两个不同且已校验的制品，使用新的输出目录：

```powershell
.\backend\.venv\Scripts\python.exe scripts/ops-release-drill.py --previous F:/Private/ESAA/releases/a.zip --candidate F:/Private/ESAA/releases/b.zip --output F:/Private/ESAA/drills/rollback-001
```

该命令只在自己新建目录创建模拟账号和数据、启动自己拥有的临时进程、运行本机 TLS 接收端；不修改当前 `.env` 或现有业务库。随机模拟密码与签名秘密仅在运行内存/子进程环境中传递，报告不包含登录令牌。

演练先用 A 建立已送达事件和建单失败的待处理任务，并通过实际 HTTP 验证鉴权/权限。停止写入进程后冻结备份，模拟接收确认后发送端未持久化确认的重放窗口。B 执行 schema 03→04 迁移，故意配置无效知识库，验证 ready 503、health 存活。停止 B，将升级前快照恢复到新文件，启动 A；旧会话与 RBAC保留，恢复 worker 为待处理事件生成唯一工单、修复历史状态并实际发送 TLS通知。同一事件重放只在接收端账本留下一个记录。

候选进程的运行确认可能写入后续数据库，恢复会丢弃这些操作状态；外部接收账本独立保留并去重。模拟演练未授权冻结后新增业务写入。正式发布必须落实维护窗口、写入冻结、任务登记和实际损失范围；若旧版兼容新库，可优先只回退应用，但必须先证明兼容性。

## 证据与未完成范围

成功记录：`logs/phase0/phase7-release-rollback-3.log`、`logs/phase7/release-rollback-drill-3/report.json`。12 项实际检查通过，报告绑定 A/B制品摘要和迁移版本。前两次脚本输出解析/接收账本列名错误的失败记录原样保留，不能当作成功。

正式镜像切换、进程监督、入口 TLS、正式通知渠道、秘密托管恢复、跨主机恢复和实际 RPO/RTO仍待部署验收。恢复旧快照还须核对之后的保全/擦除历史，防止恢复已删除材料；备份与接收端账本均包含受限业务资料。
