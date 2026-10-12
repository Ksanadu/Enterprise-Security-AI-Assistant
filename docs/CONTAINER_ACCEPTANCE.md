# 容器验收执行说明

最新最终 PR 源提交 `a7d4eee6855e2c4ceef7440f9e9dd98644c98f85` 的同套验收也已通过：[运行 38298909044](https://github.com/Ksanadu/enterprise-security-ai-assistant/actions/runs/38298909044)，job `114976707995`，制品 `11769446894`。PR #1 已合并；下面首次成功及失败记录作为过程证据保留。

2026-10-13：GitHub Ubuntu runner 已实际通过 Mock + TF-IDF 容器核心验收，Docker Engine28.0.4。无 `.env` 与模拟 `.env` 两阶段均通过，记录：[成功运行](https://github.com/Ksanadu/enterprise-security-ai-assistant/actions/runs/38297173963)，对应源提交 `f7c4b1c49f6f9fb299e5f7ec62dad0441cde3219`。本机仍没有可用 Docker Engine，WSL 尚未初始化；容器浏览器和真实模型组合仍待执行。

首次运行因Compose重复 `stop_grace_period` 失败；修复后发现空/缺失知识库误报就绪，故障验收再次失败。两项现已修复，分别加入重复键与空目录/缺失目录回归；不得把旧失败记录覆盖为通过。故障日志与JSON报告在工作流制品保存，清理仅限本次随机项目/卷。

具备 Docker Engine 和 Compose 2.24+ 后，在项目根目录执行：

```powershell
backend\.venv\Scripts\python.exe scripts\container-acceptance.py
```

脚本复制经过过滤的当前源码到专用临时目录，不复制 `.env`、业务数据库、向量缓存、虚拟环境或 `node_modules`。分别运行无 `.env` 和模拟 `.env` 两种配置；项目名、镜像标签、端口和卷独立生成。结束时只清理本轮生成的 Compose 项目及卷。

实际检查包括 SPA/CSP/nginx 代理、中文政策查询、多轮验证码泄露升级、请求幂等、RBAC、人工确认、容器重启后的会话和工单保留。故障阶段使用不存在的知识目录，要求存活接口仍可读、就绪接口返回 503，且高风险报告仍有工单。

输出保存在 `logs/container-acceptance`。运行日志和结果都须审阅；脚本失败不能用静态 Compose 检查代替。`.github/workflows/container-acceptance.yml` 已在Ubuntu runner执行同一入口。已通过的18项配置/行为组合包含SPA/CSP/代理、中文政策、多轮升级、幂等、权限、人工响应、重启和知识库故障存活/就绪/建单；不是浏览器视觉或真实模型验收。

容器中的浏览器全流程、错误生产配置、真实模型故障和磁盘写入失败仍须补充执行证据。本机现有故障注入测试证明对应应用逻辑，但不能证明容器挂载、网络和文件权限行为。

参考：[Compose 健康启动顺序](https://docs.docker.com/compose/how-tos/startup-order/)。CI 使用的 action 主版本已核对官方发布页：[checkout](https://github.com/actions/checkout/releases/tag/v7.0.1)、[setup-python](https://github.com/actions/setup-python/releases/tag/v7.0.0)。
