# 容器验收执行说明

当前实际容器验收未完成：本机未安装可用的 Docker Engine，WSL 尚未初始化。本文和脚本是验收准备，不是通过记录。

具备 Docker Engine 和 Compose 2.24+ 后，在项目根目录执行：

```powershell
backend\.venv\Scripts\python.exe scripts\container-acceptance.py
```

脚本复制经过过滤的当前源码到专用临时目录，不复制 `.env`、业务数据库、向量缓存、虚拟环境或 `node_modules`。分别运行无 `.env` 和模拟 `.env` 两种配置；项目名、镜像标签、端口和卷独立生成。结束时只清理本轮生成的 Compose 项目及卷。

实际检查包括 SPA/CSP/nginx 代理、中文政策查询、多轮验证码泄露升级、请求幂等、RBAC、人工确认、容器重启后的会话和工单保留。故障阶段使用不存在的知识目录，要求存活接口仍可读、就绪接口返回 503，且高风险报告仍有工单。

输出保存在 `logs/container-acceptance`。运行日志和结果都须审阅；脚本失败不能用静态 Compose 检查代替。`.github/workflows/container-acceptance.yml` 在具备 Docker 的 Ubuntu runner 执行同一入口，目前尚未远程运行。

容器中的浏览器全流程、错误生产配置、真实模型故障和磁盘写入失败仍须补充执行证据。本机现有故障注入测试证明对应应用逻辑，但不能证明容器挂载、网络和文件权限行为。

参考：[Compose 健康启动顺序](https://docs.docker.com/compose/how-tos/startup-order/)。CI 使用的 action 主版本已核对官方发布页：[checkout](https://github.com/actions/checkout/releases/tag/v7.0.1)、[setup-python](https://github.com/actions/setup-python/releases/tag/v7.0.0)。
