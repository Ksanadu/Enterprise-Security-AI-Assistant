# 质量评测与结果解释

## 数据与执行

`backend/evaluation/frozen-v1.json` 包含 300 个单轮案例（60 个事实族，每族 5 种改写）和 30 组多轮案例。单轮族整体划分为开发集 185 题、验收集 115 题；多轮为 20/10 组。同一族的近似改写不会跨集。

案例为模拟数据，标签由实施者根据 PRODUCT_SPEC 和模拟 KB-009 编写。**尚未经过独立人工标注审阅，不能据此宣称生产准确率。** SHA-256 校验阻止静默改标签；需要修订标签时，应新建版本并记录理由。

从项目根目录执行：

```powershell
cd backend
.\.venv\Scripts\python.exe scripts/evaluate_quality.py --split development --output ../logs/phase6/development
.\.venv\Scripts\python.exe scripts/evaluate_quality.py --split validation --output ../logs/phase6/validation
```

程序使用独立临时数据库、模拟账号、Mock + TF-IDF，通过完整 API 提问，结束后恢复环境变量。不会使用现有业务数据库。阈值须在验收前冻结并绑定数据集摘要；验收集禁止 `--limit`。开发集抽样只标为诊断，不能通过验收。

报告包含意图和风险混淆矩阵、每类 precision/recall、语言分组、授权来源召回、高风险送达、正常操作误报、多轮当前/峰值风险、实际数据库工单数量和延迟。高风险风险等级、升级和送达采用硬门禁；RBAC 和阻断不得违反冻结预期。

## 本轮事实（2026-10-12）

- 开发集初始高风险送达召回约 51%，修复后在 `development-repaired-3` 达到 100%；风险准确率 100%，意图约 98.9%，授权来源召回约 98.9%，多轮 100%。仍有两处意图标签争议和一处检索缺口。
- 阈值已在首次验收前保存为 `thresholds-v1.json`，未依据验收结果下调。
- **首次独立验收失败。** `logs/phase6/validation-first/report.json`：意图约 75.7%，风险约 74.5%，高风险送达 80%，正常操作 High/Critical 误报约 13.3%，阻断约 96.5%，多轮 80%；越权来源次数为 0。
- 失败揭示了账号接管、中文勒索、否定/假设事件、授权培训和权限绕过表述的缺口。开发集的成功不等于独立验收通过。
- v1 验收失败已用于缺陷定位，后续修复重跑属于**回归复测**。新的独立质量结论需要未参与调优的数据和独立标注审阅。不得将重复使用 v1 的绿灯重新称为首次独立验收。
- `validation-regression-2` 的状态判断存在已确认的条件优先级错误，其 `regression_passed` 和 exit 0 **无效**；原报告保留并附有 `INVALID_STATUS.md`。指标仍未达到冻结阈值。错误已修复并加入状态门禁回归，后续以新执行记录为准。
- 纠正后的 `validation-regression-corrected` 明确返回失败（exit 1）：风险约 99.1%、高风险送达/多轮/阻断 100%、授权来源召回约 93.3%、越权来源 0。意图约 88.7%及正常操作 High/Critical 误报约 1.67%仍低于冻结门槛。首次独立失败仍然有效，不能由这次回归替代。
- 后续 `validation-regression-observed` 风险/送达/阻断/多轮 100%，正常操作高风险误报 0；意图 109/115（94.78%）仍未达 95%。六项差异均为新旧标签冲突，说明见 [QUALITY_LABEL_CONFLICTS.md](QUALITY_LABEL_CONFLICTS.md)，冻结结果未改写为通过。

## 尚需完成

1. 将失败转成事实级回归，修复后执行全量工程门禁及 v1 回归复测，保留首次失败记录。
2. 审阅 FAQ/Policy、MFA/Phishing 等意图边界；依据文档统一标签与实现，记录版本变化，不能只把标签改成当前输出。
3. 由未参与调优的审阅者冻结新验收数据，并审阅引用支持和关键安全操作建议。
4. 配置真实 LLM/Embedding 后分别执行真实模式评测；本入口的离线成绩不能替代真实模型成绩。
5. 隐私、并发、重复请求、上下文裁剪、历史授权和模型故障还需结合工程故障测试；单轮准确率不能覆盖这些性质。

## 真实模型入口

`backend/scripts/evaluate_models.py` 支持 `offline`、`llm_tfidf`、`llm_semantic`。真实模式必须配置 `.env` 并显式提供 `--max-network-calls`，输出调用预算、已报告 Token、延迟、降级比例和 `answer-review.csv`。只有供应商账单可证明实际费用；未提供定价和账单时不编造金额。

真实模式即使自动检查通过，也标为 `automated_checks_passed_manual_review_pending`，需完成人工引用和建议审阅后才能结项。
