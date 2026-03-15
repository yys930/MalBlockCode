# 系统设计文档：基于 LLM 的恶意流量阻断闭环系统（MalBlock）

## 1. 项目概述
**项目名称**：MalBlock — 基于 LLM 的恶意流量阻断研究系统  
**运行环境**：Ubuntu 22.04 虚拟机  
**数据集**：CIC-IDS-2017（PCAP + TrafficLabelling CSV）

**研究目标**：  
构建一个可运行、可评估、可解释的恶意流量阻断系统，支持三类输入通道：
- **通道 A：离线 PCAP 检测通道**
- **通道 B：PCAP 真实回放 / 在线检测通道**
- **通道 C：CSV 流级直读通道**

系统目标不是只输出“恶意/正常”分类结果，而是输出**结构化阻断策略**，并通过 `nftables` 真正执行 `drop / rate_limit / watch` 三类动作。

**闭环定义**：  
`流量输入 → 检测告警 / 流特征 → 结构化证据 → RAG+LLM 决策 → 阻断执行 → 评估分析 → 策略修正`

---

## 2. 设计原则与研究假设

### 2.1 设计原则
1. **可复现**：离线 PCAP、真实回放、CSV 理想输入三种实验链路可重复运行。
2. **可解释**：LLM 决策必须输出结构化证据、策略字段与执行结果。
3. **可评估**：区分“数据覆盖”“决策正确性”“执行效果”“闭环反馈”。
4. **可控安全**：阻断动作受白名单、TTL、执行模式约束，不允许 LLM 任意下发高风险动作。
5. **可扩展**：支持后续替换模型、RAG 检索方式、执行策略与可视化界面。

### 2.2 研究假设
1. LLM 可基于结构化告警/流特征生成合理的阻断策略，而不是只做标签分类。
2. 引入 RAG 历史策略案例，有助于提高处置一致性与解释性。
3. 通道 A/B 更适合评估**干预后告警压制效果**。
4. 通道 C 更适合评估**在理想结构化输入条件下，LLM 对恶意流的策略选择能力上限**。

---

## 3. 系统总体架构

### 3.1 架构分层
1. **输入层**：PCAP 离线/在线回放、CSV 流记录
2. **检测层**：Suricata 生成 `eve.json`
3. **处理层**：告警抽取、噪声过滤、时间窗聚合、CSV 适配
4. **决策层**：RAG + LLM Agent
5. **执行层**：MCP + nftables
6. **评估层**：结构化评估报告生成
7. **展示层**：后续可接 Web Dashboard

### 3.2 数据流
1. **通道 A：离线 PCAP**
   - `suricata -r` 读取 PCAP
   - 生成 `eve.json`
   - 抽取告警、聚合时间窗、进入 Agent

2. **通道 B：真实回放 / 在线检测**
   - `tcpreplay` 回放 PCAP 到指定接口
   - Suricata 在线监听宿主机接口
   - 抽取告警、聚合时间窗、进入 Agent

3. **通道 C：CSV 流级模式**
   - 直接读取 `TrafficLabelling` CSV
   - 将每条流记录映射为统一 `window`
   - 不依赖 Suricata 告警

4. **统一后续处理**
   - 构造 `llm_inputs_selected.jsonl`
   - 构造 LLM message
   - 注入 RAG 与批次内上下文
   - 生成结构化决策并执行
   - 写出评估报告

---

## 4. 输入与数据集设计

### 4.1 CIC-IDS-2017 数据源选择
本项目主数据源优先使用：
- `TrafficLabelling`

原因：
- 包含 `Source IP / Destination IP / Port / Timestamp / Label`
- 能直接映射到阻断目标
- 更适合 CSV 通道与阻断系统设计

`MachineLearningCVE` 更适合作为传统 ML 分类基线，不作为本系统主输入。

### 4.2 恶意流量总集构建
已实现恶意总集构建脚本：
- `backend/dataset/cic_ids2017_builder.py`
- `backend/scripts/build_cic_dataset.py`

当前输出：
- `backend/datasets/cic_ids2017_trafficlabelling/malicious_merged_cleaned.csv`
- `backend/datasets/cic_ids2017_trafficlabelling/manifest.json`

当前构建规则：
- 遍历 `TrafficLabelling` 下全部 CSV
- 仅保留恶意流量
- 清洗关键字段
- 去重
- 保留来源信息：
  - `source_file`
  - `source_day`
  - `original_row_id`

该数据集是当前 CSV 通道的主输入。

### 4.3 CSV 通道多样化采样
为避免固定优先级采样总是落在 `DDoS` 热点上，CSV 通道现支持三种样本选择模式：

- `priority`
  - 按恶意优先、严重度、包速排序
- `random`
  - 全局随机抽样
- `stratified_label`
  - 按恶意标签分层随机抽样，优先覆盖所有恶意类型

当前推荐实验参数：
```bash
--topk 100 --exclude-benign --selection-mode stratified_label --seed 42
```

---

## 5. 模块设计

### 5.1 输入与统一作业管理
**功能**：统一管理三类输入通道和输出目录。

主要入口：
- `backend/scripts/run_offline_channel.py`
- `backend/scripts/run_replay_channel.py`
- `backend/scripts/run_csv_channel.py`
- `backend/scripts/run_channel.py`

统一输出目录：
- `backend/jobs/<job_id>/`

统一摘要文件：
- `backend/jobs/<job_id>/channel_summary.json`

### 5.2 告警抽取与过滤模块
**适用**：通道 A/B  
**功能**：
- 从 `eve.json` 抽取 `alert`
- 过滤已知噪声 signature
- 清理缺失关键字段的告警

主要文件：
- `backend/pipeline/suricata_alerts.py`

输出：
- `alerts_filtered.jsonl`

### 5.3 时间窗聚合模块
**适用**：通道 A/B  
**功能**：按 `src_ip + window_sec` 聚合告警窗口。

主要特征：
- `hits`
- `severity_min`
- `alert_density_per_sec`
- `burst_duration_sec`
- `unique_dest_ip_count`
- `unique_dest_port_count`
- `signature_diversity`
- `dominant_proto`
- `top_signatures`
- `top_categories`
- `dest_ports`
- `top_dest_ips`

主要文件：
- `backend/pipeline/window_aggregate.py`

输出：
- `llm_inputs_selected.jsonl`

### 5.4 CSV 流级适配模块
**适用**：通道 C  
**功能**：将 `TrafficLabelling` 恶意流量总集直接映射为统一 `window`。

主要文件：
- `backend/pipeline/csv_flow_adapter.py`

当前适配能力：
- 支持 ISO 时间解析
- 支持 `malicious_merged_cleaned.csv`
- 为每条流构造：
  - `flow_uid`
  - `source_file`
  - `source_day`
  - `source_row_id`
- 从 `label` 派生：
  - `attack_family`
  - `severity`
  - `CSV_FLOW::<label>` 伪 signature

作用：
- 用于理想化结构化输入实验
- 用于快速验证 Agent 决策策略

### 5.5 RAG + LLM 决策模块
**功能**：对结构化证据进行策略决策，并在需要时触发执行工具。

主要文件：
- `backend/agent/message_builder.py`
- `backend/agent/build_messages.py`
- `backend/agent/prompt.py`
- `backend/agent/policy.py`
- `backend/agent/llm_agent_sf.py`
- `backend/agent/run_agent_batch.py`

#### 5.5.1 RAG 历史策略案例
主要文件：
- `backend/agent/rag_store.py`
- `backend/rag/decision_history.jsonl`
- `backend/rag/chroma_db`

当前检索对象不是原始告警文本，而是历史**策略案例**：
- `incident_profile`
- `historical_strategy`
- `execution_result`
- `feedback`

#### 5.5.2 Agent 输入
每条 message 当前包含：
- `constraints`
- `hints`
- `window`
- `evidence_window`
- `retrieved_evidence`
- `decision_context`
- `meta`

#### 5.5.3 Agent 动态决策增强
当前 Agent 不再只依赖模型自由输出，而是加入了：

1. **决策上下文增强**
   - `prior_block_count`
   - `prior_rate_limit_count`
   - `prior_watch_count`
   - `same_attack_family_seen_count`
   - `same_label_seen_count`
   - `current_enforcement_mode`
   - `current_enforcement_ttl_sec`
   - `max_block_ttl_sec_seen`

2. **Prompt 层递进处罚要求**
   - 同一 `src_ip` 重复恶意时要求体现递进处罚
   - 不鼓励机械重复给低强度处罚
   - 已有同等级或更强处置时，要求考虑“已有策略覆盖”

3. **运行时 TTL 纠偏**
   - 模型给出的 `ttl_sec` 不再直接被信任
   - `block/rate_limit/watch` 的工具参数会至少达到策略推荐 TTL
   - 同一 IP 重复恶意时会按上下文进行平滑升级

4. **执行短路**
   - 如果同一 job 内某个 `src_ip` 已经处于同等级或更强处置状态
   - 当前 Agent 不再重复下发同类工具
   - 会返回：
     - `covered_by_existing_action`
     - `skipped_execution`

5. **附加解释字段**
   - `decision_state`
     - `new_block`
     - `escalated_block`
     - `covered_by_existing_block`
   - `ttl_reason`
     - 说明 TTL 来源与升级依据

### 5.6 执行模块
**实现方式**：MCP + nftables

主要文件：
- `backend/agent/mcp_enforcer_server.py`
- `backend/agent/mcp_enforcer_client.py`

可调用工具：
- `block_ip`
- `rate_limit_ip`
- `watch_ip`
- `unblock_ip`
- `list_blocked`

#### 5.6.1 nftables 对象
初始化脚本：
- `backend/scripts/init_nftables.sh`
- `backend/scripts/reset_nftables.sh`

当前实际使用的 set：
- `blocklist_v4`
- `ratelimit_v4`
- `watchlist_v4`

当前 live 规则含义：
- `blocklist_v4` -> 直接 `drop`
- `ratelimit_v4` -> 限速通过，超限 `drop`
- `watchlist_v4` -> 限速记录日志，不阻断

#### 5.6.2 执行保障
- 支持 `DRY_RUN`
- 支持审计日志
- 支持白名单保护
- 支持对重复下发返回 `already_present`

---

## 6. LLM Agent 设计

### 6.1 决策输入
- `constraints`：系统硬约束
- `hints`：从窗口派生的高层特征
- `window`：压缩后的主证据
- `evidence_window`：完整证据
- `retrieved_evidence`：RAG 历史案例
- `decision_context`：当前批次内同一源 IP 的历史状态
- `meta`：作业与工具调用审计信息

### 6.2 决策输出
输出必须为 JSON-only，核心字段：

```json
{
  "action": "block|monitor|allow|review",
  "target": {"type":"ip","value":"<src_ip>"},
  "ttl_sec": 3600,
  "confidence": 0.95,
  "risk_score": 90,
  "labels": ["dos", "executed"],
  "reasons": ["..."],
  "strategy": {
    "block_scope": "src_ip",
    "duration_tier": "short|medium|long",
    "priority": "low|medium|high|critical",
    "follow_up": "none|collect_more_windows|track_recurrence|manual_review|raise_alert",
    "execution_mode": "none|drop|rate_limit|watch",
    "template_id": "dos_containment",
    "escalation_level": 0
  },
  "evidence": {...},
  "tool_result": {...},
  "decision_state": "new_block|escalated_block|covered_by_existing_block",
  "ttl_reason": "policy_recommended|repeat_offender_escalation|covered_by_existing_action"
}
```

### 6.3 约束策略
- action 必须来自允许集合
- `noise_only` 时禁止自动 block
- TTL 受最小/最大边界约束
- 禁止封禁白名单 IP
- 不确定时默认 `review`
- 输出的 `target.value` 必须与 `src_ip` 一致

### 6.4 策略模板与递进升级
当前模板按 `attack_family` 预置：
- `dos_containment`
- `credential_abuse_control`
- `recon_escalation`
- `dns_abuse_watch`
- `botnet_containment`
- `web_attack_block`
- `generic_triage`

动态升级依赖：
- 当前样本危险程度
- 同一 IP 在当前批次中的历史 block/monitor/watch/rate-limit 次数
- 同一 IP 是否重复出现相同攻击族或标签
- 历史案例检索结果

### 6.5 运行时保护
- 进入 LLM 前先执行 `precheck_action`
- 工具参数由运行时补全
- 输出不合法则回退 `fallback`
- 若工具已执行但结果与策略不一致，系统自动纠偏

---

## 7. 评估模块设计

### 7.1 评估目标
评估模块不是只算 `F1`，而是同时回答：
1. 本次样本覆盖情况如何
2. Agent 决策是否正确
3. 工具执行是否成功
4. 是否存在重复处置
5. 对不同攻击类型的表现是否一致

### 7.2 评估实现
主要文件：
- `backend/eval/channel_eval.py`

统一输出：
- `backend/jobs/<job_id>/evaluation_report.json`

### 7.3 当前评估报告结构
当前 `evaluation_report.json` 包含：

- `job_meta`
- `dataset_summary`
- `decision_eval`
- `execution_eval`
- `error_analysis`
- `samples`
- `effect_eval`

### 7.4 CSV 通道当前评估能力
**数据摘要**
- `input_rows`
- `selected_rows`
- `label_distribution`
- `attack_family_distribution`
- `source_day_distribution`
- `unique_src_ip_count`
- `unique_flow_uid_count`

**决策评估**
- `tp / fp / tn / fn`
- `precision / recall / f1`
- `matched_decisions / unmatched_decisions`
- `per_label_metrics`
- `per_attack_family_metrics`
- `per_source_day_metrics`

**执行评估**
- `tool_success_count`
- `tool_failure_count`
- `already_present_count`
- `repeat_enforcement_ratio`
- `unique_blocked_ip_count`
- `unique_rate_limited_ip_count`
- `unique_watched_ip_count`

**错误分析**
- `false_positive_cases`
- `false_negative_cases`
- `review_cases`
- `unmatched_cases`

### 7.5 A/B 通道评估重点
离线/回放通道当前主要做：
- `action_distribution`
- `execution_mode_distribution`
- 工具执行统计
- `suppression_ratio`

### 7.6 当前已知评估结论
在 `csv_malicious_stratified_001` 和 `csv_malicious_stratified_002` 中已经验证：
- `stratified_label` 确实能覆盖 14 类恶意标签
- 评估已能正确反映样本分布与执行冗余
- `csv_malicious_stratified_002` 中动态 TTL 升级已显现

---

## 8. 实验运行与复现

### 8.1 恶意总集构建
```bash
python3 backend/scripts/build_cic_dataset.py \
  --input-dir /home/os/FinalCode/data/CIC-IDS-2017/CSVs/TrafficLabelling \
  --output-dir /home/os/FinalCode/malblock/backend/datasets/cic_ids2017_trafficlabelling \
  --dedupe-mode flow \
  --progress-every 200000
```

### 8.2 CSV 通道推荐运行方式
```bash
python3 backend/scripts/run_csv_channel.py \
  --csv /home/os/FinalCode/malblock/backend/datasets/cic_ids2017_trafficlabelling/malicious_merged_cleaned.csv \
  --job-id csv_malicious_stratified_002 \
  --topk 100 \
  --exclude-benign \
  --selection-mode stratified_label \
  --seed 42 \
  --rag-top-k 3
```

### 8.3 评估命令
```bash
PYTHONPATH=backend python3 - <<'PY'
from eval.channel_eval import evaluate_job
evaluate_job('/home/os/FinalCode/malblock/backend/jobs/csv_malicious_stratified_002')
PY
```

---

## 9. 当前进展与待优化点

### 9.1 已落地
- 恶意总集构建完成
- CSV 通道适配完成
- 多样化采样完成
- 评估模块结构化增强完成
- Agent 动态上下文与 TTL 升级已落地
- nftables 三类执行模式已在 live 系统中验证生效

### 9.2 当前待优化
1. **重复执行统计需进一步纳入评估**
   - 当前 Agent 已支持 `covered_by_existing_action`
   - 后续应在评估中显式统计短路执行次数

2. **TTL 升级曲线仍需继续调优**
   - `csv_malicious_stratified_002` 已出现从 `300` 提升到 `10800/21600/86400`
   - 但仍需进一步验证升级是否过于激进

3. **RAG 反馈闭环还未完全闭合**
   - 当前评估结果尚未自动反写回 `decision_history.jsonl` 的 `feedback`

4. **前端展示层尚未落地**
   - 目前仍以脚本与 JSON 报告为主

---

## 10. 后续扩展方向
1. 将 `covered_by_existing_action / skipped_execution` 纳入评估与论文图表
2. 打通 `evaluation_report -> RAG feedback` 闭环
3. 增加基于 `MachineLearningCVE` 的传统 ML 基线对比
4. 开发最小可用的 Web Dashboard
5. 增强 replay 通道的真实阻断效果评估
