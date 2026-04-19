# 系统设计文档：基于 LLM 的恶意流量阻断闭环系统（MalBlock）

## 1. 项目概述
**项目名称**：MalBlock — 基于 LLM 的恶意流量阻断研究系统  
**运行环境**：Ubuntu 22.04 虚拟机  
**主要数据集**：CIC-IDS-2017（PCAP + TrafficLabelling CSV）

**研究目标**：  
构建一个可运行、可评估、可解释、可执行的恶意流量阻断系统。系统不仅输出“恶意/正常”判断，而是输出结构化阻断策略，并通过 `nftables` 执行 `drop / rate_limit / watch` 三类动作。

系统当前支持三类实验通道：
- **通道 A：离线 PCAP 检测通道**
- **通道 B：在线回放 / 流式处理通道**
- **通道 C：CSV 结构化流级通道**

当前系统已实现从流量输入到策略执行、评估分析、前端展示的完整实验链路，形成如下闭环：

`流量输入 -> 检测告警 / 流特征 -> 结构化证据 -> RAG + LLM 决策 -> nftables 执行 -> 结构化评估 -> 前端展示`

---

## 2. 设计原则与研究假设

### 2.1 设计原则
1. **可复现**：离线、在线回放、CSV 三类通道均能重复运行。
2. **可解释**：LLM 决策必须输出结构化证据、策略字段与执行结果。
3. **可评估**：评估不仅包含分类指标，也包含执行效果、重复处置、短路处置和压制效果。
4. **可控安全**：LLM 不能直接任意下发高风险动作，执行受白名单、TTL、策略模板与运行时修正规则约束。
5. **可扩展**：支持后续替换模型、RAG 检索方式、策略模板和展示前端。

### 2.2 研究假设
1. LLM 可以基于结构化证据生成可执行阻断策略，而非仅输出标签分类。
2. 引入 RAG 历史策略案例可提升处置一致性和解释性。
3. 离线/在线回放更适合评估检测与干预后的执行效果。
4. CSV 通道更适合评估在理想结构化输入条件下的策略决策上限。

---

## 3. 系统总体架构

### 3.1 架构分层
1. **输入层**：PCAP 离线、在线回放、CSV 流记录
2. **检测层**：Suricata 生成 `eve.json`
3. **处理层**：告警抽取、噪声过滤、时间窗聚合、CSV 适配
4. **决策层**：RAG + LLM Agent
5. **执行层**：MCP + nftables
6. **评估层**：结构化评估报告
7. **展示层**：Web Dashboard

### 3.2 当前三类通道的数据流

#### 通道 A：离线 PCAP
1. `suricata -r` 读取 PCAP
2. 输出 `eve.json`
3. 抽取 `alert`
4. 过滤噪声 signature
5. 按 `src_ip + window_sec` 聚合
6. 取 top-k 窗口进入 LLM
7. 输出结构化决策并执行 nft
8. 生成评估报告

#### 通道 B：在线回放 / 流式处理
1. Suricata 在线监听指定接口
2. `tcpreplay` 持续回放 PCAP 到指定接口或 netns 中的虚拟接口
3. Suricata 持续产生新的 `eve.json` 告警
4. 系统维护 `eve.json` 读取偏移量，仅增量读取**新产生的 alert**
5. 每隔一个 `window_sec` 周期触发一次处理：
   - 收集该周期内新产生的告警
   - 对新增告警做聚合
   - 依据 `hits / severity / 目标集中度 / burst` 排序
   - 选取该周期 top-k 窗口送入 LLM
6. LLM 决策后立即执行 nft
7. 下一周期继续处理后续新增告警

这意味着当前在线通道已经不再是“回放结束后统一批处理”，而是**滚动窗口式流式处理**。

#### 通道 C：CSV 结构化流级模式
1. 直接读取 `TrafficLabelling` CSV
2. 将每条流记录映射为统一 `window`
3. 采样后直接构造消息
4. 进入 LLM 决策和执行层
5. 输出评估报告

---

## 4. 输入与数据集设计

### 4.1 主数据源选择
主数据源优先使用 CIC-IDS-2017 的 `TrafficLabelling`，原因是：
- 含 `Source IP / Destination IP / Port / Timestamp / Label`
- 便于映射阻断目标
- 更适合 CSV 通道与阻断系统设计

`MachineLearningCVE` 更适合作为传统 ML 分类基线，不是本系统主输入。

### 4.2 恶意总集构建
已实现：
- [backend/dataset/cic_ids2017_builder.py](/home/os/FinalCode/malblock/backend/dataset/cic_ids2017_builder.py)
- [backend/scripts/build_cic_dataset.py](/home/os/FinalCode/malblock/backend/scripts/build_cic_dataset.py)

当前输出：
- `backend/datasets/cic_ids2017_trafficlabelling/malicious_merged_cleaned.csv`
- `backend/datasets/cic_ids2017_trafficlabelling/manifest.json`

构建规则：
- 遍历全部 `TrafficLabelling` CSV
- 仅保留恶意流量
- 清洗关键字段
- 去重
- 保留来源字段：
  - `source_file`
  - `source_day`
  - `original_row_id`

### 4.3 CSV 通道采样模式
当前支持三种采样模式：
- `priority`
  - 恶意优先、严重度高优先、包速高优先
- `random`
  - 全局随机抽样
- `stratified_label`
  - 按标签分层随机抽样，尽量覆盖更多攻击类型

推荐论文实验参数：

```bash
--topk 100 --exclude-benign --selection-mode stratified_label --seed 42
```

---

## 5. 模块设计

### 5.1 统一通道入口
主要入口：
- [backend/scripts/run_offline_channel.py](/home/os/FinalCode/malblock/backend/scripts/run_offline_channel.py)
- [backend/scripts/run_replay_channel.py](/home/os/FinalCode/malblock/backend/scripts/run_replay_channel.py)
- [backend/scripts/run_csv_channel.py](/home/os/FinalCode/malblock/backend/scripts/run_csv_channel.py)
- [backend/scripts/run_channel.py](/home/os/FinalCode/malblock/backend/scripts/run_channel.py)

统一输出目录：
- `backend/jobs/<job_id>/`

统一摘要文件：
- `channel_summary.json`
- `evaluation_report.json`

### 5.2 告警抽取与过滤
适用：通道 A / B

主要文件：
- [backend/pipeline/suricata_alerts.py](/home/os/FinalCode/malblock/backend/pipeline/suricata_alerts.py)

功能：
- 从 `eve.json` 抽取 `event_type=alert`
- 清理缺失字段
- 过滤已知噪声 signature：
  - invalid checksum
  - invalid ack
  - unable to match response to request
  - request header invalid
  - gzip decompression failed

输出：
- `alerts_raw.jsonl`
- `alerts_filtered.jsonl`

### 5.3 时间窗聚合
适用：通道 A / B

主要文件：
- [backend/pipeline/window_aggregate.py](/home/os/FinalCode/malblock/backend/pipeline/window_aggregate.py)

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

当前排序逻辑：
- `hits` 越高越优先
- `severity_min` 越高风险越优先
- 目标越集中越优先
- burst 越明显越优先

### 5.4 CSV 流级适配
适用：通道 C

主要文件：
- [backend/pipeline/csv_flow_adapter.py](/home/os/FinalCode/malblock/backend/pipeline/csv_flow_adapter.py)

当前能力：
- 支持 ISO / 多种常见时间格式解析
- 支持 `malicious_merged_cleaned.csv`
- 为每条流构造统一 window
- 自动派生：
  - `attack_family`
  - `severity`
  - `CSV_FLOW::<label>` 伪 signature

### 5.5 RAG + LLM 决策
主要文件：
- [backend/agent/message_builder.py](/home/os/FinalCode/malblock/backend/agent/message_builder.py)
- [backend/agent/build_messages.py](/home/os/FinalCode/malblock/backend/agent/build_messages.py)
- [backend/agent/prompt.py](/home/os/FinalCode/malblock/backend/agent/prompt.py)
- [backend/agent/policy.py](/home/os/FinalCode/malblock/backend/agent/policy.py)
- [backend/agent/llm_agent_sf.py](/home/os/FinalCode/malblock/backend/agent/llm_agent_sf.py)
- [backend/agent/run_agent_batch.py](/home/os/FinalCode/malblock/backend/agent/run_agent_batch.py)

#### 5.5.1 当前消息结构
每条 message 包含：
- `constraints`
- `hints`
- `window`
- `evidence_window`
- `retrieved_evidence`
- `decision_context`
- `meta`

#### 5.5.2 RAG 检索对象
当前不是检索原始告警，而是检索历史策略案例：
- `incident_profile`
- `historical_strategy`
- `execution_result`
- `feedback`

#### 5.5.3 动态上下文与递进处罚
当前已实现：
- 同一 `src_ip` 的批次内历史上下文
- `prior_block_count / prior_rate_limit_count / prior_watch_count`
- `same_attack_family_seen_count / same_label_seen_count`
- `current_enforcement_mode / current_enforcement_ttl_sec`
- `max_block_ttl_sec_seen`

对应效果：
- 重复恶意流量会触发 TTL 升级
- 已有同等级或更强处置时，会短路执行
- 产生：
  - `skipped_execution`
  - `covered_by_existing_action`
  - `covered_by_existing_block`

### 5.6 执行模块
主要文件：
- [backend/agent/mcp_enforcer_server.py](/home/os/FinalCode/malblock/backend/agent/mcp_enforcer_server.py)
- [backend/agent/mcp_enforcer_client.py](/home/os/FinalCode/malblock/backend/agent/mcp_enforcer_client.py)

支持工具：
- `block_ip`
- `rate_limit_ip`
- `watch_ip`
- `unblock_ip`
- `list_blocked`

当前 nft set：
- `blocklist_v4`
- `ratelimit_v4`
- `watchlist_v4`

当前 live 规则含义：
- `blocklist_v4` -> 直接 `drop`
- `ratelimit_v4` -> 限速通过，超限 `drop`
- `watchlist_v4` -> 记录日志，不阻断

当前执行保障：
- `DRY_RUN`
- 白名单保护
- 审计日志
- 重复下发识别

### 5.7 在线实验环境
为了支持真正的在线回放实验，当前已增加专用环境脚本：
- [backend/scripts/init_replay_env.sh](/home/os/FinalCode/malblock/backend/scripts/init_replay_env.sh)
- [backend/scripts/reset_replay_env.sh](/home/os/FinalCode/malblock/backend/scripts/reset_replay_env.sh)

默认创建：
- `netns = mbreplay`
- Suricata 监听接口：`veth-mb-host`
- tcpreplay 回放接口：`veth-mb-replay`
- 默认将两端 veth MTU 调整为 `9000`

该环境用于保证：
- 回放流量和监听流量路径可控
- 在线实验可重复搭建
- 降低 `tcpreplay` 在 veth 环境中因超 MTU 报文触发 `Message too long` 的概率

---

## 6. LLM Agent 设计

### 6.1 决策输入
- `constraints`
- `hints`
- `window`
- `evidence_window`
- `retrieved_evidence`
- `decision_context`
- `meta`

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

### 6.3 运行时保护
当前已实现：
- 进入模型前 `precheck_action`
- 输出 schema 校验
- 工具参数运行时补全
- 工具失败时 fallback
- 已有更强策略时短路执行

---

## 7. 评估模块设计

主要文件：
- [backend/eval/channel_eval.py](/home/os/FinalCode/malblock/backend/eval/channel_eval.py)

统一输出：
- `evaluation_report.json`

### 7.1 CSV 通道评估
当前支持：
- `tp / fp / tn / fn`
- `precision / recall / f1`
- `per_label_metrics`
- `per_attack_family_metrics`
- `per_source_day_metrics`
- `false_positive_cases / false_negative_cases / review_cases`

### 7.2 离线 / 在线通道评估
当前重点：
- `action_distribution`
- `execution_mode_distribution`
- `tool_success_count / tool_failure_count`
- `skipped_execution_count`
- `covered_by_existing_action_count`
- `mean_suppression_ratio`

---

## 8. 前端展示层设计

主要文件：
- [frontend/src/App.jsx](/home/os/FinalCode/malblock/frontend/src/App.jsx)
- [frontend/src/styles.css](/home/os/FinalCode/malblock/frontend/src/styles.css)

当前前端已落地为研究平台控制台，支持：
- 主页面选择三类实验通道
- 各通道独立控制面板
- 历史 job 列表
- LLM 决策流展示
- nft 执行流展示
- 最终实验结果展示
- 结构化评估摘要
- **nft 实时状态模块**

### 8.1 nft 实时状态模块
当前每个通道页面都支持读取系统实时 nft 状态，展示：
- `blocklist_v4`
- `ratelimit_v4`
- `watchlist_v4`

每个集合当前展示：
- 成员数
- 每个成员的 IP
- `TTL`
- `剩余时间`

该模块不依赖历史 job，而是读取系统当前 live nft 状态。

---

## 9. 当前项目进度

### 9.1 已完成
1. 恶意总集构建完成
2. CSV 通道适配完成
3. CSV 多种采样模式完成
4. 离线 PCAP 通道完成
5. 在线回放通道完成
6. 在线通道已升级为**流式窗口处理**
7. RAG + LLM 决策链完成
8. MCP + nftables 执行链完成
9. 动态 TTL 升级与短路执行完成
10. 结构化评估模块完成
11. Web 前端控制台完成
12. nft 实时状态展示完成
13. 在线实验环境脚本完成
14. 系统级 nftables 持久化配置完成

### 9.2 当前系统状态
当前系统已经不再是脚本拼接验证，而是一个完整的实验平台，具备：
- 可运行
- 可评估
- 可解释
- 可执行
- 可展示

### 9.3 当前仍待优化
1. 在线通道虽然已流式化，但仍以 `eve.json` 增量读取为主，后续可进一步演进为更严格的实时事件驱动处理。
2. `evaluation_report -> RAG feedback` 还未自动回写闭环。
3. 离线通道仍可能受到高频噪声窗口影响，后续可继续优化预筛选策略。
4. 前端图表与论文图表导出仍可继续增强。

---

## 10. 推荐运行方式

### 10.1 CSV 通道
```bash
python3 backend/scripts/run_channel.py csv \
  --csv /home/os/FinalCode/malblock/backend/datasets/cic_ids2017_trafficlabelling/malicious_merged_cleaned.csv \
  --job-id csv_malicious_stratified_001 \
  --topk 100 \
  --exclude-benign \
  --selection-mode stratified_label \
  --seed 42 \
  --rag-top-k 3
```

### 10.2 离线通道
```bash
python3 backend/scripts/run_channel.py offline \
  --pcap /home/os/FinalCode/data/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap \
  --job-id offline_tuesday_001 \
  --window-sec 60 \
  --min-hits 3 \
  --topk 20 \
  --rag-top-k 3
```

### 10.3 在线流式通道
先初始化实验环境：

```bash
/home/os/FinalCode/malblock/backend/scripts/init_replay_env.sh
```

若需要显式指定 MTU，也可执行：

```bash
HOST_MTU=9000 REPLAY_MTU=9000 /home/os/FinalCode/malblock/backend/scripts/init_replay_env.sh
```

再运行在线通道：

```bash
/home/os/FinalCode/malblock/backend/MBvenv/bin/python \
  /home/os/FinalCode/malblock/backend/scripts/run_channel.py replay \
  --pcap /home/os/FinalCode/data/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap \
  --suricata-interface veth-mb-host \
  --replay-interface veth-mb-replay \
  --replay-netns mbreplay \
  --job-id replay_tuesday_stream_001 \
  --suricata-checksum-mode none \
  --replay-speed topspeed \
  --capture-wait-sec 2 \
  --suricata-ready-timeout-sec 180 \
  --window-sec 60 \
  --min-hits 3 \
  --topk 20 \
  --rag-top-k 3
```

---

## 11. 当前阶段总结
MalBlock 当前已经完成从研究原型向“可演示、可执行、可评估的毕业设计系统”的升级。  
其中最关键的当前进展有三点：

1. **LLM 不再只是分类器，而是结构化阻断策略生成器**
2. **nftables 已真实接入执行链路**
3. **在线通道已实现基于窗口周期的流式处理机制**

因此，当前系统已经具备较强的论文实现价值和答辩展示价值。
