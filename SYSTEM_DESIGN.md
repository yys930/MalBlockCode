# 系统设计文档：基于 LLM 的恶意流量阻断闭环系统（MalBlock）

## 1. 项目概述
**项目名称**：MalBlock — 基于 LLM 的恶意流量阻断研究系统  
**运行环境**：Ubuntu 22.04 虚拟机  
**数据集**：CIC-IDS-2017（PCAP + TrafficLabelling CSV）

**研究目标**：
构建一个可运行的闭环恶意流量阻断系统，支持 **实时回放** 与 **离线回放** 两种流量输入方式，基于 Suricata 告警进行特征聚合，并由 LLM Agent 生成阻断策略，执行阻断后进行效果评估与反馈；同时提供 Web 可视化界面和量化评估结果，满足本科毕业设计的研究性与工程性要求。

**闭环定义**：
`流量输入 → 检测告警 → 特征聚合 → RAG+LLM 决策 → 阻断执行 → 反馈评估 → 策略修正`

---

## 2. 设计原则与研究假设

### 2.1 设计原则
1. **可复现**：所有关键环节可在离线 PCAP 回放中复现。
2. **可解释**：LLM 决策必须输出结构化证据，支持审计与可视化。
3. **可评估**：利用 CSV 标签对决策效果进行量化评估。
4. **可扩展**：模块化设计，便于替换模型与检测引擎。
5. **可控安全**：阻断动作受到严格约束与白名单保护。

### 2.2 研究假设
1. LLM 能在结构化告警特征与历史证据支持下生成有效阻断策略。
2. RAG 引入历史决策与反馈可降低误伤率并提高决策一致性。
3. 以窗口级 IP 决策作为评估粒度可合理衡量阻断效果。

---

## 3. 系统总体架构

### 3.1 架构分层
1. **流量输入层**：PCAP 实时回放 / 离线回放
2. **检测层**：Suricata 生成 `eve.json`
3. **数据处理层**：告警抽取、噪声过滤、时间窗聚合
4. **智能决策层**：RAG + LLM Agent
5. **执行层**：nftables 阻断 / 解封（MCP）
6. **反馈评估层**：量化效果评估 + 反馈修正
7. **可视化层**：Web Dashboard

### 3.2 数据流
1. **实时模式**：
   - `tcpreplay` 回放 PCAP → 虚拟网卡
   - Suricata 监听网卡 → `eve.json`
   - 实时抽取 `alert` → `alerts_filtered.jsonl`

2. **离线模式**：
   - `suricata -r` 读取 PCAP → `eve.json`
   - 批处理抽取与聚合

3. **统一后续处理**：
   - 告警 → 时间窗聚合 → LLM 输入
   - LLM 决策 → 阻断执行 → 反馈评估

---

## 4. 模块设计

### 4.1 流量输入模块
**功能**：提供实时与离线两种流量输入模式。  
- 实时回放：`tcpreplay` + `veth` 虚拟网卡  
- 离线回放：`suricata -r` 直接处理 PCAP  
**输出**：`eve.json`

### 4.2 检测与告警抽取模块
**功能**：从 Suricata 事件流中抽取 `alert` 并过滤噪声。  
- 过滤策略：
  - 已知噪声 signature 过滤
  - 统计型噪声过滤（可选）
**输出**：`alerts_filtered.jsonl`

### 4.3 时间窗聚合模块
**功能**：按 `src_ip + window_sec` 聚合告警。  
**窗口配置**：60s  
**输出特征**：
- hits
- severity_min
- top_signatures
- dest_ports
- top_dest_ips
- proto_top
- first_seen / last_seen
**输出文件**：`llm_inputs_selected.jsonl`

### 4.4 RAG + LLM 决策模块
**功能**：为 LLM 提供历史证据并生成阻断决策。

#### 4.4.1 历史证据库
记录以下信息：
- 窗口特征
- LLM 决策
- 阻断执行结果
- 反馈评估
- 检索重点不是“历史告警文本”，而是“历史策略案例”

#### 4.4.2 检索策略
- 当前实现：本地 JSONL 历史库 + 相似度打分检索
- 相似度特征：attack_family、top_signature、top_signatures 重合度、dest_ports 重合度、top_dest_ips 重合度、severity、hits
- 输出 TopK 相似历史案例
- 检索结果以历史策略为中心组织：incident_profile、historical_strategy、execution_result、feedback

#### 4.4.3 提示词注入
将检索结果作为 Evidence 片段插入 prompt，辅助决策。

#### 4.4.4 当前落地方式
- 历史案例库文件：`backend/rag/decision_history.jsonl`
- 每条历史案例包含：
  - `incident_profile`：当前事件画像（hints + window 摘要）
  - `historical_strategy`：历史处置策略（action、ttl、risk_score、reasons）
  - `execution_result`：工具执行结果
  - `feedback`：效果反馈与误伤状态
  - `job_id`、`window_key`
- `build_messages.py` 可在构建消息阶段预加载历史检索结果
- `run_agent_batch.py` 会在每次调用 LLM 前再次检索最新历史，并在决策完成后把当前结果写回历史库
- 这样同一批次中的后续样本也可以利用前面样本的处理结果

### 4.5 阻断执行模块
**实现**：MCP + nftables
- block_ip
- unblock_ip
- list_blocked

**保障**：
- 审计日志记录
- 支持 DRY_RUN
- 白名单保护

### 4.6 反馈评估模块
**功能**：评估阻断效果，形成闭环。  
**指标**：
- Precision / Recall / F1
- 误伤率（FP）
- 阻断有效率（TP）

**策略修正**：
- 告警未下降 → 延长 TTL
- 误伤发生 → 解封 + 白名单

### 4.7 Web 可视化模块
**前端**：React + Vite  
**后端**：FastAPI

**核心页面**：
1. 实时/离线任务列表
2. LLM 决策记录
3. 阻断管理（当前封禁列表）
4. 评估结果与趋势
5. 告警统计图

---

## 5. LLM Agent 设计

### 5.1 决策输入
- constraints：系统安全约束（严格遵守）
- hints：二次特征（噪声比例、可疑关键词、端口特征）
- window：聚合证据窗口（用于解释与审计）
- retrieved_evidence：RAG 检索得到的历史策略案例，重点包含过去的处置、执行结果与反馈

### 5.2 决策输出
必须为 JSON-only，符合 schema：
```
{
  "action": "block|observe|ignore|review",
  "target": {"type":"ip","value":"<src_ip>"},
  "ttl_sec": <int>,
  "confidence": <float 0..1>,
  "risk_score": <int 0..100>,
  "labels": ["<string>"],
  "reasons": ["<string>"],
  "evidence": {...},
  "tool_result": { ... }
}
```

### 5.3 约束策略
- action 必须来自 allowed_actions
- noise_only 时默认不 block
- TTL 范围限制
- 禁止封禁白名单 IP
- 不确定时 default_action_if_uncertain

### 5.4 Agent 运行时保护
- 在进入 LLM 前执行预检查，对纯噪声、高噪声、白名单 IP、非法 IP 直接给出保守策略
- 工具调用参数由运行时补全，强制将 `target.value` 与 `window.src_ip` 对齐
- 若最终输出为 `block`，则必须存在成功的 `block_ip` 工具结果
- 若工具已执行但最终 action 与之不一致，系统自动改写为可审计的保守结果，避免评估层读取到伪状态
- 对模型输出异常、JSON 解析失败、工具调用失败统一回退到 `fallback` 决策

---

## 6. 量化评估设计

### 6.1 真值来源
CIC-IDS-2017 `TrafficLabelling` CSV

### 6.2 评估粒度
`src_ip + 60s 时间窗`

### 6.3 混淆矩阵指标
- TP：恶意窗口被阻断
- FP：正常窗口被阻断
- FN：恶意窗口未阻断
- TN：正常窗口未阻断

### 6.4 指标计算
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2PR / (P + R)
- 误伤率 = FP / (FP + TN)
- 阻断有效率 = TP / (TP + FN)

### 6.5 按攻击类型评估
分别统计：DoS、PortScan、Botnet、Web Attack 等类别指标。

---

## 7. 数据与文件规范

### 7.1 统一输入输出
- `eve.json`
- `alerts_filtered.jsonl`
- `llm_inputs_selected.jsonl`
- `llm_decisions.jsonl`
- `evaluation_report.json`

### 7.2 决策 JSON Schema
必须包含：
- action
- target
- ttl_sec
- confidence
- risk_score
- labels
- reasons
- evidence

---

## 8. 可复现性设计
- 所有实验输出固定到 `backend/jobs/<job_id>/`
- 每次运行生成完整输出和 summary
- 便于对比不同参数、不同 LLM 模型的效果

---

## 9. 后续扩展
- 引入攻击类型识别与策略模板（按类别决定 TTL）
- 引入 RAG 历史案例库
- 引入在线学习式策略修正
- 引入多模型对比实验
