# MalBlock 项目运行指南

本文档说明如何启动前后端、运行三类实验通道，并查看论文所需评估结果。默认项目根目录为：

```bash
/home/os/FinalCode/malblock
```

---

## 1. 项目简介

MalBlock 是一个“基于大模型的恶意流量阻断系统”本科毕业设计项目。系统支持三类实验通道：

- **CSV 通道**：直接读取结构化流量记录，适合快速跑批和量化评估；
- **离线 PCAP 通道**：使用 Suricata 对 PCAP 做离线检测，再进行聚合、LLM 决策与执行；
- **在线 Replay 通道**：在实验网络环境中回放 PCAP，进行流式检测、滚动决策与执行。

系统整体闭环为：

```text
流量输入 -> Suricata 检测/告警 -> 结构化证据 -> RAG + LLM 决策 -> nftables 执行 -> 评估 -> 前端展示
```

论文主线应围绕以下评估维度展开：
- 决策有效性评估
- 执行有效性评估
- 干预收益观察评估
- 数据覆盖性评估（可选）

---

## 2. 环境准备

### 2.1 后端 Python 环境

项目默认使用以下虚拟环境：

```bash
/home/os/FinalCode/malblock/backend/MBvenv
```

激活方式：

```bash
cd /home/os/FinalCode/malblock/backend
source MBvenv/bin/activate
```

如果需要安装 API 依赖，可执行：

```bash
pip install -r requirements-api.txt
```

### 2.2 前端 Node 环境

进入前端目录并安装依赖：

```bash
cd /home/os/FinalCode/malblock/frontend
npm install
```

### 2.3 关键环境变量

真实调用大模型前，请先设置：

```bash
export SILICONFLOW_API_KEY=你的密钥
```

如果只是调试流程、不希望真实修改 nftables，建议开启：

```bash
export DRY_RUN=1
```

---

## 3. 前后端启动

建议开启两个终端，分别运行后端 API 和前端页面。

### 3.1 启动后端 API

```bash
cd /home/os/FinalCode/malblock/backend
source MBvenv/bin/activate
python scripts/run_api.py
```

默认监听地址：
- `http://127.0.0.1:8000`
- API 前缀：`http://127.0.0.1:8000/api`

可先用以下命令检查后端是否正常：

```bash
curl http://127.0.0.1:8000/api/health
```

如果返回：

```json
{"status":"ok"}
```

说明后端 API 已启动成功。

### 3.2 启动前端

```bash
cd /home/os/FinalCode/malblock/frontend
npm run dev
```

默认访问地址：
- `http://127.0.0.1:5173`

---

## 4. 统一运行入口

项目三类实验通道统一入口为：

```bash
backend/scripts/run_channel.py
```

推荐在项目根目录执行：

```bash
cd /home/os/FinalCode/malblock
source backend/MBvenv/bin/activate
```

每次运行完成后，对应结果通常保存在：

```bash
backend/jobs/<job_id>/
```

常见输出包括：
- `channel_summary.json`
- `llm_inputs_selected.jsonl`
- `llm_decisions.jsonl`
- `evaluation_report.json`

---

## 5. 运行 CSV 通道

CSV 通道最适合做论文中的 **决策有效性评估**。

### 5.1 快速运行示例

```bash
python backend/scripts/run_channel.py csv \
  --csv /home/os/FinalCode/malblock/backend/datasets/cic_ids2017_trafficlabelling/mixed_eval_cleaned.csv \
  --job-id csv_mixed_eval_001 \
  --topk 100 \
  --selection-mode stratified_label \
  --seed 42 \
  --rag-top-k 3
```

### 5.2 重新生成评估报告

```bash
python backend/scripts/evaluate_channel.py \
  --job-dir /home/os/FinalCode/malblock/backend/jobs/csv_mixed_eval_001
```

重点关注：
- `decision_eval.risk_detection_metrics.*`
- `decision_eval.strong_mitigation_metrics.*`
- `dataset_summary.*`

---

## 6. 运行离线 PCAP 通道

离线通道适合复盘单个 PCAP 的完整检测与处置闭环，主要用于 **执行有效性评估** 和 **干预收益观察评估**。

```bash
python backend/scripts/run_channel.py offline \
  --pcap /home/os/FinalCode/data/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap \
  --job-id offline_tuesday_001 \
  --window-sec 60 \
  --min-hits 3 \
  --topk 20 \
  --rag-top-k 3
```

评估：

```bash
python backend/scripts/evaluate_channel.py \
  --job-dir /home/os/FinalCode/malblock/backend/jobs/offline_tuesday_001
```

重点关注：
- `decision_eval.decision_count`
- `execution_eval.*`
- `effect_eval.mean_suppression_ratio`
- `dataset_summary.*`

---

## 7. 运行在线 Replay 通道

在线 Replay 通道适合做联机演示与在线联动验证。

### 7.1 初始化 replay 实验环境

```bash
/home/os/FinalCode/malblock/backend/scripts/init_replay_env.sh
```

该脚本默认创建：
- `netns = mbreplay`
- Suricata 监听接口：`veth-mb-host`
- tcpreplay 回放接口：`veth-mb-replay`

### 7.2 运行 replay 通道

```bash
python backend/scripts/run_channel.py replay \
  --pcap /home/os/FinalCode/data/CIC-IDS-2017/PCAPs/Thursday-WorkingHours.pcap \
  --suricata-interface veth-mb-host \
  --replay-interface veth-mb-replay \
  --replay-netns mbreplay \
  --job-id replay_thursday_001 \
  --suricata-checksum-mode none \
  --replay-speed multiplier \
  --tcpreplay-extra-arg 10 \
  --capture-wait-sec 2 \
  --suricata-ready-timeout-sec 180 \
  --window-sec 60 \
  --min-hits 3 \
  --topk 20 \
  --rag-top-k 3
```

评估：

```bash
python backend/scripts/evaluate_channel.py \
  --job-dir /home/os/FinalCode/malblock/backend/jobs/replay_thursday_001
```

重点关注：
- `stream_alert_count_raw`
- `stream_alert_count_filtered`
- `execution_eval.*`
- `effect_eval.mean_suppression_ratio`

### 7.3 清理 replay 环境

```bash
/home/os/FinalCode/malblock/backend/scripts/reset_replay_env.sh
```

---

## 8. nftables 真实执行

如果希望系统把 `block / rate_limit / watch` 真实写入 nftables，则需要初始化规则：

```bash
/home/os/FinalCode/malblock/backend/scripts/init_nftables.sh
```

完成测试后可重置：

```bash
/home/os/FinalCode/malblock/backend/scripts/reset_nftables.sh
```

如果只是调试逻辑、不希望改动系统规则，请始终设置：

```bash
export DRY_RUN=1
```

---

## 9. 前端使用说明

前端启动后，页面可用于：
- 选择三类实验通道；
- 配置任务参数并启动实验；
- 查看历史 job 列表；
- 查看 LLM 决策流；
- 查看 nft 执行流；
- 查看最终实验结果；
- 查看结构化评估摘要；
- 对 replay 结果做执行 / 无执行对照评估。

如果页面无法加载数据，请优先检查：
1. 后端 API 是否已启动；
2. `http://127.0.0.1:8000/api/health` 是否正常；
3. 前端是否正常运行在 `5173`。

---

## 10. 推荐运行顺序

如果你是第一次完整跑这个项目，建议按以下顺序：

### 方案 A：先跑论文主实验
1. 启动后端 API
2. 启动前端
3. 设置 `DRY_RUN=1`
4. 运行 CSV 通道
5. 查看 `evaluation_report.json` 和前端评估结果

### 方案 B：做完整闭环演示
1. 启动后端 API
2. 启动前端
3. 设置 `DRY_RUN=1`
4. 运行离线 PCAP 通道
5. 查看决策流、执行流和评估结果

### 方案 C：做联机演示
1. 初始化 replay 环境
2. 启动后端 API
3. 启动前端
4. 设置 `DRY_RUN=1`
5. 运行 replay 通道
6. 观察实时决策与执行结果

---

## 11. 常见问题

### 11.1 `python: can't open file ... backend/backend/scripts/...`
说明你已经在 `backend/` 目录下，却又写了 `backend/scripts/...`。

如果你在 `backend/` 目录下，应写成：

```bash
python scripts/run_api.py
python scripts/evaluate_channel.py --job-dir ...
```

如果你在项目根目录下，则可以写成：

```bash
python backend/scripts/run_api.py
```

### 11.2 前端打不开数据
先检查：

```bash
curl http://127.0.0.1:8000/api/health
```

### 11.3 大模型无法调用
请确认是否已设置：

```bash
export SILICONFLOW_API_KEY=你的密钥
```

### 11.4 不想让系统真实修改 nftables
请确认设置：

```bash
export DRY_RUN=1
```

---

## 12. 最简启动方案

### 终端 1：启动后端

```bash
cd /home/os/FinalCode/malblock/backend
source MBvenv/bin/activate
export SILICONFLOW_API_KEY=你的密钥
export DRY_RUN=1
python scripts/run_api.py
```

### 终端 2：启动前端

```bash
cd /home/os/FinalCode/malblock/frontend
npm install
npm run dev
```

然后在浏览器中打开：

```text
http://127.0.0.1:5173
```

进入页面后，优先选择 **CSV 通道** 完成第一次实验。
