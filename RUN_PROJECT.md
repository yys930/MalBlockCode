# MalBlock 项目运行指南

本文档说明如何在当前项目中完成环境准备、前后端启动、数据集构建，以及三类实验通道的运行。默认项目根目录为：

```bash
/home/os/FinalCode/malblock
```

---

## 1. 项目简介

MalBlock 是一个“基于大模型的恶意流量阻断系统”本科毕业设计项目。当前系统支持三类实验通道：

- **CSV 通道**：直接读取结构化流量记录，适合快速跑批和量化评估。
- **离线 PCAP 通道**：使用 Suricata 对 PCAP 做离线检测，再进行聚合、LLM 决策与执行。
- **在线 Replay 通道**：在实验网络环境中回放 PCAP，进行流式检测、滚动决策与执行。

系统整体闭环为：

```text
流量输入 -> 检测/特征提取 -> 结构化证据 -> RAG + LLM 决策 -> nftables 执行 -> 评估 -> 前端展示
```

---

## 2. 环境准备

### 2.1 后端 Python 环境

项目当前默认使用以下虚拟环境：

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

当前 API 依赖主要包括：

- `fastapi`
- `uvicorn`
- `python-dotenv`

> 说明：项目中的 LLM、RAG、Suricata、MCP、nftables 等其他依赖，应以你当前已有的后端运行环境为准。如果后端主流程此前已经能跑，通常无需重新搭建。

---

### 2.2 前端 Node 环境

进入前端目录并安装依赖：

```bash
cd /home/os/FinalCode/malblock/frontend
npm install
```

当前前端基于：

- React 18
- Vite 5

---

### 2.3 关键环境变量

如果需要真实调用大模型，请先设置：

```bash
export SILICONFLOW_API_KEY=你的密钥
```

如果只是调试流程，不希望真实修改 nftables，建议开启：

```bash
export DRY_RUN=1
```

建议在调试、演示和论文截图阶段优先使用 `DRY_RUN=1`，避免误修改系统防火墙规则。

---

## 3. 前后端启动

建议开启两个终端，分别运行后端 API 和前端页面。

### 3.1 启动后端 API

在后端目录中执行：

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

---

### 3.2 启动前端

在前端目录中执行：

```bash
cd /home/os/FinalCode/malblock/frontend
npm run dev
```

默认访问地址：

- `http://127.0.0.1:5173`

前端默认请求后端：

- `http://127.0.0.1:8000/api`

因此通常需要保证前后端同时启动。

---

## 4. 数据集构建

如果你已经有构建好的数据集文件，可以跳过这一节。

如果需要从 CIC-IDS-2017 的 `TrafficLabelling` 原始 CSV 构建项目所需数据集，可执行：

```bash
cd /home/os/FinalCode/malblock/backend
source MBvenv/bin/activate
python scripts/build_cic_dataset.py \
  --input-dir /home/os/FinalCode/data/CIC-IDS-2017/CSVs/TrafficLabelling \
  --output-dir /home/os/FinalCode/malblock/backend/datasets/cic_ids2017_trafficlabelling \
  --dedupe-mode flow \
  --mixed-eval-benign-ratio 1.0 \
  --mixed-eval-seed 42
```

构建完成后，通常会得到：

- `backend/datasets/cic_ids2017_trafficlabelling/malicious_merged_cleaned.csv`
- `backend/datasets/cic_ids2017_trafficlabelling/mixed_eval_cleaned.csv`
- `backend/datasets/cic_ids2017_trafficlabelling/manifest.json`

其中：

- `malicious_merged_cleaned.csv`：适合只看恶意样本策略输出。
- `mixed_eval_cleaned.csv`：适合正式评估，包含恶意与 benign 样本。

---

## 5. 统一运行入口

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

其中常见输出包括：

- `channel_summary.json`
- `llm_inputs_selected.jsonl`
- `llm_decisions.jsonl`
- `evaluation_report.json`

---

## 6. 运行 CSV 通道

CSV 通道适合快速跑批，也最适合做量化评估。

### 6.1 仅恶意样本策略分析

```bash
python backend/scripts/run_channel.py csv \
  --csv /home/os/FinalCode/malblock/backend/datasets/cic_ids2017_trafficlabelling/malicious_merged_cleaned.csv \
  --job-id csv_malicious_001 \
  --topk 100 \
  --exclude-benign \
  --selection-mode stratified_label \
  --seed 42 \
  --rag-top-k 3
```

适合用于：

- 查看不同攻击类型下的策略分布
- 做答辩演示
- 分析 LLM 输出风格与处置倾向

### 6.2 正式 mixed-eval 评估

```bash
python backend/scripts/run_channel.py csv \
  --csv /home/os/FinalCode/malblock/backend/datasets/cic_ids2017_trafficlabelling/mixed_eval_cleaned.csv \
  --job-id csv_mixed_eval_001 \
  --topk 200 \
  --selection-mode stratified_label \
  --seed 42 \
  --rag-top-k 3
```

适合用于：

- 输出 `precision / recall / f1`
- 进行论文中的主量化实验
- 对比不同采样方式的效果

---

## 7. 运行离线 PCAP 通道

离线通道适合复盘单个 PCAP 的完整检测与处置闭环。

```bash
python backend/scripts/run_channel.py offline \
  --pcap /home/os/FinalCode/data/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap \
  --job-id offline_tuesday_001 \
  --window-sec 60 \
  --min-hits 3 \
  --topk 20 \
  --rag-top-k 3
```

说明：

- `window-sec`：时间窗长度
- `min-hits`：进入候选窗口的最小告警数
- `topk`：送入 LLM 的窗口数量
- `rag-top-k`：RAG 检索历史案例数量

适合用于：

- 复现实验流程
- 展示告警聚合 → LLM 决策 → 执行 → 评估
- 观察策略智能性和执行有效性

---

## 8. 运行在线 Replay 通道

在线 Replay 通道适合做联机演示，但环境准备要求更高。

### 8.1 初始化 replay 实验环境

先执行：

```bash
/home/os/FinalCode/malblock/backend/scripts/init_replay_env.sh
```

该脚本会默认创建：

- `netns = mbreplay`
- Suricata 监听接口：`veth-mb-host`
- tcpreplay 回放接口：`veth-mb-replay`

如果需要手动指定 MTU，可执行：

```bash
HOST_MTU=9000 REPLAY_MTU=9000 /home/os/FinalCode/malblock/backend/scripts/init_replay_env.sh
```

---

### 8.2 运行 replay 通道

```bash
python backend/scripts/run_channel.py replay \
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

适合用于：

- 联机演示系统闭环
- 观察滚动窗口式流式处理
- 分析阻断后风险窗口变化趋势

---

### 8.3 清理 replay 环境

实验结束后可执行：

```bash
/home/os/FinalCode/malblock/backend/scripts/reset_replay_env.sh
```

---

## 9. nftables 真实执行

如果希望系统把 `block / rate_limit / watch` 真实写入 nftables，则需要初始化规则：

```bash
/home/os/FinalCode/malblock/backend/scripts/init_nftables.sh
```

完成测试后可重置：

```bash
/home/os/FinalCode/malblock/backend/scripts/reset_nftables.sh
```

如果只是希望调试逻辑、不希望改动系统规则，请始终设置：

```bash
export DRY_RUN=1
```

建议：

- **调试阶段**：使用 `DRY_RUN=1`
- **正式演示真实阻断前**：再关闭 `DRY_RUN`

---

## 10. 重新评估已有任务

如果某个 job 已经运行完成，但你想重新生成评估报告，可以执行：

```bash
cd /home/os/FinalCode/malblock/backend
source MBvenv/bin/activate
python scripts/evaluate_channel.py --job-dir /home/os/FinalCode/malblock/backend/jobs/你的job_id
```

评估结果输出位置：

```bash
backend/jobs/<job_id>/evaluation_report.json
```

---

## 11. 前端使用说明

前端启动后，进入浏览器页面可进行以下操作：

- 选择三类实验通道
- 配置任务参数并启动实验
- 查看历史 job 列表
- 查看 LLM 决策流
- 查看 nft 执行流
- 查看最终实验结果
- 查看结构化评估摘要
- 查看系统当前 nft 实时状态

如果页面无法加载数据，请优先检查：

1. 后端 API 是否已启动
2. `http://127.0.0.1:8000/api/health` 是否正常
3. 前端是否正常运行在 `5173`

---

## 12. 推荐运行顺序

如果你是第一次完整跑这个项目，建议按以下顺序：

### 方案 A：先跑最稳妥的论文实验

1. 启动后端 API
2. 启动前端
3. 设置 `DRY_RUN=1`
4. 运行 CSV mixed-eval 通道
5. 查看 `evaluation_report.json` 和前端结果

这是最稳妥、最适合论文写作的路线。

### 方案 B：做完整闭环演示

1. 启动后端 API
2. 启动前端
3. 设置 `DRY_RUN=1`
4. 运行离线 PCAP 通道
5. 查看决策流、执行流和评估结果

这是最适合答辩展示闭环逻辑的路线。

### 方案 C：做联机演示

1. 初始化 replay 环境
2. 启动后端 API
3. 启动前端
4. 设置 `DRY_RUN=1`
5. 运行 replay 通道
6. 观察实时决策与执行结果

这是展示系统联机能力的路线，但环境要求更高。

---

## 13. 常见问题

### 13.1 `python: can't open file ... backend/backend/scripts/...`

说明你已经在 `backend/` 目录下，却又写了 `backend/scripts/...`。

如果你在 `backend/` 目录下，应写成：

```bash
python scripts/run_api.py
python scripts/build_cic_dataset.py ...
```

如果你在项目根目录下，则可以写成：

```bash
python backend/scripts/run_api.py
```

---

### 13.2 前端打不开数据

先检查：

```bash
curl http://127.0.0.1:8000/api/health
```

如果能返回 `{"status":"ok"}`，说明后端没问题；否则先解决后端启动问题。

---

### 13.3 大模型无法调用

请确认是否已设置：

```bash
export SILICONFLOW_API_KEY=你的密钥
```

如果未设置，LLM 决策链会失败。

---

### 13.4 不想让系统真实修改 nftables

请确认设置：

```bash
export DRY_RUN=1
```

这样执行层会返回模拟成功结果，而不会真的修改系统规则。

---

## 14. 最简启动方案

如果你现在只想尽快跑通一次项目，建议直接执行：

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

### 然后在浏览器中打开

```text
http://127.0.0.1:5173
```

进入页面后，优先选择 **CSV 通道** 进行第一次实验。

---

## 15. 建议

对于本科毕业设计答辩，建议你优先准备以下两种运行方式：

1. **CSV mixed-eval 实验**：适合展示量化结果和评估指标。
2. **离线 PCAP 实验**：适合展示完整闭环流程和系统可执行性。

如果时间充足，再准备 replay 通道作为联机演示增强项。
