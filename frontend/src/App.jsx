import { useEffect, useMemo, useState } from "react";

const API_BASE = "http://127.0.0.1:8000/api";

const channelMeta = {
  offline: {
    key: "offline",
    title: "离线通道",
    subtitle: "Offline PCAP Experiment",
    description: "用于离线复现实验流程。通过 PCAP、Suricata、时间窗聚合和 LLM 阻断策略验证完整闭环。",
    accent: "离线复现",
    bullets: ["适合复盘 PCAP 样本", "关注 LLM 决策与执行闭环", "输出结构化评估结果"],
    historyTitle: "离线实验记录",
    controlTitle: "离线实验控制面板",
    controlNote: "围绕 PCAP 样本、时间窗聚合参数与候选窗口规模配置离线实验。适合复现实验流程并观察完整闭环。",
    decisionTitle: "离线通道 LLM 决策流",
    decisionNote: "突出展示离线检测链路下的 LLM 决策结果，包括动作、TTL、决策状态与策略说明。",
    executionTitle: "离线通道 nft 执行流",
    executionNote: "专门观察阻断执行层反馈，验证离线实验中是否成功执行、是否短路以及是否被已有策略覆盖。",
    finalTitle: "离线实验最终结果",
    finalNote: "汇总离线通道实验结束后的关键指标、策略分布与执行成效，作为最终实验结果展示。",
    evalTitle: "离线实验评估结果",
    evalNote: "展示离线通道的结构化评估摘要，包括数据覆盖、决策质量、执行表现与关键风险样本。",
    objectiveTitle: "实验目的",
    objectiveText: "复现离线 PCAP 样本在检测、聚合、LLM 决策与执行层上的完整闭环，适合做策略回溯和结果复盘。",
    recommendedTitle: "推荐参数",
    recommendedParams: ["window_sec=60", "min_hits=3", "topk=20", "rag_top_k=3"],
  },
  replay: {
    key: "replay",
    title: "在线通道",
    subtitle: "Replay / Online Experiment",
    description: "用于在线回放和联机验证。强调回放接口、检测接口与阻断执行层的协同工作。",
    accent: "联机验证",
    bullets: ["适合展示在线实验链路", "支持回放接口与命名空间参数", "便于验证执行层联动"],
    historyTitle: "在线实验记录",
    controlTitle: "在线实验控制面板",
    controlNote: "围绕回放接口、检测接口、回放速度和命名空间配置在线实验，适合联机演示阻断链路。",
    decisionTitle: "在线通道 LLM 决策流",
    decisionNote: "聚焦在线回放实验中的实时策略响应，适合观察联机场景下决策节奏与攻击处置变化。",
    executionTitle: "在线通道 nft 执行流",
    executionNote: "重点查看在线联动时的实际执行反馈，便于验证回放与执行层是否稳定协同。",
    finalTitle: "在线实验最终结果",
    finalNote: "汇总在线通道实验完成后的结果分布、关键指标与阻断表现，用于联机实验总结。",
    evalTitle: "在线实验评估结果",
    evalNote: "展示在线通道的压制效果、执行表现和关键风险样本，更适合用于系统联机验证。",
    objectiveTitle: "实验目的",
    objectiveText: "验证在线回放场景下检测链路、LLM 决策链路与 nft 执行链路的协同稳定性，适合做联机演示。",
    recommendedTitle: "推荐参数",
    recommendedParams: ["replay_speed=topspeed", "capture_wait_sec=2", "window_sec=60", "topk=20"],
  },
  csv: {
    key: "csv",
    title: "CSV 通道",
    subtitle: "Structured Flow Experiment",
    description: "用于直接读取结构化流量数据，快速验证 LLM 在理想输入条件下的策略决策能力。",
    accent: "结构化验证",
    bullets: ["适合快速跑批实验", "便于控制采样与随机种子", "适合比较策略分布与评估结果"],
    historyTitle: "CSV 实验记录",
    controlTitle: "CSV 实验控制面板",
    controlNote: "围绕结构化流数据路径、采样规模、标签分层模式和随机种子配置实验，适合快速跑批验证。",
    decisionTitle: "CSV 通道 LLM 决策流",
    decisionNote: "聚焦理想结构化输入条件下的 LLM 策略选择结果，适合观察决策分布与重复处罚逻辑。",
    executionTitle: "CSV 通道 nft 执行流",
    executionNote: "单独观察 CSV 实验中的执行结果，重点验证短路、covered 与 already_present 等执行指标。",
    finalTitle: "CSV 实验最终结果",
    finalNote: "汇总结构化输入实验的策略分布、性能指标与执行表现，用于分析理想输入条件下的上限表现。",
    evalTitle: "CSV 实验评估结果",
    evalNote: "重点展示结构化评估指标，例如 Precision、Recall、F1，以及关键误判或风险样本。",
    objectiveTitle: "实验目的",
    objectiveText: "在理想结构化输入条件下评估 LLM 的策略选择能力，适合做快速跑批和策略分布对比实验。",
    recommendedTitle: "推荐参数",
    recommendedParams: ["topk=100", "selection_mode=stratified_label", "seed=42", "exclude_benign=true"],
  },
};

const chartColors = ["#195dff", "#62c5ff", "#0f3f99", "#8bddff", "#5d8cff", "#1e8bbb"];

const defaultForms = {
  offline: {
    job_id: "",
    rag_top_k: 3,
    pcap: "",
    window_sec: 60,
    min_hits: 3,
    topk: 20,
  },
  replay: {
    job_id: "",
    rag_top_k: 3,
    pcap: "",
    suricata_interface: "",
    replay_interface: "",
    suricata_checksum_mode: "none",
    replay_speed: "topspeed",
    replay_netns: "",
    tcpreplay_extra_args: "",
    capture_wait_sec: 2,
    suricata_ready_timeout_sec: 180,
    window_sec: 60,
    min_hits: 3,
    topk: 20,
  },
  csv: {
    job_id: "",
    rag_top_k: 3,
    csv: "",
    topk: 100,
    exclude_benign: true,
    selection_mode: "stratified_label",
    seed: 42,
  },
};

const defaultReplayComparisonForm = {
  exec_job_dir: "",
  baseline_job_dir: "",
};

function formatNumber(value) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "string" && Number.isNaN(Number(value))) return value;
  return new Intl.NumberFormat("zh-CN").format(value);
}

function formatDecimal(value) {
  if (value === null || value === undefined || value === "") return "-";
  const parsed = Number(value);
  if (Number.isNaN(parsed)) return String(value);
  return Number.isInteger(parsed) ? formatNumber(parsed) : parsed.toFixed(3);
}

function formatRatio(value) {
  if (value === null || value === undefined || value === "") return "-";
  return `${(Number(value) * 100).toFixed(1)}%`;
}

function formatDateTime(value) {
  if (value === null || value === undefined || value === "") return "-";
  const date = new Date(Number(value) * 1000);
  if (Number.isNaN(date.getTime())) return "-";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatDurationSeconds(value) {
  if (value === null || value === undefined || value === "") return "-";
  const total = Number(value);
  if (!Number.isFinite(total) || total < 0) return "-";
  if (total < 1) return `${Math.round(total * 1000)}ms`;

  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = Math.floor(total % 60);
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  if (seconds || parts.length === 0) parts.push(`${seconds}s`);
  return parts.join(" ");
}

function channelJobName(channel) {
  if (channel === "csv") return "csv_flow";
  if (channel === "offline") return "offline_pcap";
  return "replay_online";
}

function jobMatchesChannel(job, channel) {
  return Boolean(job) && job.channel === channelJobName(channel);
}

function firstDefined(...values) {
  return values.find((value) => value !== null && value !== undefined && value !== "");
}

function getRiskMetrics(evaluation) {
  const decisionEval = evaluation?.decision_eval || {};
  return decisionEval.risk_detection_metrics || decisionEval.csv_metrics || {};
}

function getStrongMetrics(evaluation) {
  const decisionEval = evaluation?.decision_eval || {};
  return decisionEval.strong_mitigation_metrics || decisionEval.csv_metrics || {};
}

function compactCaseList(cases, limit = 5) {
  return (cases || []).slice(0, limit);
}

function DoughnutCard({ title, data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => Number(value) > 0);
  if (!entries.length) {
    return (
      <div className="chart-card">
        <div className="section-head">
          <h3>{title}</h3>
        </div>
        <div className="empty-state compact">暂无数据</div>
      </div>
    );
  }

  const total = entries.reduce((sum, [, value]) => sum + Number(value), 0);
  let start = 0;
  const segments = entries.map(([label, value], index) => {
    const percent = (Number(value) / total) * 100;
    const color = chartColors[index % chartColors.length];
    const segment = `${color} ${start.toFixed(2)}% ${(start + percent).toFixed(2)}%`;
    start += percent;
    return { label, value, color, segment };
  });
  const gradient = `conic-gradient(${segments.map((item) => item.segment).join(", ")})`;

  return (
    <div className="chart-card">
      <div className="section-head">
        <h3>{title}</h3>
      </div>
      <div className="chart-inner">
        <div className="doughnut" style={{ background: gradient }}>
          <div className="doughnut-center">
            <span>Total</span>
            <strong>{formatNumber(total)}</strong>
          </div>
        </div>
        <div className="legend-list">
          {segments.map((item) => (
            <div className="legend-row" key={item.label}>
              <span className="legend-dot" style={{ background: item.color }} />
              <span>{item.label}</span>
              <strong>{formatNumber(item.value)}</strong>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function HomePage({ onEnter }) {
  return (
    <div className="home-page">
      <header className="hero hero-home">
        <div className="hero-grid" />
        <div className="hero-content">
          <p className="eyebrow">MalBlock Research Platform</p>
          <h1>基于 LLM 的恶意流量阻断实验平台</h1>
          <p className="hero-copy">
            统一管理离线通道、在线回放通道与 CSV 结构化通道。每个通道采用独立页面组织实验控制、实时决策、执行回执与评估结果。
          </p>
        </div>
      </header>

      <section className="entry-section">
        <div className="entry-head">
          <div>
            <p className="section-kicker">Experiment Channels</p>
            <h2>选择实验通道</h2>
          </div>
        </div>
        <div className="entry-grid">
          {Object.values(channelMeta).map((item) => (
            <article className="entry-card" key={item.key}>
              <div className="entry-card-top">
                <div className="badge-row">
                  <span className="badge">{item.subtitle}</span>
                  <span className="badge subtle">{item.accent}</span>
                </div>
                <div className="entry-icon">{item.key === "offline" ? "A" : item.key === "replay" ? "B" : "C"}</div>
              </div>
              <h3>{item.title}</h3>
              <p>{item.description}</p>
              <ul className="entry-list">
                {item.bullets.map((text) => (
                  <li key={text}>{text}</li>
                ))}
              </ul>
              <button className="primary-btn entry-btn" onClick={() => onEnter(item.key)}>
                进入 {item.title}
              </button>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function RunPanel({ channel, meta, form, updateForm, onRun, latestRun }) {
  return (
    <section className="card control-card">
      <div className="section-head">
        <div>
          <p className="section-kicker">Operation Panel</p>
          <h2>{meta.controlTitle}</h2>
        </div>
        <button className="primary-btn" onClick={onRun}>
          启动实验
        </button>
      </div>
      <div className="panel-note">{meta.controlNote}</div>

      <div className="advice-grid">
        <article className="advice-card">
          <span>{meta.objectiveTitle}</span>
          <strong>{meta.accent}</strong>
          <p>{meta.objectiveText}</p>
        </article>
      </div>

      <div className="form-block">
        <section className="param-group">
          <div className="param-group-head">
            <span className="param-index">01</span>
            <div>
              <h3>通用任务参数</h3>
              <p>定义任务标识与 RAG 检索深度，适用于所有通道。</p>
            </div>
          </div>
          <div className="field-grid two-col">
            <label>
              <span>Job ID</span>
              <input value={form.job_id} onChange={(e) => updateForm("job_id", e.target.value)} placeholder="留空自动生成" />
            </label>
            <label>
              <span>RAG Top K</span>
              <input type="number" value={form.rag_top_k} onChange={(e) => updateForm("rag_top_k", Number(e.target.value))} />
            </label>
          </div>
        </section>

        {channel === "offline" && (
          <section className="param-group">
            <div className="param-group-head">
              <span className="param-index">02</span>
              <div>
                <h3>离线输入与聚合参数</h3>
                <p>配置离线 PCAP 输入以及时间窗聚合条件，用于控制候选窗口规模。</p>
              </div>
            </div>
            <label>
              <span>PCAP 路径</span>
              <input value={form.pcap} onChange={(e) => updateForm("pcap", e.target.value)} placeholder="/path/to/file.pcap" />
            </label>
            <div className="field-grid three-col">
              <label>
                <span>窗口秒数</span>
                <input type="number" value={form.window_sec} onChange={(e) => updateForm("window_sec", Number(e.target.value))} />
              </label>
              <label>
                <span>最小 hits</span>
                <input type="number" value={form.min_hits} onChange={(e) => updateForm("min_hits", Number(e.target.value))} />
              </label>
              <label>
                <span>Top K</span>
                <input type="number" value={form.topk} onChange={(e) => updateForm("topk", Number(e.target.value))} />
              </label>
            </div>
          </section>
        )}

        {channel === "replay" && (
          <>
            <section className="param-group">
              <div className="param-group-head">
                <span className="param-index">02</span>
                <div>
                  <h3>在线输入与接口参数</h3>
                  <p>配置 PCAP、检测接口、回放接口与命名空间，用于联机实验链路。</p>
                </div>
              </div>
              <label>
                <span>PCAP 路径</span>
                <input value={form.pcap} onChange={(e) => updateForm("pcap", e.target.value)} placeholder="/path/to/file.pcap" />
              </label>
              <div className="field-grid three-col">
                <label>
                  <span>Suricata 接口</span>
                  <input value={form.suricata_interface} onChange={(e) => updateForm("suricata_interface", e.target.value)} />
                </label>
                <label>
                  <span>Replay 接口</span>
                  <input value={form.replay_interface} onChange={(e) => updateForm("replay_interface", e.target.value)} />
                </label>
                <label>
                  <span>命名空间</span>
                  <input value={form.replay_netns} onChange={(e) => updateForm("replay_netns", e.target.value)} />
                </label>
              </div>
            </section>

            <section className="param-group">
              <div className="param-group-head">
                <span className="param-index">03</span>
                <div>
                  <h3>回放与检测控制参数</h3>
                  <p>控制回放速度、校验模式、抓取等待时间和 Suricata 就绪超时。</p>
                </div>
              </div>
              <div className="field-grid two-col">
                <label>
                  <span>Suricata 校验模式</span>
                  <input value={form.suricata_checksum_mode} onChange={(e) => updateForm("suricata_checksum_mode", e.target.value)} />
                </label>
                <label>
                  <span>Replay 速度</span>
                  <input value={form.replay_speed} onChange={(e) => updateForm("replay_speed", e.target.value)} />
                </label>
                <label>
                  <span>抓取等待</span>
                  <input type="number" value={form.capture_wait_sec} onChange={(e) => updateForm("capture_wait_sec", Number(e.target.value))} />
                </label>
                <label>
                  <span>就绪超时</span>
                  <input
                    type="number"
                    value={form.suricata_ready_timeout_sec}
                    onChange={(e) => updateForm("suricata_ready_timeout_sec", Number(e.target.value))}
                  />
                </label>
              </div>
              <label>
                <span>附加 tcpreplay 参数</span>
                <input value={form.tcpreplay_extra_args} onChange={(e) => updateForm("tcpreplay_extra_args", e.target.value)} placeholder="如 --loop=2 --pps=1000" />
              </label>
            </section>

            <section className="param-group">
              <div className="param-group-head">
                <span className="param-index">04</span>
                <div>
                  <h3>聚合与筛选参数</h3>
                  <p>配置时间窗聚合强度与候选样本数量，控制进入 LLM 的窗口集合。</p>
                </div>
              </div>
              <div className="field-grid three-col">
                <label>
                  <span>窗口秒数</span>
                  <input type="number" value={form.window_sec} onChange={(e) => updateForm("window_sec", Number(e.target.value))} />
                </label>
                <label>
                  <span>最小 hits</span>
                  <input type="number" value={form.min_hits} onChange={(e) => updateForm("min_hits", Number(e.target.value))} />
                </label>
                <label>
                  <span>Top K</span>
                  <input type="number" value={form.topk} onChange={(e) => updateForm("topk", Number(e.target.value))} />
                </label>
              </div>
            </section>
          </>
        )}

        {channel === "csv" && (
          <>
            <section className="param-group">
              <div className="param-group-head">
                <span className="param-index">02</span>
                <div>
                  <h3>结构化数据输入</h3>
                  <p>指定 CSV 数据集路径，直接以结构化流记录作为实验输入。</p>
                </div>
              </div>
              <label>
                <span>CSV 路径</span>
                <input value={form.csv} onChange={(e) => updateForm("csv", e.target.value)} />
              </label>
            </section>

            <section className="param-group">
              <div className="param-group-head">
                <span className="param-index">03</span>
                <div>
                  <h3>采样与筛选参数</h3>
                  <p>控制结构化流量的采样规模、标签覆盖方式与随机性，便于做批量实验对比。</p>
                </div>
              </div>
              <div className="field-grid three-col">
                <label>
                  <span>Top K</span>
                  <input type="number" value={form.topk} onChange={(e) => updateForm("topk", Number(e.target.value))} />
                </label>
                <label>
                  <span>采样模式</span>
                  <select value={form.selection_mode} onChange={(e) => updateForm("selection_mode", e.target.value)}>
                    <option value="stratified_label">按标签分层采样</option>
                    <option value="priority">按优先级采样</option>
                    <option value="random">随机采样</option>
                  </select>
                </label>
                <label>
                  <span>随机种子</span>
                  <input type="number" value={form.seed} onChange={(e) => updateForm("seed", Number(e.target.value))} />
                </label>
              </div>
              <label className="checkbox-line">
                <input type="checkbox" checked={form.exclude_benign} onChange={(e) => updateForm("exclude_benign", e.target.checked)} />
                <span>排除 benign</span>
              </label>
            </section>
          </>
        )}
      </div>

      <div className="run-status-box">
        <div className="section-head compact-head">
          <div>
            <p className="section-kicker">Run Status</p>
            <h3>任务执行状态</h3>
          </div>
        </div>
        {latestRun ? (
          <>
            <div className="run-metrics">
              <div>
                <span>状态</span>
                <strong>{latestRun.status}</strong>
              </div>
              <div>
                <span>Job ID</span>
                <strong>{latestRun.job_id}</strong>
              </div>
            </div>
            <div className="code-box">{(latestRun.command || []).join(" ")}</div>
          </>
        ) : (
          <div className="empty-state compact">尚未启动任务。</div>
        )}
      </div>
    </section>
  );
}

function JobHistory({ jobs, selectedJobId, onSelect, onRefresh, title, note }) {
  return (
    <section className="card jobs-card">
      <div className="section-head">
        <div>
          <p className="section-kicker">Experiment Records</p>
          <h2>{title}</h2>
        </div>
        <button className="ghost-btn" onClick={onRefresh}>
          刷新
        </button>
      </div>
      <div className="panel-note">{note}</div>
      <div className="job-list">
        {jobs.length ? (
          jobs.map((job) => (
            <button key={job.job_id} className={`job-item ${selectedJobId === job.job_id ? "active" : ""}`} onClick={() => onSelect(job.job_id)}>
              <div>
                <div className="badge-row">
                  <span className="badge">{job.channel || "unknown"}</span>
                  <span className="badge subtle">{job.has_evaluation ? "evaluated" : "pending"}</span>
                </div>
                <strong>{job.job_id}</strong>
                <p>{job.source_path || "暂无 source_path"}</p>
              </div>
              <div className="job-item-metrics">
                <span>决策 {formatNumber(job.decision_count)}</span>
                <span>重复 {formatRatio(job.repeat_enforcement_ratio)}</span>
                <span>短路 {formatNumber(job.skipped_execution_count)}</span>
              </div>
            </button>
          ))
        ) : (
          <div className="empty-state compact">暂无历史实验记录。</div>
        )}
      </div>
    </section>
  );
}

function DecisionTimeline({ title, note, items }) {
  const summary = {
    total: items.length,
    block: items.filter((item) => item.action === "block").length,
    escalated: items.filter((item) => item.decision_state === "escalated_block").length,
    covered: items.filter((item) => item.decision_state === "covered_by_existing_block").length,
  };
  return (
    <section className="card timeline-card">
      <div className="section-head">
        <div>
          <p className="section-kicker">LLM Decisions</p>
          <h2>{title}</h2>
        </div>
      </div>
      <div className="panel-note">{note}</div>
      <div className="timeline-summary">
        <div><span>决策条数</span><strong>{formatNumber(summary.total)}</strong></div>
        <div><span>Block 动作</span><strong>{formatNumber(summary.block)}</strong></div>
        <div><span>升级处罚</span><strong>{formatNumber(summary.escalated)}</strong></div>
        <div><span>已有策略覆盖</span><strong>{formatNumber(summary.covered)}</strong></div>
      </div>
      <div className="timeline-list">
        {items.length ? (
          items.map((item) => (
            <article className="timeline-item" key={`${item.index}-${item.target_ip}-${item.ttl_sec}`}>
              <div className="timeline-dot" />
              <div className="timeline-body">
                <div className="timeline-head">
                  <strong>#{formatNumber(item.index)} · {item.action} · {item.target_ip}</strong>
                  <span className={`state-pill ${item.decision_state ? "" : "muted"}`}>{item.decision_state || "不适用"}</span>
                </div>
                <div className="timeline-tags">
                  <span>{item.execution_mode || "无执行模式"}</span>
                  <span>TTL {formatNumber(item.ttl_sec)}</span>
                  <span className={!item.ttl_reason ? "muted" : ""}>{item.ttl_reason || "无 TTL 原因"}</span>
                </div>
                <p>{item.reason || "暂无原因说明"}</p>
              </div>
            </article>
          ))
        ) : (
          <div className="empty-state compact">暂无 LLM 决策结果。</div>
        )}
      </div>
    </section>
  );
}

function ExecutionTimeline({ title, note, items }) {
  const summary = {
    total: items.length,
    ok: items.filter((item) => item.tool_ok).length,
    skipped: items.filter((item) => item.skipped_execution).length,
    alreadyPresent: items.filter((item) => item.already_present).length,
  };
  return (
    <section className="card timeline-card execution-card">
      <div className="section-head">
        <div>
          <p className="section-kicker">NFT Execution</p>
          <h2>{title}</h2>
        </div>
      </div>
      <div className="panel-note">{note}</div>
      <div className="timeline-summary execution-summary">
        <div><span>执行条数</span><strong>{formatNumber(summary.total)}</strong></div>
        <div><span>执行成功</span><strong>{formatNumber(summary.ok)}</strong></div>
        <div><span>短路跳过</span><strong>{formatNumber(summary.skipped)}</strong></div>
        <div><span>already_present</span><strong>{formatNumber(summary.alreadyPresent)}</strong></div>
      </div>
      <div className="timeline-list">
        {items.length ? (
          items.map((item) => (
            <article className="timeline-item" key={`${item.index}-${item.target_ip}-exec`}>
              <div className={`timeline-dot ${item.tool_ok ? "ok" : "warn"}`} />
              <div className="timeline-body">
                <div className="timeline-head">
                  <strong>#{formatNumber(item.index)} · {item.target_ip}</strong>
                  <span className={`state-pill ${item.tool_ok ? "ok" : "pending"}`}>{item.tool_ok ? "tool ok" : "未执行/等待"}</span>
                </div>
                <div className="timeline-tags">
                  <span>{item.execution_mode || "无执行模式"}</span>
                  <span>TTL {formatNumber(item.ttl_sec)}</span>
                  {item.skipped_execution ? <span className="warn">skipped</span> : null}
                  {item.covered_by_existing_action ? <span className="warn">covered</span> : null}
                  {item.already_present ? <span className="risk">already_present</span> : null}
                </div>
                <p>执行模式：{item.execution_mode || "-"}。该记录用于刻画 nft 执行层是否真正落表，以及是否被已有动作覆盖。</p>
              </div>
            </article>
          ))
        ) : (
          <div className="empty-state compact">暂无执行结果。</div>
        )}
      </div>
    </section>
  );
}

function NftStatusPanel({ data, error, onRefresh }) {
  const sets = data?.sets || {};
  const cards = [
    ["阻断集合", sets.block, "blocklist_v4"],
    ["限速集合", sets.rate_limit, "ratelimit_v4"],
    ["观察集合", sets.watch, "watchlist_v4"],
  ];

  return (
    <section className="card nft-card">
      <div className="section-head">
        <div>
          <p className="section-kicker">NFT Runtime</p>
          <h2>nft 实时状态</h2>
        </div>
        <button className="ghost-btn" onClick={onRefresh}>
          刷新
        </button>
      </div>
      <div className="panel-note">
        实时读取当前系统中的 nft set 状态，用于确认 block、rate-limit 与 watch 三类动作是否已经真实落表。
      </div>
      <div className="nft-meta-row">
        <span>更新时间</span>
        <strong>{formatDateTime(data?.updated_at)}</strong>
      </div>
      {error ? <div className="risk-card">{error}</div> : null}
      <div className="nft-grid">
        {cards.map(([title, item, fallbackName]) => (
          <article className="nft-set-card" key={title}>
            <div className="badge-row">
              <span className="badge">{title}</span>
              <span className="badge subtle">{item?.set_name || fallbackName}</span>
            </div>
            <div className="nft-count">{formatNumber(item?.count || 0)}</div>
            <div className="nft-subtitle">
              {!data ? "等待状态数据" : item?.ok === false ? "读取失败" : "当前成员数"}
            </div>
            {!data ? (
              <div className="empty-state compact">正在读取 nft 实时状态</div>
            ) : item?.ok === false ? (
              <div className="risk-card">{item.error || "读取 nft set 失败"}</div>
            ) : item?.members?.length ? (
              <div className="nft-member-list">
                {item.members.slice(0, 8).map((member, index) => (
                  <div className="nft-member-card" key={`${member.value}-${index}`}>
                    <div className="nft-member-ip">
                      <span className="legend-dot" />
                      <strong>{member.value || "-"}</strong>
                    </div>
                    <div className="nft-member-meta">TTL：{formatDurationSeconds(member.timeout)}</div>
                    <div className="nft-member-meta">剩余时间：{formatDurationSeconds(member.expires)}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state compact">当前无成员</div>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

function FinalSummary({ meta, job }) {
  const evaluation = job?.evaluation || {};
  const executionEval = evaluation.execution_eval || {};
  const strongMetrics = getStrongMetrics(evaluation);
  const strategyEval = evaluation.strategy_eval || {};
  const safetyEval = evaluation.safety_eval || {};
  const datasetSummary = evaluation.dataset_summary || {};
  const distributions = job?.distributions || {};

  const cards = [
    ["决策总量", job?.decision_count],
    ["样本规模", datasetSummary.selected_rows],
    ["策略匹配率", formatRatio(strategyEval.strategy_match_rate)],
    ["重复执行比", formatRatio(executionEval.repeat_enforcement_ratio)],
    ["短路次数", executionEval.skipped_execution_count],
    ["强处置 Precision", formatDecimal(strongMetrics.precision)],
    ["强处置 Recall", formatDecimal(strongMetrics.recall)],
    ["强处置 F1", formatDecimal(strongMetrics.f1)],
    ["唯一阻断 IP", executionEval.unique_blocked_ip_count],
    ["安全预检次数", safetyEval.precheck_intervention_count],
  ];

  return (
    <section className="card summary-panel">
      <div className="section-head">
        <div>
          <p className="section-kicker">Final Results</p>
          <h2>{meta.finalTitle}</h2>
        </div>
      </div>
      <div className="panel-note">{meta.finalNote}</div>
      {job ? (
        <>
          <div className="headline-grid">
            <div className="headline-main">
              <div className="badge-row">
                <span className="badge">{job.channel}</span>
                <span className="badge subtle">{job.job_id}</span>
              </div>
              <h3>{job.source_path || "暂无 source_path"}</h3>
              <p>{meta.finalNote}</p>
            </div>
            <div className="headline-side">
              <div><span>Channel</span><strong>{job.channel || "-"}</strong></div>
              <div><span>Job</span><strong>{job.job_id || "-"}</strong></div>
            </div>
          </div>
          <div className="summary-grid">
            {cards.map(([label, value]) => (
              <article className="summary-card" key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </article>
            ))}
          </div>
          <div className="chart-grid">
            <DoughnutCard title="动作分布" data={distributions.action} />
            <DoughnutCard title="执行模式" data={distributions.execution_mode} />
            <DoughnutCard title="决策状态" data={distributions.decision_state} />
            <DoughnutCard title="TTL 原因" data={distributions.ttl_reason} />
          </div>
        </>
      ) : (
        <div className="empty-state">请选择一个实验结果。</div>
      )}
    </section>
  );
}

function EvaluationPanel({ meta, job, onEvaluate }) {
  const evaluation = job?.evaluation || {};
  const datasetSummary = evaluation.dataset_summary || {};
  const decisionEval = evaluation.decision_eval || {};
  const riskMetrics = getRiskMetrics(evaluation);
  const strongMetrics = getStrongMetrics(evaluation);
  const strategyEval = evaluation.strategy_eval || {};
  const executionEval = evaluation.execution_eval || {};
  const effectEval = evaluation.effect_eval || {};
  const safetyEval = evaluation.safety_eval || {};

  const riskCases = [
    ...(evaluation.error_analysis?.false_positive_cases || []),
    ...(evaluation.error_analysis?.false_negative_cases || []),
    ...(evaluation.error_analysis?.review_cases || []),
    ...(evaluation.error_analysis?.strategy_mismatch_cases || []),
    ...(evaluation.error_analysis?.constraint_violation_cases || []),
    ...(executionEval.tool_failed_cases || []),
  ].slice(0, 5);

  return (
    <section className="card evaluation-card">
      <div className="section-head">
        <div>
          <p className="section-kicker">Evaluation Results</p>
          <h2>{meta.evalTitle}</h2>
        </div>
        <button className="ghost-btn" onClick={onEvaluate} disabled={!job}>
          重新评估
        </button>
      </div>
      <div className="panel-note">{meta.evalNote}</div>
      {job ? (
        <div className="evaluation-stack">
          <section className="evaluation-block">
            <h3>数据覆盖</h3>
            <div className="metric-mini-grid">
              <div><span>输入行数</span><strong>{formatNumber(datasetSummary.input_rows)}</strong></div>
              <div><span>采样行数</span><strong>{formatNumber(datasetSummary.selected_rows)}</strong></div>
              <div><span>唯一源 IP</span><strong>{formatNumber(datasetSummary.unique_src_ip_count)}</strong></div>
              <div><span>唯一 Flow UID</span><strong>{formatNumber(datasetSummary.unique_flow_uid_count)}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>决策有效性</h3>
            <div className="metric-mini-grid">
              <div><span>决策总量</span><strong>{formatNumber(decisionEval.decision_count || job?.decision_count)}</strong></div>
              <div><span>风险识别 Precision</span><strong>{formatDecimal(riskMetrics.precision)}</strong></div>
              <div><span>风险识别 Recall</span><strong>{formatDecimal(riskMetrics.recall)}</strong></div>
              <div><span>风险识别 F1</span><strong>{formatDecimal(riskMetrics.f1)}</strong></div>
              <div><span>强处置 Precision</span><strong>{formatDecimal(strongMetrics.precision)}</strong></div>
              <div><span>强处置 Recall</span><strong>{formatDecimal(strongMetrics.recall)}</strong></div>
              <div><span>强处置 F1</span><strong>{formatDecimal(strongMetrics.f1)}</strong></div>
              <div><span>匹配决策数</span><strong>{formatNumber(firstDefined(strongMetrics.matched_decisions, decisionEval.csv_metrics?.matched_decisions))}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>策略智能性</h3>
            <div className="metric-mini-grid">
              <div><span>策略匹配率</span><strong>{formatRatio(strategyEval.strategy_match_rate)}</strong></div>
              <div><span>动作匹配率</span><strong>{formatRatio(strategyEval.action_match_rate)}</strong></div>
              <div><span>执行模式匹配率</span><strong>{formatRatio(strategyEval.execution_mode_match_rate)}</strong></div>
              <div><span>过度处置率</span><strong>{formatRatio(strategyEval.over_mitigation_rate)}</strong></div>
              <div><span>处置不足率</span><strong>{formatRatio(strategyEval.under_mitigation_rate)}</strong></div>
              <div><span>TTL 自适应分</span><strong>{formatDecimal(strategyEval.ttl_adaptation_score)}</strong></div>
              <div><span>升级一致性</span><strong>{formatRatio(strategyEval.escalation_consistency)}</strong></div>
              <div><span>策略评估样本</span><strong>{formatNumber(strategyEval.evaluated_decisions)}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>执行有效性</h3>
            <div className="metric-mini-grid">
              <div><span>成功执行</span><strong>{formatNumber(executionEval.tool_success_count)}</strong></div>
              <div><span>失败执行</span><strong>{formatNumber(executionEval.tool_failure_count)}</strong></div>
              <div><span>新增执行</span><strong>{formatNumber(executionEval.new_enforcement_count)}</strong></div>
              <div><span>重复/短路执行</span><strong>{formatNumber(executionEval.repeat_enforcement_count)}</strong></div>
              <div><span>重复执行比</span><strong>{formatRatio(executionEval.repeat_enforcement_ratio)}</strong></div>
              <div><span>短路次数</span><strong>{formatNumber(executionEval.skipped_execution_count)}</strong></div>
              <div><span>已覆盖比例</span><strong>{formatRatio(executionEval.covered_by_existing_action_ratio)}</strong></div>
              <div><span>决策-执行一致性</span><strong>{formatRatio(executionEval.decision_to_execution_consistency)}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>安全可控性</h3>
            <div className="metric-mini-grid">
              <div><span>Protected 误封尝试</span><strong>{formatNumber(safetyEval.protected_ip_block_attempt_count)}</strong></div>
              <div><span>Protected 安全处置</span><strong>{formatNumber(safetyEval.protected_ip_safe_handling_count)}</strong></div>
              <div><span>Noise-only 误阻断</span><strong>{formatNumber(safetyEval.noise_only_false_block_count)}</strong></div>
              <div><span>高噪声过激处置</span><strong>{formatNumber(safetyEval.high_noise_overreaction_count)}</strong></div>
              <div><span>Fallback 次数</span><strong>{formatNumber(safetyEval.fallback_trigger_count)}</strong></div>
              <div><span>约束违规数</span><strong>{formatNumber(safetyEval.constraint_violation_count)}</strong></div>
              <div><span>预检干预数</span><strong>{formatNumber(safetyEval.precheck_intervention_count)}</strong></div>
              <div><span>唯一阻断 IP</span><strong>{formatNumber(executionEval.unique_blocked_ip_count)}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>收益观察</h3>
            <div className="metric-mini-grid">
              <div><span>指标语义</span><strong>{effectEval.metric_semantics === "proxy" ? "代理指标" : "-"}</strong></div>
              <div><span>代理指标名</span><strong>{effectEval.proxy_metric_name || "-"}</strong></div>
              <div><span>评估决策数</span><strong>{formatNumber(effectEval.evaluated_decisions)}</strong></div>
              <div><span>平均压制率</span><strong>{formatRatio(effectEval.mean_suppression_ratio)}</strong></div>
            </div>
            {effectEval.reason ? <div className="empty-state compact">{effectEval.reason}</div> : null}
            {!effectEval.reason && effectEval.metric_semantics === "proxy" ? (
              <div className="empty-state compact">该数值表示后续窗口风险下降的代理指标，不作为严格因果阻断收益结论。</div>
            ) : null}
          </section>
          <section className="evaluation-block">
            <h3>分布概览</h3>
            <div className="chart-grid">
              <DoughnutCard title="动作分布" data={job?.distributions?.action} />
              <DoughnutCard title="执行模式" data={job?.distributions?.execution_mode} />
              <DoughnutCard title="决策状态" data={job?.distributions?.decision_state} />
              <DoughnutCard title="TTL 原因" data={job?.distributions?.ttl_reason} />
            </div>
          </section>
          <section className="evaluation-block">
            <h3>关键风险样本</h3>
            <div className="risk-list">
              {riskCases.length ? (
                compactCaseList(riskCases).map((item, index) => (
                  <div className="risk-card" key={index}>{JSON.stringify(item)}</div>
                ))
              ) : (
                <div className="empty-state compact">当前 job 未发现高优先级异常样本。</div>
              )}
            </div>
          </section>
        </div>
      ) : (
        <div className="empty-state">暂无评估结果。</div>
      )}
    </section>
  );
}

function ReplayComparisonPanel({ form, updateForm, onCompare, loading, error, report }) {
  const compatibility = report?.compatibility || {};
  const matching = report?.matching || {};
  const summaryDelta = report?.summary_delta || {};
  const pairOutcomes = report?.pair_outcomes || {};
  const executionImpact = report?.execution_impact || {};
  const suppression = report?.suppression_comparison || {};
  const alertVolume = report?.alert_volume_comparison || {};
  const samples = report?.samples || {};

  return (
    <section className="card evaluation-card">
      <div className="section-head">
        <div>
          <p className="section-kicker">Replay Comparison</p>
          <h2>执行 / 无执行 对照评估</h2>
        </div>
        <button className="primary-btn" onClick={onCompare} disabled={loading}>
          {loading ? "评估中..." : "开始对照评估"}
        </button>
      </div>
      <div className="panel-note">独立比较两组已完成的在线回放实验结果，一组为真实执行阻断，另一组为 DRY_RUN 无执行基线。</div>
      <div className="form-block">
        <div className="field-grid two-col">
          <label>
            <span>执行组结果路径</span>
            <input value={form.exec_job_dir} onChange={(e) => updateForm("exec_job_dir", e.target.value)} placeholder="/path/to/exec_job_dir" />
          </label>
          <label>
            <span>无执行对照组路径</span>
            <input value={form.baseline_job_dir} onChange={(e) => updateForm("baseline_job_dir", e.target.value)} placeholder="/path/to/baseline_job_dir" />
          </label>
        </div>
      </div>
      {error ? <div className="risk-card">{error}</div> : null}
      {report ? (
        <div className="evaluation-stack">
          {!compatibility.compatible ? (
            <div className="risk-card">兼容性检查未完全通过：{(compatibility.differences || []).join("；") || "存在配置差异"}</div>
          ) : null}
          <section className="evaluation-block">
            <h3>对照概览</h3>
            <div className="metric-mini-grid">
              <div><span>执行组 Job</span><strong>{report?.exec_job?.job_id || "-"}</strong></div>
              <div><span>对照组 Job</span><strong>{report?.baseline_job?.job_id || "-"}</strong></div>
              <div><span>匹配决策数</span><strong>{formatNumber(matching.matched_pairs)}</strong></div>
              <div><span>执行组匹配率</span><strong>{formatRatio(matching.match_rate_exec)}</strong></div>
              <div><span>对照组匹配率</span><strong>{formatRatio(matching.match_rate_baseline)}</strong></div>
              <div><span>兼容性</span><strong>{compatibility.compatible ? "通过" : "存在差异"}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>核心差值</h3>
            <div className="metric-mini-grid">
              <div><span>平均压制率差值</span><strong>{formatRatio(suppression.delta_mean_suppression_ratio)}</strong></div>
              <div><span>过滤告警差值</span><strong>{formatNumber(alertVolume.delta_filtered_alerts)}</strong></div>
              <div><span>过滤告警变化率</span><strong>{formatRatio(alertVolume.delta_filtered_alert_ratio)}</strong></div>
              <div><span>工具成功数差值</span><strong>{formatNumber(summaryDelta.tool_success_count_delta)}</strong></div>
              <div><span>新增执行差值</span><strong>{formatNumber(summaryDelta.new_enforcement_count_delta)}</strong></div>
              <div><span>唯一阻断 IP 差值</span><strong>{formatNumber(summaryDelta.unique_blocked_ip_count_delta)}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>动作与执行对比</h3>
            <div className="metric-mini-grid">
              <div><span>同动作同模式</span><strong>{formatNumber(pairOutcomes.same_action_same_mode)}</strong></div>
              <div><span>同动作异模式</span><strong>{formatNumber(pairOutcomes.same_action_different_mode)}</strong></div>
              <div><span>不同动作</span><strong>{formatNumber(pairOutcomes.different_action)}</strong></div>
              <div><span>执行组更强</span><strong>{formatNumber(pairOutcomes.exec_stronger_than_baseline)}</strong></div>
              <div><span>对照组更强</span><strong>{formatNumber(pairOutcomes.baseline_stronger_than_exec)}</strong></div>
              <div><span>仅执行层差异对</span><strong>{formatNumber(executionImpact.pairs_with_execution_only_effect)}</strong></div>
            </div>
          </section>
          <section className="evaluation-block">
            <h3>典型样本</h3>
            <div className="risk-list">
              {(samples.different_action_cases || []).slice(0, 5).map((item, index) => (
                <div className="risk-card" key={`diff-${index}`}>{JSON.stringify(item)}</div>
              ))}
              {(samples.suppression_improvement_cases || []).slice(0, 5).map((item, index) => (
                <div className="risk-card" key={`supp-${index}`}>{JSON.stringify(item)}</div>
              ))}
              {!((samples.different_action_cases || []).length || (samples.suppression_improvement_cases || []).length) ? (
                <div className="empty-state compact">暂无可展示样本。</div>
              ) : null}
            </div>
          </section>
        </div>
      ) : (
        <div className="empty-state">请输入两组 replay 结果路径后开始评估。</div>
      )}
    </section>
  );
}

function ChannelPage({
  channel,
  onBack,
  onSwitchChannel,
  jobs,
  selectedJobId,
  selectedJob,
  form,
  updateForm,
  onRun,
  onRefreshJobs,
  onSelectJob,
  latestRun,
  onEvaluate,
  nftStatus,
  nftStatusError,
  onRefreshNft,
  replayComparisonForm,
  onUpdateReplayComparisonForm,
  onCompareReplay,
  replayComparisonLoading,
  replayComparisonError,
  replayComparisonReport,
}) {
  const meta = channelMeta[channel];
  const visibleJob = jobMatchesChannel(selectedJob, channel) ? selectedJob : null;
  const timeline = visibleJob?.timeline || [];
  const channelJobs = jobs.filter((job) => job.channel === channelJobName(channel));
  const channelRun = latestRun && latestRun.channel === channel ? latestRun : null;

  return (
    <div className="channel-page">
      <header className="hero hero-channel">
        <div className="hero-grid" />
        <div className="hero-content">
          <div className="channel-hero-layout">
            <div className="channel-hero-copy">
              <h1>{meta.title}</h1>
              <p className="hero-copy">{meta.description}</p>
            </div>
            <div className="channel-nav-panel">
              <button className="back-btn nav-btn" onClick={onBack}>主页面</button>
              {Object.values(channelMeta).map((item) => (
                <button
                  key={item.key}
                  className={`channel-tab-btn nav-btn ${item.key === channel ? "active" : ""}`}
                  onClick={() => onSwitchChannel(item.key)}
                >
                  {item.title}
                </button>
              ))}
            </div>
          </div>
        </div>
      </header>

      <main className="channel-layout">
        <div className="channel-sidebar">
          <RunPanel channel={channel} meta={meta} form={form} updateForm={updateForm} onRun={onRun} latestRun={channelRun} />
        </div>

        <div className="channel-content">
          <JobHistory
            jobs={channelJobs}
            selectedJobId={visibleJob ? selectedJobId : ""}
            onSelect={onSelectJob}
            onRefresh={onRefreshJobs}
            title={meta.historyTitle}
            note="选择某个实验记录后，本页面会同步切换到对应的决策流、执行流、实验结果和评估摘要。"
          />
          <DecisionTimeline title={meta.decisionTitle} note={meta.decisionNote} items={timeline} />
          <ExecutionTimeline title={meta.executionTitle} note={meta.executionNote} items={timeline} />
          <NftStatusPanel data={nftStatus} error={nftStatusError} onRefresh={onRefreshNft} />
          <FinalSummary meta={meta} job={visibleJob} />
          <EvaluationPanel meta={meta} job={visibleJob} onEvaluate={onEvaluate} />
          {channel === "replay" ? (
            <ReplayComparisonPanel
              form={replayComparisonForm}
              updateForm={onUpdateReplayComparisonForm}
              onCompare={onCompareReplay}
              loading={replayComparisonLoading}
              error={replayComparisonError}
              report={replayComparisonReport}
            />
          ) : null}
        </div>
      </main>
    </div>
  );
}

function App() {
  const [page, setPage] = useState("home");
  const [forms, setForms] = useState(defaultForms);
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState("");
  const [selectedJob, setSelectedJob] = useState(null);
  const [latestRunId, setLatestRunId] = useState("");
  const [latestRun, setLatestRun] = useState(null);
  const [nftStatus, setNftStatus] = useState(null);
  const [nftStatusError, setNftStatusError] = useState("");
  const [replayComparisonForm, setReplayComparisonForm] = useState(defaultReplayComparisonForm);
  const [replayComparisonLoading, setReplayComparisonLoading] = useState(false);
  const [replayComparisonError, setReplayComparisonError] = useState("");
  const [replayComparisonReport, setReplayComparisonReport] = useState(null);
  const [loading, setLoading] = useState(true);

  async function api(path, options) {
    const response = await fetch(`${API_BASE}${path}`, options);
    const payload = await response.json();
    if (!response.ok) {
      const error = new Error(payload.detail || payload.error || `Request failed: ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  async function loadConfig() {
    const payload = await api("/config");
    setForms((prev) => ({
      ...prev,
      csv: { ...prev.csv, csv: payload.defaults.csv || prev.csv.csv },
    }));
  }

  async function loadNftStatus() {
    try {
      const payload = await api("/nft/status");
      setNftStatus(payload);
      setNftStatusError("");
    } catch (error) {
      setNftStatus(null);
      setNftStatusError(error.message || "读取 nft 实时状态失败");
    }
  }

  async function loadJobs(targetJobId = "") {
    const payload = await api("/jobs?limit=30");
    const items = payload.items || [];
    setJobs(items);
    const preferredJobId =
      (targetJobId && items.some((item) => item.job_id === targetJobId) && targetJobId) ||
      (selectedJobId && items.some((item) => item.job_id === selectedJobId) && selectedJobId) ||
      items[0]?.job_id ||
      "";
    const nextJobId = preferredJobId;
    if (nextJobId) {
      await loadJob(nextJobId);
    }
  }

  async function loadJob(jobId) {
    try {
      const payload = await api(`/jobs/${encodeURIComponent(jobId)}`);
      setSelectedJobId(jobId);
      setSelectedJob(payload);
    } catch (error) {
      if (error.status === 404) {
        return;
      }
      throw error;
    }
  }

  async function loadRun(runId, options = {}) {
    if (!runId) return;
    const { syncSelection = false } = options;
    const payload = await api(`/runs/${encodeURIComponent(runId)}`);
    setLatestRun(payload);
    if (syncSelection && payload.job_snapshot) {
      setSelectedJobId(payload.job_snapshot.job_id);
      setSelectedJob(payload.job_snapshot);
    }
  }

  useEffect(() => {
    async function bootstrap() {
      try {
        await loadConfig();
        await loadNftStatus();
        await loadJobs();
      } finally {
        setLoading(false);
      }
    }
    bootstrap();
  }, []);

  useEffect(() => {
    if (!latestRunId) return;
    const timer = window.setInterval(() => {
      loadRun(latestRunId, { syncSelection: false }).catch(console.error);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [latestRunId]);

  useEffect(() => {
    if (page === "home") return;
    loadNftStatus().catch(console.error);
    const timer = window.setInterval(() => {
      loadNftStatus().catch(console.error);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [page]);

  useEffect(() => {
    if (page === "home") return;
    if (jobMatchesChannel(selectedJob, page)) return;
    const channelJobs = jobs.filter((job) => job.channel === channelJobName(page));
    const nextJobId = channelJobs[0]?.job_id || "";
    if (nextJobId) {
      loadJob(nextJobId).catch(console.error);
      return;
    }
    setSelectedJobId("");
    setSelectedJob(null);
  }, [page, jobs, selectedJob]);

  const activeChannel = useMemo(() => (page === "home" ? null : page), [page]);

  function updateForm(field, value) {
    if (!activeChannel) return;
    setForms((prev) => ({
      ...prev,
      [activeChannel]: {
        ...prev[activeChannel],
        [field]: value,
      },
    }));
  }

  function updateReplayComparisonForm(field, value) {
    setReplayComparisonForm((prev) => ({
      ...prev,
      [field]: value,
    }));
  }

  async function startRun() {
    if (!activeChannel) return;
    const current = forms[activeChannel];
    const payload = {
      ...current,
      channel: activeChannel,
      tcpreplay_extra_args:
        activeChannel === "replay"
          ? String(current.tcpreplay_extra_args || "")
              .split(/\s+/)
              .map((item) => item.trim())
              .filter(Boolean)
          : [],
    };
    const result = await api("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setLatestRunId(result.run_id);
    await loadRun(result.run_id, { syncSelection: true });
    await loadJobs();
  }

  async function rerunEvaluation() {
    if (!selectedJobId) return;
    const payload = await api(`/jobs/${encodeURIComponent(selectedJobId)}/evaluate`, { method: "POST" });
    setSelectedJob(payload.job);
    await loadJobs(selectedJobId);
  }

  async function compareReplay() {
    setReplayComparisonLoading(true);
    setReplayComparisonError("");
    try {
      const payload = await api("/replay/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(replayComparisonForm),
      });
      setReplayComparisonReport(payload.report || null);
    } catch (error) {
      setReplayComparisonReport(null);
      setReplayComparisonError(error.message || "对照评估失败");
    } finally {
      setReplayComparisonLoading(false);
    }
  }

  return (
    <div className="app-shell">
      {page === "home" ? (
        <HomePage onEnter={setPage} />
      ) : (
        <ChannelPage
          channel={page}
          onBack={() => setPage("home")}
          onSwitchChannel={setPage}
          jobs={jobs}
          selectedJobId={selectedJobId}
          selectedJob={selectedJob}
          form={forms[page]}
          updateForm={updateForm}
          onRun={startRun}
          onRefreshJobs={() => loadJobs()}
          onSelectJob={loadJob}
          latestRun={latestRun}
          onEvaluate={rerunEvaluation}
          nftStatus={nftStatus}
          nftStatusError={nftStatusError}
          onRefreshNft={loadNftStatus}
          replayComparisonForm={replayComparisonForm}
          onUpdateReplayComparisonForm={updateReplayComparisonForm}
          onCompareReplay={compareReplay}
          replayComparisonLoading={replayComparisonLoading}
          replayComparisonError={replayComparisonError}
          replayComparisonReport={replayComparisonReport}
        />
      )}
      {loading ? <div className="loading-mask">Loading…</div> : null}
    </div>
  );
}

export default App;
