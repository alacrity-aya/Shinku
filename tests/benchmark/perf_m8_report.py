#!/usr/bin/env python3
"""Render a self-contained PERF-M8-1 HTML report from summary.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


SCENARIO_ORDER = (
    "native-off-shinku-off",
    "native-off-shinku-on",
    "native-on-shinku-off",
    "native-on-shinku-on",
)


def resolve_summary_path(value: Path) -> Path:
    path = value.expanduser().resolve()
    if path.is_dir():
        path = path / "summary.json"
    if not path.is_file():
        raise ValueError(f"summary file does not exist: {path}")
    return path


def build_report_data(summary: dict[str, Any], source: Path) -> dict[str, Any]:
    groups = summary.get("groups")
    if not isinstance(groups, dict) or not groups:
        raise ValueError("summary.json has no benchmark groups")

    compact_groups: list[dict[str, Any]] = []
    for group_name, metrics in groups.items():
        parts = group_name.split("/", 2)
        if len(parts) != 3 or not isinstance(metrics, dict):
            raise ValueError(f"invalid benchmark group: {group_name}")
        workload, phase, scenario = parts
        compact_groups.append(
            {
                "name": group_name,
                "workload": workload,
                "phase": phase,
                "scenario": scenario,
                "metrics": {key: value for key, value in metrics.items() if key != "merged_histogram"},
            }
        )

    scenario_rank = {name: index for index, name in enumerate(SCENARIO_ORDER)}
    compact_groups.sort(
        key=lambda item: (
            item["workload"],
            item["phase"],
            scenario_rank.get(item["scenario"], len(scenario_rank)),
            item["scenario"],
        )
    )
    return {
        "source": str(source),
        "run_name": source.parent.name,
        "complete": bool(summary.get("complete")),
        "canonical_eligible": bool(summary.get("canonical_eligible")),
        "round_count": summary.get("round_count", 0),
        "tc_modes": summary.get("tc_modes", []),
        "common_load_qps": summary.get("common_load_qps", {}),
        "common_driver_scenarios": summary.get("common_driver_scenarios", {}),
        "capacity_unstable": summary.get("capacity_unstable", {}),
        "calibrations": summary.get("calibrations", {}),
        "groups": compact_groups,
    }


def render_html(report_data: dict[str, Any]) -> str:
    serialized = json.dumps(report_data, ensure_ascii=True, separators=(",", ":")).replace("</", "<\\/")
    return _HTML_TEMPLATE.replace("__REPORT_DATA__", serialized)


def write_report(summary_path: Path, output_path: Path | None = None) -> Path:
    source = resolve_summary_path(summary_path)
    try:
        summary = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {source}: {error}") from error
    if not isinstance(summary, dict):
        raise ValueError("summary.json root must be an object")

    destination = output_path.expanduser().resolve() if output_path else source.with_name("report.html")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(build_report_data(summary, source)), encoding="utf-8")
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a self-contained PERF-M8-1 HTML report.")
    parser.add_argument("summary", type=Path, help="summary.json or its benchmark result directory")
    parser.add_argument("-o", "--output", type=Path, help="output path (default: report.html beside summary.json)")
    arguments = parser.parse_args(argv)
    try:
        destination = write_report(arguments.summary, arguments.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(destination)
    return 0


_HTML_TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>PERF-M8-1 Benchmark Report</title>
<style>
:root {
  color-scheme: light;
  --ink: #18211f;
  --muted: #61706c;
  --line: #d7dfdc;
  --surface: #ffffff;
  --canvas: #f3f6f4;
  --teal: #087f72;
  --coral: #d85b43;
  --gold: #c88a10;
  --blue: #3975b7;
  --good: #18794e;
  --warn: #a15c00;
  --bad: #b42318;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--canvas); color: var(--ink); font: 14px/1.45 Inter, ui-sans-serif, system-ui, sans-serif; }
button, select { font: inherit; }
.topband { background: #132824; color: #f7fbf9; border-bottom: 4px solid var(--teal); }
.wrap { width: min(1440px, calc(100% - 40px)); margin: 0 auto; }
.headline { min-height: 148px; display: flex; align-items: end; justify-content: space-between; gap: 24px; padding: 32px 0 28px; }
.eyebrow { color: #93c8be; font: 700 12px/1.2 ui-monospace, monospace; text-transform: uppercase; }
h1 { margin: 7px 0 0; font-size: 31px; line-height: 1.12; letter-spacing: 0; }
.source { max-width: 620px; color: #bad0ca; font: 12px/1.45 ui-monospace, monospace; overflow-wrap: anywhere; text-align: right; }
.statusline { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; margin-bottom: 12px; }
.badge { padding: 5px 9px; border: 1px solid #527069; border-radius: 4px; font-size: 12px; font-weight: 700; }
.badge.good { color: #92e4bd; border-color: #34775a; }
.badge.warn { color: #ffd592; border-color: #866331; }
.toolbar { background: var(--surface); border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 5; }
.toolbar-inner { min-height: 58px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
.tabs, .segments { display: inline-flex; gap: 2px; padding: 3px; background: #e9efec; border-radius: 6px; }
.tabs button, .segments button { border: 0; background: transparent; color: var(--muted); border-radius: 4px; padding: 7px 13px; cursor: pointer; font-weight: 650; }
.tabs button.active, .segments button.active { background: var(--surface); color: var(--ink); box-shadow: 0 1px 2px #15251f1f; }
.filters { display: flex; align-items: center; gap: 10px; }
main { padding: 26px 0 56px; }
.view[hidden] { display: none; }
.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 28px; }
.kpi { min-height: 106px; padding: 17px 18px; border: 1px solid var(--line); border-radius: 7px; background: var(--surface); }
.kpi .label { color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
.kpi .value { margin-top: 8px; font-size: 27px; line-height: 1.1; font-weight: 760; font-variant-numeric: tabular-nums; }
.kpi .detail { margin-top: 6px; color: var(--muted); font-size: 12px; }
.section-head { display: flex; align-items: end; justify-content: space-between; gap: 20px; margin: 0 0 12px; }
h2 { margin: 0; font-size: 20px; letter-spacing: 0; }
.context { color: var(--muted); font-size: 13px; }
.charts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.panel { min-width: 0; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; padding: 16px; }
.panel h3 { margin: 0; font-size: 14px; letter-spacing: 0; }
.panel-note { margin-top: 3px; color: var(--muted); font-size: 12px; }
.chart { height: 310px; margin-top: 10px; }
.chart svg { width: 100%; height: 100%; overflow: visible; }
.gridline { stroke: #dfe6e3; stroke-width: 1; }
.axislabel { fill: var(--muted); font-size: 11px; }
.barlabel { fill: var(--ink); font-size: 11px; font-weight: 650; }
.legend { display: flex; flex-wrap: wrap; gap: 12px; min-height: 22px; margin-top: 4px; color: var(--muted); font-size: 12px; }
.legend span::before { content: ''; display: inline-block; width: 9px; height: 9px; margin-right: 5px; border-radius: 2px; background: var(--swatch); }
.findings { margin-top: 14px; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.finding { padding: 14px 16px; border-left: 4px solid var(--teal); background: #e9f4f1; }
.finding.warn { border-color: var(--warn); background: #fff4df; }
.finding strong { display: block; margin-bottom: 3px; }
.cal-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.cal-meta { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 13px 0 6px; }
.cal-meta div { padding: 8px; background: #f2f6f4; border-radius: 4px; }
.cal-meta small { display: block; color: var(--muted); }
.cal-meta b { display: block; margin-top: 2px; font-variant-numeric: tabular-nums; }
.cal-chart { height: 250px; }
.table-shell { overflow: auto; border: 1px solid var(--line); border-radius: 7px; background: var(--surface); }
table { width: 100%; border-collapse: collapse; white-space: nowrap; font-variant-numeric: tabular-nums; }
th { position: sticky; top: 0; z-index: 1; padding: 11px 12px; background: #e9efec; color: #43514d; text-align: right; font-size: 11px; text-transform: uppercase; }
th:first-child, td:first-child { text-align: left; }
td { padding: 10px 12px; border-top: 1px solid #e6ebe9; text-align: right; }
tbody tr:hover { background: #f4f8f6; }
.valid { color: var(--good); font-weight: 700; }
.invalid { color: var(--bad); font-weight: 700; }
.foot { margin-top: 16px; color: var(--muted); font-size: 12px; }
@media (max-width: 900px) {
  .wrap { width: min(100% - 24px, 1440px); }
  .headline { align-items: flex-start; flex-direction: column; }
  .source { text-align: left; }
  .toolbar { position: static; }
  .toolbar-inner { align-items: stretch; flex-direction: column; padding: 9px 0; }
  .filters { justify-content: space-between; }
  .kpis, .charts, .findings, .cal-grid { grid-template-columns: 1fr; }
  .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 520px) {
  h1 { font-size: 25px; }
  .tabs button, .segments button { padding: 7px 9px; }
  .filters { align-items: flex-start; flex-direction: column; }
  .kpis { grid-template-columns: 1fr; }
  .cal-meta { grid-template-columns: repeat(2, 1fr); }
}
@media print {
  .toolbar { display: none; }
  body { background: white; }
  .view[hidden] { display: block; }
  .view { break-before: page; }
  .view:first-child { break-before: auto; }
}
</style>
</head>
<body>
<header class="topband">
  <div class="wrap headline">
    <div><div class="eyebrow">Shinku performance evidence</div><h1>PERF-M8-1 Benchmark Report</h1></div>
    <div><div class="statusline" id="statusline"></div><div class="source" id="source"></div></div>
  </div>
</header>
<nav class="toolbar" aria-label="Report views">
  <div class="wrap toolbar-inner">
    <div class="tabs" id="tabs">
      <button class="active" data-view="overview">Overview</button>
      <button data-view="calibration">Calibration</button>
      <button data-view="data">Data</button>
    </div>
    <div class="filters" id="filters">
      <div class="segments" id="workload-filter"></div>
      <div class="segments" id="phase-filter"></div>
    </div>
  </div>
</nav>
<main class="wrap">
  <section class="view" id="view-overview">
    <div class="kpis" id="kpis"></div>
    <div class="section-head"><div><h2>Scenario comparison</h2><div class="context" id="comparison-context"></div></div></div>
    <div class="charts">
      <article class="panel"><h3>Throughput</h3><div class="panel-note">Median completed queries per second</div><div class="chart" id="qps-chart"></div><div class="legend" id="qps-legend"></div></article>
      <article class="panel"><h3>Latency</h3><div class="panel-note">Merged histogram upper bounds, milliseconds</div><div class="chart" id="latency-chart"></div><div class="legend" id="latency-legend"></div></article>
      <article class="panel"><h3>CPU demand</h3><div class="panel-note">Median mean cores during the formal interval</div><div class="chart" id="cpu-chart"></div><div class="legend" id="cpu-legend"></div></article>
      <article class="panel"><h3>End-to-end hit ratio</h3><div class="panel-note">Shinku and CoreDNS cache contribution combined</div><div class="chart" id="hit-chart"></div><div class="legend" id="hit-legend"></div></article>
    </div>
    <div class="findings" id="findings"></div>
  </section>
  <section class="view" id="view-calibration" hidden>
    <div class="section-head"><div><h2>Calibration envelope</h2><div class="context" id="calibration-context"></div></div></div>
    <div class="cal-grid" id="calibration-grid"></div>
  </section>
  <section class="view" id="view-data" hidden>
    <div class="section-head"><div><h2>Aggregated measurements</h2><div class="context">Complete summary fields excluding raw histogram bins</div></div></div>
    <div class="table-shell"><table><thead><tr><th>Scenario</th><th>QPS</th><th>p50 ms</th><th>p99 ms</th><th>QPS CV</th><th>Hit</th><th>CoreDNS</th><th>Shinku user</th><th>Host</th><th>Paired delta</th><th>Valid</th></tr></thead><tbody id="data-body"></tbody></table></div>
    <div class="foot">No product performance threshold is applied. Raw histogram bins remain in the source summary.</div>
  </section>
</main>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
const report = JSON.parse(document.getElementById('report-data').textContent);
const scenarioOrder = ['native-off-shinku-off','native-off-shinku-on','native-on-shinku-off','native-on-shinku-on'];
const scenarioLabels = {'native-off-shinku-off':'No cache','native-off-shinku-on':'Shinku','native-on-shinku-off':'CoreDNS','native-on-shinku-on':'Shinku + CoreDNS'};
const scenarioColors = {'native-off-shinku-off':'#61706c','native-off-shinku-on':'#087f72','native-on-shinku-off':'#d85b43','native-on-shinku-on':'#3975b7'};
const seriesColors = ['#087f72','#d85b43','#c88a10','#3975b7'];
const workloads = [...new Set(report.groups.map(g => g.workload))];
const phases = [...new Set(report.groups.map(g => g.phase))];
let selectedWorkload = workloads[0];
let selectedPhase = phases.includes('capacity') ? 'capacity' : phases[0];

const number = (value, digits = 0) => value == null || !Number.isFinite(Number(value)) ? 'N/A' : Number(value).toLocaleString(undefined, {maximumFractionDigits: digits, minimumFractionDigits: digits});
const percent = value => value == null ? 'N/A' : number(Number(value) * 100, 2) + '%';
const ms = value => value == null ? 'N/A' : number(Number(value) * 1000, 3);
const metric = (group, key) => Number(group?.metrics?.[key] ?? 0);
const currentGroups = () => scenarioOrder.map(s => report.groups.find(g => g.workload === selectedWorkload && g.phase === selectedPhase && g.scenario === s)).filter(Boolean);

function buttons(target, values, selected, callback) {
  const root = document.getElementById(target);
  root.innerHTML = '';
  values.forEach(value => {
    const button = document.createElement('button');
    button.textContent = value[0].toUpperCase() + value.slice(1);
    button.className = value === selected ? 'active' : '';
    button.onclick = () => callback(value);
    root.appendChild(button);
  });
}

function renderHeader() {
  const badges = [
    `<span class="badge ${report.complete ? 'good' : 'warn'}">${report.complete ? 'Complete' : 'Incomplete'}</span>`,
    `<span class="badge ${report.canonical_eligible ? 'good' : 'warn'}">${report.canonical_eligible ? 'Canonical eligible' : 'Non-canonical'}</span>`,
    `<span class="badge">${number(report.round_count)} rounds</span>`
  ];
  document.getElementById('statusline').innerHTML = badges.join('');
  document.getElementById('source').textContent = report.source;
}

function renderKpis(groups) {
  const best = groups.reduce((a, b) => metric(a, 'qps_median') > metric(b, 'qps_median') ? a : b);
  const lowestP99 = groups.reduce((a, b) => metric(a, 'latency_p99_seconds') < metric(b, 'latency_p99_seconds') ? a : b);
  const target = report.common_load_qps[selectedWorkload];
  const unstable = Object.entries(report.capacity_unstable).filter(([key, value]) => value && key.startsWith(selectedWorkload + '/')).length;
  const cards = [
    ['Top throughput', number(metric(best, 'qps_median')), scenarioLabels[best.scenario] + ' QPS'],
    ['Lowest p99', ms(metric(lowestP99, 'latency_p99_seconds')) + ' ms', scenarioLabels[lowestP99.scenario]],
    ['Common load', target == null ? 'N/A' : number(target), report.common_driver_scenarios[selectedWorkload] ? 'driver: ' + scenarioLabels[report.common_driver_scenarios[selectedWorkload]] : 'capacity phase'],
    ['Stability', unstable ? unstable + ' unstable' : 'Stable', report.tc_modes.length ? 'TC: ' + report.tc_modes.join(', ') : 'TC mode unavailable']
  ];
  document.getElementById('kpis').innerHTML = cards.map(c => `<div class="kpi"><div class="label">${c[0]}</div><div class="value">${c[1]}</div><div class="detail">${c[2]}</div></div>`).join('');
}

function renderLegend(target, labels, colors) {
  document.getElementById(target).innerHTML = labels.map((label, index) => `<span style="--swatch:${colors[index]}">${label}</span>`).join('');
}

function barChart(target, groups, series, options = {}) {
  const root = document.getElementById(target);
  const width = 680, height = 292, left = 64, right = 12, top = 18, bottom = 54;
  const plotW = width - left - right, plotH = height - top - bottom;
  const values = groups.flatMap(group => series.map(s => Math.max(0, s.value(group))));
  const max = options.max ?? Math.max(...values, 1) * 1.12;
  const ticks = 4;
  const cluster = plotW / groups.length;
  const barW = Math.min(42, (cluster * 0.72) / series.length);
  let svg = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${options.aria || 'Bar chart'}">`;
  for (let tick = 0; tick <= ticks; tick++) {
    const y = top + plotH - plotH * tick / ticks;
    const value = max * tick / ticks;
    svg += `<line class="gridline" x1="${left}" y1="${y}" x2="${width-right}" y2="${y}"/><text class="axislabel" x="${left-8}" y="${y+4}" text-anchor="end">${options.tick ? options.tick(value) : number(value)}</text>`;
  }
  groups.forEach((group, gi) => {
    const totalW = barW * series.length;
    const startX = left + cluster * gi + (cluster - totalW) / 2;
    series.forEach((item, si) => {
      const value = Math.max(0, item.value(group));
      const h = Math.max(value > 0 ? 1 : 0, plotH * value / max);
      const x = startX + si * barW, y = top + plotH - h;
      svg += `<rect x="${x+1}" y="${y}" width="${barW-2}" height="${h}" rx="2" fill="${item.color}"><title>${scenarioLabels[group.scenario]} · ${item.label}: ${item.format(value)}</title></rect>`;
    });
    const label = scenarioLabels[group.scenario].replace(' + ', ' +\n');
    label.split('\n').forEach((line, index) => { svg += `<text class="barlabel" x="${left + cluster * (gi + .5)}" y="${top+plotH+19+index*13}" text-anchor="middle">${line}</text>`; });
  });
  root.innerHTML = svg + '</svg>';
}

function renderOverview() {
  const groups = currentGroups();
  if (!groups.length) return;
  renderKpis(groups);
  document.getElementById('comparison-context').textContent = `${selectedWorkload} workload · ${selectedPhase} load · ${groups[0].metrics.rounds} round(s) per scenario`;
  barChart('qps-chart', groups, [{label:'Median QPS', color:'#087f72', value:g=>metric(g,'qps_median'), format:v=>number(v)}], {tick:v=>number(v/1000)+'k', aria:'Median QPS by scenario'});
  renderLegend('qps-legend',['Median QPS'],['#087f72']);
  barChart('latency-chart', groups, [
    {label:'p50',color:'#3975b7',value:g=>metric(g,'latency_p50_seconds')*1000,format:v=>number(v,3)+' ms'},
    {label:'p99',color:'#d85b43',value:g=>metric(g,'latency_p99_seconds')*1000,format:v=>number(v,3)+' ms'}
  ], {tick:v=>number(v,1), aria:'Latency percentiles by scenario'});
  renderLegend('latency-legend',['p50','p99'],['#3975b7','#d85b43']);
  barChart('cpu-chart', groups, [
    {label:'CoreDNS',color:'#d85b43',value:g=>metric(g,'core_dns_mean_cores_median'),format:v=>number(v,3)+' cores'},
    {label:'Shinku user',color:'#c88a10',value:g=>metric(g,'shinku_userspace_mean_cores_median'),format:v=>number(v,3)+' cores'},
    {label:'Whole host',color:'#087f72',value:g=>metric(g,'whole_host_mean_cores_median'),format:v=>number(v,3)+' cores'}
  ], {tick:v=>number(v,1), aria:'CPU mean cores by scenario'});
  renderLegend('cpu-legend',['CoreDNS','Shinku userspace','Whole host'],['#d85b43','#c88a10','#087f72']);
  barChart('hit-chart', groups, [{label:'Hit ratio',color:'#3975b7',value:g=>metric(g,'hit_ratio_median')*100,format:v=>number(v,2)+'%'}], {max:100,tick:v=>number(v)+'%',aria:'Cache hit ratio by scenario'});
  renderLegend('hit-legend',['End-to-end hit ratio'],['#3975b7']);

  const baseline = groups.find(g=>g.scenario==='native-off-shinku-off');
  const fastest = groups.reduce((a,b)=>metric(a,'qps_median')>metric(b,'qps_median')?a:b);
  const gain = baseline ? metric(fastest,'qps_median') / metric(baseline,'qps_median') : null;
  const shinkuDeltas = groups.filter(g=>g.metrics.paired_whole_host_delta_median != null);
  const bestDelta = shinkuDeltas.length ? shinkuDeltas.reduce((a,b)=>metric(a,'paired_whole_host_delta_median')<metric(b,'paired_whole_host_delta_median')?a:b) : null;
  document.getElementById('findings').innerHTML = [
    `<div class="finding"><strong>${scenarioLabels[fastest.scenario]} leads throughput</strong>${number(metric(fastest,'qps_median'))} QPS${gain ? ', ' + number(gain,2) + '× the uncached baseline' : ''}.</div>`,
    bestDelta ? `<div class="finding"><strong>Lowest paired host demand</strong>${scenarioLabels[bestDelta.scenario]} changes whole-host demand by ${number(metric(bestDelta,'paired_whole_host_delta_median'),3)} mean cores.</div>` : `<div class="finding warn"><strong>Paired host delta unavailable</strong>No Shinku pairing is present for this selection.</div>`
  ].join('');
}

function calibrationChart(target, calibration) {
  const samples = calibration.samples || [];
  const width=650,height=236,left=58,right=12,top=13,bottom=43,plotW=width-left-right,plotH=height-top-bottom;
  const clients=[...new Set(samples.map(s=>s.clients))].sort((a,b)=>a-b);
  const outstandings=[...new Set(samples.map(s=>s.outstanding))].sort((a,b)=>a-b);
  const max=Math.max(...samples.map(s=>s.qps),1)*1.1;
  const x=value=>left+(clients.indexOf(value)+.5)*plotW/clients.length;
  const y=value=>top+plotH-value/max*plotH;
  let svg=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Calibration QPS by clients and outstanding queries">`;
  for(let i=0;i<=4;i++){const py=top+plotH-i*plotH/4;svg+=`<line class="gridline" x1="${left}" y1="${py}" x2="${width-right}" y2="${py}"/><text class="axislabel" x="${left-7}" y="${py+4}" text-anchor="end">${number(max*i/4000)}k</text>`;}
  clients.forEach(c=>svg+=`<text class="axislabel" x="${x(c)}" y="${top+plotH+19}" text-anchor="middle">${c}</text>`);
  outstandings.forEach((outstanding,oi)=>{
    const points=samples.filter(s=>s.outstanding===outstanding).sort((a,b)=>a.clients-b.clients);
    svg+=`<polyline fill="none" stroke="${seriesColors[oi%seriesColors.length]}" stroke-width="2" points="${points.map(p=>x(p.clients)+','+y(p.qps)).join(' ')}"/>`;
    points.forEach(p=>{const color=p.lost===0?seriesColors[oi%seriesColors.length]:'#b42318';svg+=`<circle cx="${x(p.clients)}" cy="${y(p.qps)}" r="${p.lost===0?4:5}" fill="${color}" stroke="white" stroke-width="1"><title>${p.clients} clients · ${outstanding} outstanding · ${number(p.qps)} QPS · lost ${number(p.lost)}</title></circle>`;});
  });
  document.getElementById(target).innerHTML=svg+'</svg>';
  return outstandings;
}

function renderCalibration() {
  const entries = Object.entries(report.calibrations[selectedWorkload] || {}).sort((a,b)=>scenarioOrder.indexOf(a[0])-scenarioOrder.indexOf(b[0]));
  document.getElementById('calibration-context').textContent = `${selectedWorkload} workload · red points indicate query loss`;
  const grid=document.getElementById('calibration-grid'); grid.innerHTML='';
  entries.forEach(([scenario,cal],index)=>{
    const article=document.createElement('article'); article.className='panel';
    article.innerHTML=`<h3>${scenarioLabels[scenario] || scenario}</h3><div class="cal-meta"><div><small>Selected clients</small><b>${number(cal.clients)}</b></div><div><small>Outstanding</small><b>${number(cal.outstanding)}</b></div><div><small>Selected QPS</small><b>${number(cal.qps)}</b></div><div><small>Observed max</small><b>${number(cal.observed_maximum_qps)}</b></div></div><div class="chart cal-chart" id="cal-${index}"></div><div class="legend" id="cal-legend-${index}"></div>`;
    grid.appendChild(article);
    const outstanding=calibrationChart(`cal-${index}`,cal);
    renderLegend(`cal-legend-${index}`,outstanding.map(v=>`${v} outstanding`),outstanding.map((_,i)=>seriesColors[i%seriesColors.length]));
  });
}

function renderTable() {
  document.getElementById('data-body').innerHTML = report.groups.map(g=>{
    const m=g.metrics;
    return `<tr><td>${g.name}</td><td>${number(m.qps_median,2)}</td><td>${ms(m.latency_p50_seconds)}</td><td>${ms(m.latency_p99_seconds)}</td><td>${percent(m.qps_cv)}</td><td>${percent(m.hit_ratio_median)}</td><td>${number(m.core_dns_mean_cores_median,3)}</td><td>${number(m.shinku_userspace_mean_cores_median,3)}</td><td>${number(m.whole_host_mean_cores_median,3)}</td><td>${number(m.paired_whole_host_delta_median,3)}</td><td class="${m.valid?'valid':'invalid'}">${m.valid?'yes':'no'}</td></tr>`;
  }).join('');
}

function refresh() {
  buttons('workload-filter',workloads,selectedWorkload,value=>{selectedWorkload=value;refresh();});
  buttons('phase-filter',phases,selectedPhase,value=>{selectedPhase=value;refresh();});
  renderOverview(); renderCalibration();
}

document.getElementById('tabs').addEventListener('click',event=>{
  const button=event.target.closest('button'); if(!button)return;
  document.querySelectorAll('#tabs button').forEach(item=>item.classList.toggle('active',item===button));
  document.querySelectorAll('.view').forEach(view=>view.hidden=view.id!==`view-${button.dataset.view}`);
  document.getElementById('filters').style.visibility=button.dataset.view==='data'?'hidden':'visible';
});
renderHeader(); renderTable(); refresh();
</script>
</body>
</html>
'''


if __name__ == "__main__":
    sys.exit(main())
