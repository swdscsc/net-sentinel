# -*- coding: utf-8 -*-
"""
NetSentinel · 演示与报告生成
-------------------------------------------------
运行 detector + evaluate，产出自包含 HTML 报告 output/report.html：
  · 概览卡片 / 检测指标表
  · 流量时间线（攻击窗口着色）
  · 告警类型分布 / Top 流量主机
  · 告警明细表
纯标准库，图表用内联 SVG，离线可用、可直接截图发 HR。
"""
import csv, os
from collections import defaultdict
from detector import detect
from evaluate import evaluate, TYPES

OUT_DIR = "output"
REPORT = os.path.join(OUT_DIR, "report.html")
T_STEPS = 240
COLOR = {"PORT_SCAN": "#e67e22", "SYN_FLOOD": "#c0392b",
         "BRUTE_FORCE": "#8e44ad", "EXFIL": "#2980b9", "ANOMALY": "#7f8c8d"}


def load_flows(p="flows.csv"):
    with open(p, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def svg_timeline(flows, gt):
    bins = 48
    span = T_STEPS / bins
    vol = [0] * bins
    for r in flows:
        b = min(bins - 1, int(float(r["ts"]) / span))
        vol[b] += float(r["byte_count"])
    W, H, pad = 720, 200, 30
    mx = max(vol) or 1
    bw = (W - 2 * pad) / bins
    parts = [f'<svg viewBox="0 0 {W} {H+40}" width="100%" font-family="monospace" font-size="11">']
    # 攻击窗口阴影
    for g in gt:
        x0 = pad + (float(g["start_ts"]) / T_STEPS) * (W - 2 * pad)
        x1 = pad + (float(g["end_ts"]) / T_STEPS) * (W - 2 * pad)
        c = COLOR.get(g["type"], "#999")
        parts.append(f'<rect x="{x0:.1f}" y="{pad}" width="{x1-x0:.1f}" height="{H}" '
                     f'fill="{c}" opacity="0.18"/>')
    # 柱
    for i, v in enumerate(vol):
        x = pad + i * bw
        h = (v / mx) * H
        parts.append(f'<rect x="{x:.1f}" y="{pad+H-h:.1f}" width="{bw-1:.1f}" height="{h:.1f}" fill="#34495e"/>')
    parts.append(f'<line x1="{pad}" y1="{pad+H}" x2="{W-pad}" y2="{pad+H}" stroke="#999"/>')
    parts.append(f'<text x="{pad}" y="{pad+H+18}" fill="#555">t=0</text>')
    parts.append(f'<text x="{W-pad-30}" y="{pad+H+18}" fill="#555">t={T_STEPS}</text>')
    parts.append(f'<text x="{pad}" y="16" fill="#555">流量字节量（彩色阴影=攻击窗口）</text>')
    parts.append('</svg>')
    return "".join(parts)


def svg_bar(items, title, color="#3498db", unit=""):
    """items: [(label, value)]"""
    if not items:
        return ""
    W, H, pad = 720, 220, 30
    mx = max(v for _, v in items) or 1
    n = len(items)
    bw = (W - 2 * pad) / max(1, n)
    parts = [f'<svg viewBox="0 0 {W} {H+40}" width="100%" font-family="monospace" font-size="11">']
    parts.append(f'<text x="{pad}" y="16" fill="#555">{title}</text>')
    for i, (lab, v) in enumerate(items):
        x = pad + i * bw
        h = (v / mx) * H
        parts.append(f'<rect x="{x:.1f}" y="{pad+H-h:.1f}" width="{bw-6:.1f}" height="{h:.1f}" fill="{color}"/>')
        parts.append(f'<text x="{x:.1f}" y="{pad+H-h-4:.1f}" fill="#333" font-size="10">{v:.2f}{unit}</text>')
        parts.append(f'<text x="{x:.1f}" y="{pad+H+16:.1f}" fill="#555" font-size="10" '
                     f'transform="rotate(25 {x:.1f} {pad+H+16:.1f})">{lab}</text>')
    parts.append('</svg>')
    return "".join(parts)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    flows = load_flows()
    alerts = detect()
    rep = evaluate(alerts)
    with open("ground_truth.csv", encoding="utf-8") as f:
        gt = list(csv.DictReader(f))

    # 数据
    n_flow = len(flows)
    n_attack = len(gt)
    micro = rep["__micro__"]
    type_counts = defaultdict(int)
    for a in alerts:
        type_counts[a["type"]] += 1
    talker = defaultdict(float)
    for r in flows:
        talker[r["src_ip"]] += float(r["byte_count"])
    top = sorted(talker.items(), key=lambda x: -x[1])[:8]

    # 指标表
    rows = ""
    for t in TYPES:
        d = rep[t]
        rows += (f"<tr><td>{t}</td><td>{d['n_gt']}</td><td>{d['n_pred']}</td>"
                 f"<td>{d['precision']*100:.0f}%</td><td>{d['recall']*100:.0f}%</td>"
                 f"<td><b>{d['f1']*100:.0f}%</b></td></tr>")
    detail_rows = ""
    for t, kind, gs, gd, as_, ad in rep["__detail__"]:
        cls = {"TP": "ok", "FP": "bad", "FN": "bad"}[kind]
        detail_rows += (f"<tr><td>{t}</td><td class='{cls}'>{kind}</td>"
                        f"<td>{gs}/{as_}</td><td>{gd}/{ad}</td></tr>")

    alert_rows = ""
    for a in alerts:
        c = COLOR.get(a["type"], "#999")
        alert_rows += (f"<tr><td><span class='chip' style='background:{c}'>{a['type']}</span></td>"
                       f"<td>{a['severity']}</td><td>{a['src']}</td><td>{a['dst']}</td>"
                       f"<td>{a['confidence']}</td><td class='ev'>{a['evidence']}</td></tr>")

    legend = "".join(f"<span class='lg'><i style='background:{c}'></i>{t}</span>"
                     for t, c in COLOR.items())

    html = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>NetSentinel 网络入侵检测 · 演示报告</title>
<style>
 body{{font-family:-apple-system,'Segoe UI',Roboto,'Microsoft YaHei',sans-serif;
  margin:0;background:#f5f6fa;color:#2c3e50;padding:24px}}
 .wrap{{max-width:840px;margin:0 auto;background:#fff;border-radius:10px;
  box-shadow:0 2px 12px rgba(0,0,0,.08);padding:28px}}
 h1{{font-size:22px;margin:0 0 4px}} .sub{{color:#7f8c8d;font-size:13px;margin-bottom:18px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
 .card{{flex:1;min-width:140px;background:#f0f3f8;border-radius:8px;padding:14px}}
 .card .n{{font-size:26px;font-weight:700;color:#2c3e50}}
 .card .l{{font-size:12px;color:#7f8c8d}}
 table{{width:100%;border-collapse:collapse;margin:10px 0 22px;font-size:13px}}
 th,td{{border:1px solid #e1e6ed;padding:7px 9px;text-align:left}}
 th{{background:#f0f3f8;font-weight:600}}
 tr.ok td.bad{{color:#c0392b}} .ok{{color:#27ae60;font-weight:600}}
 .bad{{color:#c0392b;font-weight:600}}
 .chip{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
 .ev{{color:#555;font-size:12px}}
 .sec{{margin:22px 0 8px;font-size:15px;font-weight:600;border-left:3px solid #2980b9;padding-left:8px}}
 .lg{{display:inline-block;margin-right:14px;font-size:12px;color:#555}}
 .lg i{{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:4px;vertical-align:middle}}
 .foot{{margin-top:24px;font-size:11px;color:#95a5a6;border-top:1px solid #eee;padding-top:10px}}
</style></head><body><div class="wrap">
<h1>NetSentinel · 网络流量入侵检测与可视化分析</h1>
<div class="sub">纯 Python + OpenCV 无关的经典流量分析方案 · 自建带标签测试集 · 可解释规则引擎</div>
<div class="cards">
 <div class="card"><div class="n">{n_flow}</div><div class="l">流记录总数</div></div>
 <div class="card"><div class="n">{n_attack}</div><div class="l">注入攻击事件</div></div>
 <div class="card"><div class="n" style="color:#27ae60">{len(alerts)}</div><div class="l">检出告警</div></div>
 <div class="card"><div class="n" style="color:#27ae60">{micro['precision']*100:.0f}%</div><div class="l">整体 Precision</div></div>
 <div class="card"><div class="n" style="color:#27ae60">{micro['f1']*100:.0f}%</div><div class="l">整体 F1</div></div>
</div>

<div class="sec">一、检测指标（按攻击类型）</div>
<table><tr><th>攻击类型</th><th>真值</th><th>检出</th><th>Precision</th><th>Recall</th><th>F1</th></tr>
{rows}</table>

<div class="sec">二、流量时间线（攻击窗口着色）</div>
{svg_timeline(flows, gt)}
<div style="margin:6px 0 14px">{legend}</div>

<div class="sec">三、告警类型分布</div>
{svg_bar([(t, type_counts.get(t,0)) for t in TYPES], "各类型告警数量", "#3498db")}

<div class="sec">四、Top 流量主机（MB）</div>
{svg_bar([(s.split('.')[-1], v/1e6) for s, v in top], "内网主机出站/总流量 Top8", "#16a085", unit="MB")}

<div class="sec">五、告警明细</div>
<table><tr><th>类型</th><th>级别</th><th>源</th><th>目标</th><th>置信度</th><th>证据</th></tr>
{alert_rows}</table>

<div class="sec">六、评测细节（TP/FP/FN）</div>
<table><tr><th>类型</th><th>判定</th><th>真值(源/目的)</th><th>预测(源/目的)</th></tr>
{detail_rows}</table>

<div class="foot">NetSentinel demo report · 数据由 gen_traffic.py 合成并带真值标签 · 检测器 detector.py 为可解释规则引擎，
所有指标在固定随机种子下可复现。本系统定位为教学/作品集级入侵检测原型。</div>
</div></body></html>"""

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write(html)
    print("报告已生成：", REPORT)
    print(f"流记录={n_flow} 攻击事件={n_attack} 告警={len(alerts)} "
          f"P={micro['precision']*100:.0f}% R={micro['recall']*100:.0f}% F1={micro['f1']*100:.0f}%")


if __name__ == "__main__":
    main()
