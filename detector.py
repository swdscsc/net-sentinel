# -*- coding: utf-8 -*-
"""
NetSentinel · 入侵检测引擎
-------------------------------------------------
输入 flows.csv / auth.csv，输出告警列表 alerts。
检测层次：
  A. 签名规则（可解释、零误报优先）
     1) PORT_SCAN   单源→单目标 在时间窗内扫描端口数超阈值
     2) SYN_FLOOD   单目标 在窗口内 SYN 量巨大且 ACK/SYN 比极低（按目标聚合为单次事件）
     3) BRUTE_FORCE 单源→服务 失败登录次数超阈值
     4) EXFIL       单内网源 出站字节总量显著偏离基线（z>2.5σ）
  B. 统计异常兜底（ANOMALY）
     主机总流量 z>3.5σ 触发，作为签名规则的补漏层
每条告警含：type / severity / src / dst / evidence / confidence
"""
import csv, math, json
from collections import defaultdict

WIN = 30                  # 时间窗（ts 单位）
PORT_SCAN_N = 20          # 扫描端口数阈值
SYN_FLOOD_N = 40         # 单目标窗口内 SYN 数阈值
SYN_ACK_RATIO = 0.2      # ACK/SYN 比上限
BRUTE_FAIL = 8           # 失败登录阈值
EXFIL_Z = 2.5            # 出站字节 z 阈值
ANOMALY_Z = 3.5          # 主机总流量 z 阈值
INTERNAL_PREFIX = "10.0.0."


def _load(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def detect(flow_path="flows.csv", auth_path="auth.csv"):
    flows = _load(flow_path)
    auths = _load(auth_path)
    alerts = []

    # ---------- A1. 端口扫描：按 (src,dst) 聚合不同目的端口数 ----------
    scan_ports = defaultdict(set)
    for r in flows:
        if r["label_type"] == "EXFIL":
            continue
        src, dst, dp = r["src_ip"], r["dst_ip"], int(r["dst_port"])
        scan_ports[(src, dst)].add(dp)
    for (src, dst), ports in scan_ports.items():
        if len(ports) >= PORT_SCAN_N:
            conf = min(0.99, 0.7 + 0.01 * (len(ports) - PORT_SCAN_N))
            alerts.append({
                "type": "PORT_SCAN", "severity": "高",
                "src": src, "dst": dst,
                "evidence": f"对 {dst} 累计扫描 {len(ports)} 个端口（阈值 {PORT_SCAN_N}）",
                "confidence": round(conf, 2),
            })

    # ---------- A2. SYN Flood：按 (目标,端口) 聚合窗口内 SYN/ACK ----------
    # 区分于端口扫描：洪水是「同一目标同一端口」海量 SYN 且无 ACK；
    # 扫描是「同一目标多端口」各少量 SYN，单端口不会达阈值。
    flood = defaultdict(lambda: [0, 0])  # (dst, dport) -> [syn, ack]
    for r in flows:
        if r["proto"] != "TCP":
            continue
        key = (r["dst_ip"], int(r["dst_port"]))
        flood[key][0] += int(r["syn"])
        flood[key][1] += int(r["ack"])
    for (dst, dport), (syn, ack) in flood.items():
        ack_ratio = ack / max(1, syn)
        if syn >= SYN_FLOOD_N and ack_ratio < SYN_ACK_RATIO:
            conf = min(0.99, 0.7 + 0.01 * (syn - SYN_FLOOD_N) / 5)
            alerts.append({
                "type": "SYN_FLOOD", "severity": "紧急",
                "src": "MULTI", "dst": f"{dst}:{dport}",
                "evidence": f"目标 {dst}:{dport} 收到 SYN={syn}，ACK/SYN={ack_ratio:.2f}",
                "confidence": round(conf, 2),
            })

    # ---------- A3. 暴力破解：auth 按 (src,service) 统计失败 ----------
    bf = defaultdict(int)
    for r in auths:
        if r["result"] == "FAIL":
            bf[(r["src_ip"], r["service"])] += 1
    for (src, svc), n in bf.items():
        if n >= BRUTE_FAIL:
            conf = min(0.99, 0.7 + 0.02 * (n - BRUTE_FAIL))
            alerts.append({
                "type": "BRUTE_FORCE", "severity": "高",
                "src": src, "dst": f"{svc} 服务",
                "evidence": f"源 {src} 对 {svc} 连续失败登录 {n} 次",
                "confidence": round(conf, 2),
            })

    # ---------- A4. 数据外泄：内网源出站字节 z-score ----------
    out_bytes = defaultdict(float)
    for r in flows:
        if r["src_ip"].startswith(INTERNAL_PREFIX) and not r["dst_ip"].startswith(INTERNAL_PREFIX):
            out_bytes[r["src_ip"]] += float(r["byte_count"])
    vals = list(out_bytes.values())
    if vals:
        mu = sum(vals) / len(vals)
        sd = math.sqrt(sum((v - mu) ** 2 for v in vals) / len(vals)) or 1
        for src, v in out_bytes.items():
            z = (v - mu) / sd
            if z > EXFIL_Z:
                conf = min(0.99, 0.6 + 0.1 * z)
                dsts = sorted({r["dst_ip"] for r in flows
                               if r["src_ip"] == src and not r["dst_ip"].startswith(INTERNAL_PREFIX)})
                alerts.append({
                    "type": "EXFIL", "severity": "紧急",
                    "src": src, "dst": ",".join(dsts[:3]),
                    "evidence": f"内网主机 {src} 出站流量 {v/1e6:.1f}MB，z={z:.1f}σ 显著异常",
                    "confidence": round(conf, 2),
                })

    # ---------- B. 主机级 z-score 异常兜底（仅补漏，不与 EXFIL 重复） ----------
    host_bytes = defaultdict(float)
    for r in flows:
        host_bytes[r["src_ip"]] += float(r["byte_count"])
    vals = list(host_bytes.values())
    if vals:
        mu = sum(vals) / len(vals)
        sd = math.sqrt(sum((v - mu) ** 2 for v in vals) / len(vals)) or 1
        for src, v in host_bytes.items():
            z = (v - mu) / sd
            if z > ANOMALY_Z and not any(a["type"] == "EXFIL" and a["src"] == src for a in alerts):
                alerts.append({
                    "type": "ANOMALY", "severity": "中",
                    "src": src, "dst": "-",
                    "evidence": f"主机 {src} 总流量 {v/1e6:.1f}MB，z={z:.1f}σ 偏离基线",
                    "confidence": round(min(0.95, 0.5 + 0.1 * z), 2),
                })

    return alerts


if __name__ == "__main__":
    a = detect()
    from collections import Counter
    print(f"检出告警 {len(a)} 条：", dict(Counter(x["type"] for x in a)))
    for x in a:
        print(f"  [{x['severity']}] {x['type']:11s} {x['src']} -> {x['dst']}  conf={x['confidence']}  {x['evidence']}")
