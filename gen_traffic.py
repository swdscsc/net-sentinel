# -*- coding: utf-8 -*-
"""
NetSentinel · 合成网络流量与攻击事件生成器
-------------------------------------------------
模拟一个小型企业内网（10.0.0.0/24）在一段时间内的流量，
并注入四类带真值标签的攻击事件：
  1) PORT_SCAN   端口扫描（单源对单目标横扫大量端口）
  2) SYN_FLOOD    SYN Flood / DDoS（目标 443 端口 SYN 海量、ACK 比极低）
  3) BRUTE_FORCE  暴力破解（SSH 连续失败登录）
  4) EXFIL        数据外泄（内网主机向外网异常大流量）
输出：
  flows.csv        流级记录（带 label_type 真值）
  auth.csv         认证日志（带 label_type 真值）
  ground_truth.csv 攻击事件级真值（供评测匹配）
纯标准库 + numpy，可复现（固定随机种子）。
"""
import csv, random
import numpy as np

OUT = "flows.csv"
AUTH = "auth.csv"
GT = "ground_truth.csv"
SEED = 20261010
random.seed(SEED)
np.random.seed(SEED)

T_STEPS = 240                       # 时间步（0..239）
INTERNAL = [f"10.0.0.{i}" for i in range(2, 21)]   # 内网主机 10.0.0.2 ~ 10.0.0.20
EXTERNAL = ["8.8.8.8", "1.1.1.1", "52.94.236.10", "13.107.42.14",
            "104.18.32.7", "203.119.25.9", "185.199.108.153"]
POP_PORTS = [80, 443, 53, 22, 25, 3306, 8080, 443]
SERVER = "10.0.0.10"               # 内网服务器（扫描/洪水目标）

flows = []     # ts, src, dst, dport, proto, pkts, bytes, dur, syn, ack, label_type
auth = []      # ts, src, dst, service, result, label_type
gt = []        # event_id, type, src, dst, start_ts, end_ts


def add_flow(ts, src, dst, dport, pkts, nbytes, dur, syn, ack, label=""):
    flows.append([ts, src, dst, dport, "TCP", pkts, nbytes, round(dur, 2), syn, ack, label])


# ---------- 1. 正常背景流量 ----------
n_normal = 620
for _ in range(n_normal):
    ts = random.randint(0, T_STEPS - 1)
    src = random.choice(INTERNAL)
    if random.random() < 0.55:              # 内网互访
        dst = random.choice([h for h in INTERNAL if h != src])
        dport = random.choice([22, 80, 443, 3306, 8080, 21, 23])
    else:                                    # 访问外网
        dst = random.choice(EXTERNAL)
        dport = random.choice(POP_PORTS)
    pkts = int(np.random.lognormal(3.0, 0.6))
    nbytes = int(pkts * random.randint(500, 1500))
    dur = round(random.uniform(0.1, 6.0), 2)
    add_flow(ts, src, dst, dport, pkts, nbytes, dur, 1, 1, "")

# 少量正常失败登录（远低于暴力破解阈值，增加真实性）
for _ in range(6):
    ts = random.randint(0, T_STEPS - 1)
    auth.append([ts, random.choice(INTERNAL), SERVER, "SSH", "FAIL", ""])
for _ in range(20):
    ts = random.randint(0, T_STEPS - 1)
    auth.append([ts, random.choice(INTERNAL), SERVER, "SSH", "SUCCESS", ""])


# ---------- 2. 端口扫描 PORT_SCAN ----------
def port_scan(eid, attacker, target, start):
    ports = list(range(1, 1025))
    random.shuffle(ports)
    n = random.randint(55, 80)
    ports = ports[:n]
    t0 = start
    for i, p in enumerate(ports):
        ts = t0 + i // 12                 # 紧凑时间窗
        add_flow(ts, attacker, target, p, random.randint(1, 3),
                 random.randint(40, 160), round(random.uniform(0.01, 0.2), 2), 1, 0, "PORT_SCAN")
    gt.append([eid, "PORT_SCAN", attacker, target, t0, t0 + n // 12 + 1])
    return t0 + n // 12 + 5

t = port_scan("E1", "10.0.0.50", SERVER, 30)
t = port_scan("E2", "10.0.0.51", SERVER, 120)
t = port_scan("E3", "10.0.0.52", "10.0.0.14", 190)


# ---------- 3. SYN Flood / DDoS ----------
def syn_flood(eid, target, start):
    spoof_srcs = [f"172.16.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(40)]
    t0 = start
    n = random.randint(110, 150)
    for i in range(n):
        ts = t0 + i // 20
        src = random.choice(spoof_srcs)
        add_flow(ts, src, target, 443, 1, 60, 0.01, 1, 0, "SYN_FLOOD")
    gt.append([eid, "SYN_FLOOD", "MULTI", target, t0, t0 + n // 20 + 1])
    return t0 + n // 20 + 5

t = syn_flood("E4", SERVER, 60)
t = syn_flood("E5", "10.0.0.15", 150)


# ---------- 4. 暴力破解 BRUTE_FORCE ----------
def brute_force(eid, attacker, target, start):
    t0 = start
    n_fail = random.randint(20, 35)
    for i in range(n_fail):
        ts = t0 + i
        auth.append([ts, attacker, target, "SSH", "FAIL", "BRUTE_FORCE"])
    auth.append([t0 + n_fail + 1, attacker, target, "SSH", "SUCCESS", "BRUTE_FORCE"])
    gt.append([eid, "BRUTE_FORCE", attacker, target, t0, t0 + n_fail + 1])
    return t0 + n_fail + 5

t = brute_force("E6", "10.0.0.66", SERVER, 80)
t = brute_force("E7", "10.0.0.67", "10.0.0.14", 160)
t = brute_force("E8", "10.0.0.68", SERVER, 210)
t = brute_force("E9", "10.0.0.69", "10.0.0.15", 225)


# ---------- 5. 数据外泄 EXFIL ----------
def exfil(eid, src, start):
    dst = random.choice(EXTERNAL)
    t0 = start
    n = random.randint(8, 14)
    for i in range(n):
        ts = t0 + i
        nbytes = int(np.random.uniform(3e6, 9e6))   # 单流数 MB ~ 数十 MB
        pkts = int(nbytes / random.randint(800, 1400))
        add_flow(ts, src, dst, random.choice([443, 53, 8080]), pkts, nbytes,
                 round(random.uniform(2.0, 8.0), 2), 1, 1, "EXFIL")
    gt.append([eid, "EXFIL", src, dst, t0, t0 + n])
    return t0 + n + 5

t = exfil("E10", "10.0.0.77", 100)
t = exfil("E11", "10.0.0.78", 200)


# ---------- 写出 ----------
flows.sort(key=lambda r: r[0])
auth.sort(key=lambda r: r[0])
gt.sort(key=lambda r: r[0])

with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["ts", "src_ip", "dst_ip", "dst_port", "proto",
                "pkt_count", "byte_count", "duration", "syn", "ack", "label_type"])
    w.writerows(flows)

with open(AUTH, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["ts", "src_ip", "dst_ip", "service", "result", "label_type"])
    w.writerows(auth)

with open(GT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["event_id", "type", "src_ip", "dst_ip", "start_ts", "end_ts"])
    w.writerows(gt)

print(f"生成完成：flows={len(flows)} 行, auth={len(auth)} 行, 攻击事件={len(gt)} 起")
from collections import Counter
print("流级标签分布：", dict(Counter(r[10] for r in flows)))
print("认证级标签分布：", dict(Counter(r[5] for r in auth)))
