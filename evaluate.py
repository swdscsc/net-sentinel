# -*- coding: utf-8 -*-
"""
NetSentinel · 评测脚本
-------------------------------------------------
读取 ground_truth.csv（攻击事件级真值）与 detector 输出的告警，
按「类型相同 + 源/目的重叠」做贪心 1:1 匹配，计算每类与整体的
Precision / Recall / F1。供 demo 嵌入报告，也可独立运行查看指标。
"""
import csv
from collections import defaultdict
from detector import detect

TYPES = ["PORT_SCAN", "SYN_FLOOD", "BRUTE_FORCE", "EXFIL"]


def _load_gt(path="ground_truth.csv"):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def evaluate(alerts=None, gt_path="ground_truth.csv"):
    if alerts is None:
        alerts = detect()
    gt = _load_gt(gt_path)
    matched_a = set()
    matched_g = set()
    tp_by = defaultdict(int)
    detail = []

    # 贪心 1:1 匹配
    for gi, g in enumerate(gt):
        gsrc, gdst, gtype = g["src_ip"], g["dst_ip"], g["type"]
        for ai, a in enumerate(alerts):
            if ai in matched_a or a["type"] != gtype:
                continue
            src_eq = (a["src"] == gsrc)
            dst_eq = (gdst != "MULTI" and (gdst in a["dst"] or a["dst"] in gdst))
            if src_eq or dst_eq:
                matched_a.add(ai)
                matched_g.add(gi)
                tp_by[gtype] += 1
                detail.append((gtype, "TP", gsrc, gdst, a["src"], a["dst"]))
                break

    # 未匹配的告警 = FP；未匹配的真值 = FN
    for ai, a in enumerate(alerts):
        if ai not in matched_a and a["type"] in TYPES:
            detail.append((a["type"], "FP", "-", "-", a["src"], a["dst"]))
    for gi, g in enumerate(gt):
        if gi not in matched_g:
            detail.append((g["type"], "FN", g["src_ip"], g["dst_ip"], "-", "-"))

    # 汇总
    report = {}
    micro_tp = micro_fp = micro_fn = 0
    for t in TYPES:
        pred = [a for a in alerts if a["type"] == t and a["type"] in TYPES]
        gtt = [g for g in gt if g["type"] == t]
        tp = tp_by.get(t, 0)
        fp = len(pred) - tp
        fn = len(gtt) - tp
        p = tp / (tp + fp) if (tp + fp) else 0
        r = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * p * r / (p + r) if (p + r) else 0
        report[t] = dict(tp=tp, fp=fp, fn=fn, precision=p, recall=r, f1=f1,
                         n_pred=len(pred), n_gt=len(gtt))
        micro_tp += tp; micro_fp += fp; micro_fn += fn
    mp = micro_tp / (micro_tp + micro_fp) if (micro_tp + micro_fp) else 0
    mr = micro_tp / (micro_tp + micro_fn) if (micro_tp + micro_fn) else 0
    mf1 = 2 * mp * mr / (mp + mr) if (mp + mr) else 0
    report["__micro__"] = dict(precision=mp, recall=mr, f1=mf1,
                               tp=micro_tp, fp=micro_fp, fn=micro_fn)
    report["__detail__"] = detail
    return report


def _fmt(x):
    return f"{x*100:.1f}%"


if __name__ == "__main__":
    rep = evaluate()
    print("=" * 64)
    print(f"{'攻击类型':<12}{'真值':>5}{'检出':>5}{'P':>9}{'R':>9}{'F1':>9}")
    print("-" * 64)
    for t in TYPES:
        d = rep[t]
        print(f"{t:<12}{d['n_gt']:>5}{d['n_pred']:>5}{_fmt(d['precision']):>9}"
              f"{_fmt(d['recall']):>9}{_fmt(d['f1']):>9}")
    m = rep["__micro__"]
    print("-" * 64)
    print(f"{'整体(micro)':<12}{'':>5}{'':>5}{_fmt(m['precision']):>9}"
          f"{_fmt(m['recall']):>9}{_fmt(m['f1']):>9}")
    print("=" * 64)
