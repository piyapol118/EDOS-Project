"""
Kaggle / CIC-IDS2017 Dataset Entropy Evaluator (Time-Based Interval, v2)

การแก้ไขจาก v1:
- v1 แบ่ง interval ด้วยการหาร "จำนวน row" ออกเป็น 100 ก้อนเท่ากัน
  ซึ่งไม่ตรงกับ interval size T (วินาที) ที่ paper (PMC11300888) กำหนดไว้เลย
  ทำให้แต่ละ "interval" ครอบคลุมช่วงเวลาไม่เท่ากัน (ช่วง traffic หนาแน่น
  vs เบาบาง ได้ interval ที่ความยาวเวลาต่างกันมาก) ผลลัพธ์จึงไม่สม่ำเสมอ

- v2 แบ่ง interval ตาม Timestamp column จริง เป็นช่วงเวลาเท่ากันตาม
  INTERVAL_SECONDS ที่กำหนด (ตรงกับหลักการ "sliding window ขนาด T" ของ paper)

ข้อจำกัดที่ต้องรู้ (สำคัญ อ่านก่อนตีความผลลัพธ์):
  ไฟล์ CIC-IDS2017 นี้มี Timestamp ละเอียดแค่ระดับ "นาที" เท่านั้น
  (มีแค่ 93 ค่าไม่ซ้ำจาก 225,745 rows) ไม่ใช่ระดับวินาที
  ดังนั้น INTERVAL_SECONDS < 60 จะไม่มีความหมายจริงกับไฟล์นี้ —
  ถ้าอยาก interval ละเอียดกว่านาที ต้องใช้ dataset ที่มี timestamp
  ระดับวินาทีจริง (เช่น pcap ดิบ หรือ dataset อื่นที่ resolution สูงกว่า)
  สคริปต์นี้จะเตือนอัตโนมัติถ้าเจอ timestamp resolution หยาบกว่าที่ตั้งไว้
"""

import os
import sys
import math
import warnings
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.cluster import KMeans

warnings.filterwarnings("ignore")
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)

# ─── Configuration ────────────────────────────────────────────
INTERVAL_SECONDS = 60   # ปรับได้ แต่ต่ำกว่า 60 จะไม่มีความหมายกับไฟล์ CIC-IDS2017 (resolution=นาที)
STD_MULTIPLIER = 2.0
MIN_IPS_FOR_HISTORY = 5
MIN_REQUESTS_FOR_HISTORY = 30


def calculate_shannon_entropy(ip_counts: dict) -> float:
    total = sum(ip_counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in ip_counts.values():
        p_i = count / total
        if p_i > 0:
            entropy -= p_i * math.log2(p_i)
    return entropy


def cluster_users_kmeans(ip_counts: dict) -> dict:
    ips = list(ip_counts.keys())
    if len(ips) < 3:
        return {
            "clusters": {ip: "attacker" for ip in ips},
            "labels": {},
            "attackers": ips,
            "suspicious": [],
            "centroids": {"attacker": sum(ip_counts.values()) / max(len(ips), 1)},
        }

    counts = np.array(list(ip_counts.values())).reshape(-1, 1)
    count_min = counts.min()
    count_max = counts.max()
    if count_max == count_min:
        return {
            "clusters": {ip: "normal" for ip in ips},
            "labels": {},
            "attackers": [],
            "suspicious": [],
        }

    counts_normalized = (counts - count_min) / (count_max - count_min)

    kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
    labels = kmeans.fit_predict(counts_normalized)

    centroids = kmeans.cluster_centers_.flatten()
    sorted_indices = np.argsort(centroids)

    cluster_map = {}
    cluster_map[sorted_indices[0]] = "normal"
    cluster_map[sorted_indices[1]] = "suspicious"
    cluster_map[sorted_indices[2]] = "attacker"

    result = {
        "clusters": {},
        "attackers": [],
        "suspicious": [],
        "centroids": {cluster_map[i]: float(centroids[i]) for i in range(3)},
    }

    for ip, label in zip(ips, labels):
        role = cluster_map[label]
        result["clusters"][ip] = role
        if role == "attacker":
            result["attackers"].append(ip)
        elif role == "suspicious":
            result["suspicious"].append(ip)

    return result


def find_column(df, candidates):
    for col in candidates:
        if col in df.columns:
            return col
    return None


def build_time_based_intervals(df, time_col, interval_seconds):
    """
    แบ่ง DataFrame เป็น interval ตามเวลาจริง (ไม่ใช่ตาม row count แบบ v1)

    Returns: (df ที่มี column 'interval' เพิ่มเข้ามา, warning message หรือ None)
    """
    df["_parsed_time"] = pd.to_datetime(df[time_col], errors="coerce")
    n_bad = df["_parsed_time"].isna().sum()
    if n_bad > 0:
        print(f"⚠️  Found {n_bad:,} rows with unparseable Timestamp (dropped)")
        df = df.dropna(subset=["_parsed_time"]).copy()

    # เช็ค resolution จริงของ timestamp เทียบกับ interval ที่ตั้งไว้
    unique_ts = df["_parsed_time"].sort_values().unique()
    warning = None
    if len(unique_ts) >= 2:
        diffs = pd.Series(unique_ts).diff().dropna()
        median_gap_seconds = diffs.median().total_seconds()
        if median_gap_seconds > interval_seconds:
            warning = (
                f"Timestamp resolution จริง (~{median_gap_seconds:.0f}s ต่อค่า) "
                f"หยาบกว่า INTERVAL_SECONDS ที่ตั้งไว้ ({interval_seconds}s) — "
                f"interval ที่ได้จะไม่ละเอียดตามที่ตั้งใจ ควรปรับ INTERVAL_SECONDS "
                f"ให้ >= {median_gap_seconds:.0f} หรือหา dataset ที่ timestamp ละเอียดกว่านี้"
            )

    t0 = df["_parsed_time"].min()
    df["interval"] = (
        (df["_parsed_time"] - t0).dt.total_seconds() // interval_seconds
    ).astype(int)

    return df, warning


def evaluate_dataset(file_path: str):
    print(f"📂 Reading dataset from: {file_path} ...")
    if file_path.endswith('.parquet'):
        df = pd.read_parquet(file_path)
    else:
        df = pd.read_csv(file_path, low_memory=False)

    df.columns = df.columns.str.strip()

    total_rows = len(df)
    print(f"📊 Total Dataset Records: {total_rows:,} rows (100% Loaded)")

    src_ip_col = find_column(
        df, ['Source IP', 'source_ip', 'src_ip', 'Source.IP', 'Src IP', 'IPV4_SRC_ADDR', 'src_addr', 'src']
    )
    if not src_ip_col:
        src_ip_col = find_column(df, ['src_port', 'Source Port', 'Port'])
        if src_ip_col:
            print(f"⚠️  No real Source IP column found — falling back to '{src_ip_col}'")
            print("   (Results may not reflect true attacker identity, since ports")
            print("    are randomly reassigned per connection even from the same host)")

    label_col = find_column(df, ['Label', 'label', 'Attack', 'Class', 'activity'])
    time_col = find_column(df, ['Timestamp', 'timestamp', 'time', 'frame.time_epoch', 'delta_start'])

    print(f"🔍 Selected Feature: '{src_ip_col}', Label: '{label_col}', Time: '{time_col}'")

    if not src_ip_col:
        print("❌ Error: Could not identify Source IP column in dataset.")
        return

    # ─── แบ่ง interval ───────────────────────────────────────
    if time_col:
        df, warning = build_time_based_intervals(df, time_col, INTERVAL_SECONDS)
        if warning:
            print(f"⚠️  {warning}")
        print(f"⏱️ Time-based intervals ({INTERVAL_SECONDS}s per interval)")
    else:
        print("⚠️  No Timestamp column found — falling back to row-count chunking (v1 behavior)")
        num_intervals = 100
        chunk_size = max(total_rows // num_intervals, 1000)
        df['interval'] = np.arange(total_rows) // chunk_size

    intervals = df.groupby('interval')
    print(f"⏱️ Total time intervals generated: {len(intervals)}")

    entropy_history = []
    results = []

    for idx, (interval_id, group) in enumerate(intervals):
        ip_counts = dict(Counter(group[src_ip_col]))
        n_unique_ips = len(ip_counts)
        total_reqs = sum(ip_counts.values())

        if n_unique_ips == 0 or total_reqs == 0:
            continue

        entropy = calculate_shannon_entropy(ip_counts)
        h_max = math.log2(n_unique_ips) if n_unique_ips > 1 else 1.0
        h_norm = entropy / h_max if h_max > 0 else 0.0

        if len(entropy_history) < 3:
            beta_lower = 0.5000
        else:
            mean_h = np.mean(entropy_history[-20:])
            std_h = np.std(entropy_history[-20:])
            beta_lower = max(mean_h - (STD_MULTIPLIER * std_h), 0.1)

        cluster_res = cluster_users_kmeans(ip_counts)
        kmeans_attackers_count = len(cluster_res["attackers"])

        entropy_attack_flag = h_norm < beta_lower
        kmeans_attack_flag = kmeans_attackers_count >= 5
        is_detected_attack = entropy_attack_flag or kmeans_attack_flag

        actual_label = "Benign"
        if label_col:
            most_common_label = group[label_col].mode()[0] if not group[label_col].empty else "Benign"
            actual_label = str(most_common_label)
        is_actual_attack = "benign" not in actual_label.lower() and "normal" not in actual_label.lower()

        results.append({
            "interval": idx + 1,
            "unique_ips": n_unique_ips,
            "total_reqs": total_reqs,
            "entropy": round(entropy, 4),
            "h_norm": round(h_norm, 4),
            "beta_lower": round(beta_lower, 4),
            "kmeans_attackers": kmeans_attackers_count,
            "detected_attack": is_detected_attack,
            "actual_attack": is_actual_attack,
            "actual_label": actual_label,
        })

        # อัปเดตประวัติเฉพาะช่วง Normal Traffic เท่านั้น (ไม่ปนเปื้อนช่วง Attack)
        if not is_detected_attack and n_unique_ips >= MIN_IPS_FOR_HISTORY and total_reqs >= MIN_REQUESTS_FOR_HISTORY:
            entropy_history.append(h_norm)
            if len(entropy_history) > 20:
                entropy_history = entropy_history[-20:]

    res_df = pd.DataFrame(results)

    print("\n" + "=" * 105)
    print(f"FULL SUMMARY RESULTS FOR ALL {len(res_df)} INTERVALS (Feature: '{src_ip_col}'):")
    print("=" * 105)
    print(res_df.to_string(index=False))

    output_csv = "evaluation_results_v2.csv"
    res_df.to_csv(output_csv, index=False)
    print(f"\n💾 Saved full results for all {len(res_df)} intervals to file: '{output_csv}'")

    if label_col:
        tp = len(res_df[(res_df['detected_attack']) & (res_df['actual_attack'])])
        fp = len(res_df[(res_df['detected_attack']) & (~res_df['actual_attack'])])
        tn = len(res_df[(~res_df['detected_attack']) & (~res_df['actual_attack'])])
        fn = len(res_df[(~res_df['detected_attack']) & (res_df['actual_attack'])])

        accuracy = (tp + tn) / len(res_df) if len(res_df) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print("\n" + "=" * 105)
        print(f"EVALUATION METRICS (Feature: '{src_ip_col}', Total Rows: {total_rows:,}):")
        print("=" * 105)
        print(f"True Positives (TP)  : {tp}")
        print(f"False Positives (FP) : {fp}")
        print(f"True Negatives (TN)  : {tn}")
        print(f"False Negatives (FN) : {fn}")
        print(f"Accuracy             : {accuracy*100:.2f}%")
        print(f"Precision            : {precision*100:.2f}%")
        print(f"Recall               : {recall*100:.2f}%")
        print(f"F1-Score             : {f1*100:.2f}%")
        print("=" * 105)

        # ─── Entity-level coverage (เพิ่มใหม่ใน v2) ──────────────
        # ตัวเลข TP/FP ข้างบนวัดที่ระดับ "interval" (ช่วงเวลา) เท่านั้น
        # ส่วนนี้วัดที่ระดับ "IP รายตัว" แยกต่างหาก เพื่อตอบคำถามที่
        # แตกต่างกัน: "จาก attacker IP ทั้งหมดใน dataset จับได้กี่ตัว"
        if is_actual_attack_available := (label_col is not None):
            all_attacker_ips_detected = set()
            for idx, (interval_id, group) in enumerate(df.groupby('interval')):
                ip_counts = dict(Counter(group[src_ip_col]))
                if len(ip_counts) == 0:
                    continue
                cluster_res = cluster_users_kmeans(ip_counts)
                all_attacker_ips_detected.update(cluster_res["attackers"])

            true_attacker_ips = set(
                df[~df[label_col].str.lower().isin(["benign", "normal"])][src_ip_col].unique()
            )
            caught = all_attacker_ips_detected & true_attacker_ips
            print(f"\nEntity-level (per unique IP, not per interval):")
            print(f"  Total ground-truth attacker IPs : {len(true_attacker_ips)}")
            print(f"  Detected (deduplicated)         : {len(caught)}")
            print(f"  Entity-level recall             : {len(caught)/len(true_attacker_ips)*100:.2f}%" if true_attacker_ips else "  N/A")
            print("=" * 105)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "Friday-WorkingHours-afternoon-DDos.pcap_ISCX.csv"
    evaluate_dataset(path)