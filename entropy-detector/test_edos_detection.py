"""
EDoS Detection Test Script (v3 - Full Timeline 93 Intervals + Volume-Weighted Entropy)
========================================================================================
ผสม BENIGN traffic จาก CIC-IDS2017 ครบทั้ง 93 Intervals ตาม Timeline จริงของ Dataset
โดยแทรก Synthetic EDoS Yo-Yo Traffic เข้าไปในช่วงที่กำหนด (ค่าเริ่มต้น นาทีที่ 25)
และรัน Full Detection Pipeline: Volume-Weighted Entropy + K-Means + Ratio Verification

Pattern: [BENIGN ก่อน] -> [EDoS Yo-Yo + Benign Background] -> [BENIGN หลังจนจบ Dataset]

Usage:
    python test_edos_detection.py [dataset_path]
    python test_edos_detection.py Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
"""

import os
import sys
import math
import random
import warnings
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.cluster import KMeans

warnings.filterwarnings("ignore")
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)

# ─── Configuration (Tunable Parameters) ────────────────────────
INTERVAL_SECONDS         = 60       # ความยาว interval (วินาที)
STD_MULTIPLIER           = 2.0      # beta_lower = mean - STD_MULTIPLIER * std
MIN_IPS_FOR_HISTORY      = 5        # ขั้นต่ำ unique IPs เพื่ออัปเดต history
MIN_REQUESTS_FOR_HISTORY = 30       # ขั้นต่ำ total requests เพื่ออัปเดต history

# ─── EDoS Yo-Yo Parameters ─────────────────────────────────────
N_EDOS_IPS               = 17       # จำนวน Attacker IPs (จำลอง 17 pods จาก locust-heavy-yoyo)
EDOS_REQS_PER_IP_ON      = (80, 150)  # request range ต่อ IP ใน ON phase (ต่อ interval 60s)
EDOS_CYCLE_ON            = 2        # จำนวน interval ที่ ON (80s ~ 1-2 intervals @60s)
EDOS_CYCLE_OFF           = 1        # จำนวน interval ที่ OFF (40s ~ 1 interval @60s)
EDOS_DURATION_CYCLES     = 5        # จำนวน cycle ON-OFF ทั้งหมด (5 cycles x 3 = 15 intervals)
EDOS_IP_PREFIX           = "10.42.0"  # prefix สำหรับ Attacker IPs

# ─── Entropy Ratio Verification Parameters ─────────────────────
DELTA_ATTACK             = 0.95     # threshold สำหรับ Attacker cluster
DELTA_SUSPICIOUS         = 0.95     # threshold สำหรับ Suspicious cluster

# ─── Warmup / Baseline Training ────────────────────────────────
WARMUP_INTERVALS         = 3        # จำนวน interval แรกสำหรับฝึก baseline (ไม่ detect attack, สะสม H_norm เข้า history)

# ─── Volume-Weighted Entropy (แนวทางที่ 2) ─────────────────────
ENABLE_VOLUME_WEIGHTING  = True     # เปิด/ปิด การถ่วงน้ำหนัก Entropy ด้วยปริมาณ Request
VOLUME_TOLERANCE         = 3.0      # ยอมรับ traffic แกว่งตัวได้ 3.0 เท่าของ baseline ปกติโดยไม่ถูก penalty

# ─── Traffic Timeline Layout (ตรงตาม Timeline จริง 93 Intervals ของ Dataset) ──
EDOS_START_INTERVAL       = 25       # ตำแหน่ง Interval เริ่มแทรก EDoS (เช่น นาทีที่ 25)
# benign_before: interval 0 ถึง 24 (25 intervals)
# edos: 15 intervals (ON/OFF cycling)
# benign_after: interval 40 ถึง 92 (53 intervals จนจบ dataset ทั้งหมด ไม่ตัดทิ้ง)


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

def calculate_shannon_entropy(ip_counts: dict) -> float:
    """คำนวณ Shannon Entropy จาก request counts"""
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
    """K-Means clustering (k=3): Normal / Suspicious / Attacker"""
    ips = list(ip_counts.keys())
    if len(ips) < 3:
        return {
            "clusters": {ip: "attacker" for ip in ips},
            "attackers": ips,
            "suspicious": [],
            "normal": [],
            "centroids": {"attacker": sum(ip_counts.values()) / max(len(ips), 1)},
        }

    counts = np.array(list(ip_counts.values())).reshape(-1, 1)
    count_min = counts.min()
    count_max = counts.max()
    if count_max == count_min:
        return {
            "clusters": {ip: "normal" for ip in ips},
            "attackers": [],
            "suspicious": [],
            "normal": ips,
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
        "normal": [],
        "centroids": {cluster_map[i]: float(centroids[i]) for i in range(3)},
    }

    for ip, label in zip(ips, labels):
        role = cluster_map[label]
        result["clusters"][ip] = role
        if role == "attacker":
            result["attackers"].append(ip)
        elif role == "suspicious":
            result["suspicious"].append(ip)
        else:
            result["normal"].append(ip)

    return result


def verify_entropy_ratio(normal_ip_counts: dict, suspect_ip: str, suspect_count: int) -> float:
    """
    Entropy Ratio Verification (Algorithm 3.1 from Paper)
    ratio = H(X_normal U u_j) / H(X_normal)
    """
    h_normal = calculate_shannon_entropy(normal_ip_counts)
    if h_normal == 0:
        return 0.0

    merged = dict(normal_ip_counts)
    merged[suspect_ip] = merged.get(suspect_ip, 0) + suspect_count
    h_merged = calculate_shannon_entropy(merged)

    return h_merged / h_normal


def find_column(df, candidates):
    for col in candidates:
        if col in df.columns:
            return col
    return None


# ═══════════════════════════════════════════════════════════════
# Data Preparation
# ═══════════════════════════════════════════════════════════════

def load_benign_intervals(file_path: str):
    """
    โหลด CIC-IDS2017 dataset แล้วกรองเฉพาะ BENIGN
    คืนค่า list ของ dict {ip: count} ต่อ interval (ครบทั้ง 93 นาที)
    """
    print(f"Loading dataset: {file_path} ...")
    if file_path.endswith('.parquet'):
        df = pd.read_parquet(file_path)
    else:
        df = pd.read_csv(file_path, low_memory=False)

    df.columns = df.columns.str.strip()
    total_rows = len(df)
    print(f"Total records: {total_rows:,}")

    # หา columns
    src_ip_col = find_column(
        df, ['Source IP', 'source_ip', 'src_ip', 'Source.IP',
             'Src IP', 'IPV4_SRC_ADDR', 'src_addr', 'src']
    )
    label_col = find_column(df, ['Label', 'label', 'Attack', 'Class', 'activity'])
    time_col = find_column(df, ['Timestamp', 'timestamp', 'time', 'frame.time_epoch'])

    if not src_ip_col:
        print("ERROR: No Source IP column found!")
        sys.exit(1)

    print(f"Feature: '{src_ip_col}', Label: '{label_col}', Time: '{time_col}'")

    # กรอง BENIGN เท่านั้น
    if label_col:
        benign_mask = df[label_col].str.strip().str.lower().isin(["benign", "normal"])
        df = df[benign_mask].copy()
        print(f"After BENIGN filter: {len(df):,} rows ({len(df)/total_rows*100:.1f}%)")
    else:
        print("WARNING: No Label column found, using all rows as BENIGN")

    # แบ่ง interval ตามเวลาจริง (นาทีละ 1 interval)
    if time_col:
        df["_parsed_time"] = pd.to_datetime(df[time_col], errors="coerce")
        df = df.dropna(subset=["_parsed_time"]).copy()
        t0 = df["_parsed_time"].min()
        df["interval"] = (
            (df["_parsed_time"] - t0).dt.total_seconds() // INTERVAL_SECONDS
        ).astype(int)
    else:
        chunk_size = max(len(df) // 100, 500)
        df['interval'] = np.arange(len(df)) // chunk_size

    # สร้าง list ของ ip_counts ต่อ interval
    intervals_data = []
    for interval_id, group in df.groupby('interval'):
        ip_counts = dict(Counter(group[src_ip_col]))
        if len(ip_counts) > 0 and sum(ip_counts.values()) > 0:
            intervals_data.append(ip_counts)

    print(f"Total BENIGN intervals generated: {len(intervals_data)}")
    return intervals_data


def generate_edos_yoyo_traffic():
    """
    สังเคราะห์ EDoS Yo-Yo traffic ตามพฤติกรรม locust-heavy-yoyo.yaml
    
    คืนค่า list ของ (ip_counts_dict, phase_label)
    phase_label = "edos_on" หรือ "edos_off"
    """
    attacker_ips = [f"{EDOS_IP_PREFIX}.{50 + i}" for i in range(N_EDOS_IPS)]
    edos_intervals = []

    for cycle in range(EDOS_DURATION_CYCLES):
        # ON phase
        for _ in range(EDOS_CYCLE_ON):
            ip_counts = {}
            for ip in attacker_ips:
                # สุ่มจำนวน request ต่อ IP + rate factor (0.75x - 1.35x ตาม locust config)
                rate_factor = random.uniform(0.75, 1.35)
                base_reqs = random.randint(*EDOS_REQS_PER_IP_ON)
                ip_counts[ip] = int(base_reqs * rate_factor)
            edos_intervals.append((ip_counts, "edos_on"))

        # OFF phase
        for _ in range(EDOS_CYCLE_OFF):
            edos_intervals.append(({}, "edos_off"))

    print(f"Generated EDoS Yo-Yo: {len(edos_intervals)} intervals "
          f"({EDOS_DURATION_CYCLES} cycles x ({EDOS_CYCLE_ON} ON + {EDOS_CYCLE_OFF} OFF))")
    print(f"  Attacker IPs: {attacker_ips[0]} - {attacker_ips[-1]} ({N_EDOS_IPS} IPs)")

    return edos_intervals, attacker_ips


def merge_traffic(benign_intervals, edos_intervals):
    """
    ผสม Traffic ให้ครบตาม Timeline จริงของ Dataset (ครบทั้ง 93 intervals เหมือน test_kaggle_entropy.py):
    1. ก้อน A: BENIGN ก่อน EDoS (interval 0 ถึง EDOS_START_INTERVAL - 1)
    2. ก้อน EDoS: ผสม EDoS กับ Benign background (ช่วง EDOS_START_INTERVAL)
    3. ก้อน B: BENIGN หลัง EDoS (ใช้ทุก interval ที่เหลือจนจบ Dataset ทั้งหมด ไม่ตัดทิ้ง)
    """
    n_total_benign = len(benign_intervals)
    n_edos = len(edos_intervals)

    start_idx = min(EDOS_START_INTERVAL, max(0, n_total_benign - n_edos))

    merged = []

    # ก้อน A: BENIGN ก่อน EDoS
    for i in range(start_idx):
        merged.append((benign_intervals[i], False, "benign_before"))

    # ก้อน EDoS: ผสม Benign background + EDoS attacker traffic
    for j, (edos_ip_counts, edos_phase) in enumerate(edos_intervals):
        bg_idx = start_idx + j
        if bg_idx < n_total_benign:
            bg_counts = dict(benign_intervals[bg_idx])
        else:
            bg_counts = {}

        if edos_phase == "edos_on":
            combined = dict(bg_counts)
            for ip, count in edos_ip_counts.items():
                combined[ip] = combined.get(ip, 0) + count
            merged.append((combined, True, "edos_on"))
        else:
            merged.append((bg_counts, False, "edos_off"))

    # ก้อน B: BENIGN หลัง EDoS (ใช้ทุก interval ที่เหลือจนจบ Dataset ทั้งหมด)
    after_start = start_idx + n_edos
    for k in range(after_start, n_total_benign):
        merged.append((benign_intervals[k], False, "benign_after"))

    return merged


# ═══════════════════════════════════════════════════════════════
# Detection Pipeline
# ═══════════════════════════════════════════════════════════════

def run_detection(merged_traffic, attacker_ips_set):
    """
    รัน Full Detection Pipeline ทุก interval:
    1. Entropy -> Dynamic Threshold (beta_lower) -> Volume Weighting
    2. Attack Detection (ตรวจจับตามปกติทุก interval ตั้งแต่ต้น)
    3. K-Means clustering (เมื่อพบ Attack)
    4. Entropy Ratio Verification (Loop Check)
    """
    entropy_history = []
    request_history = []
    all_blocked_ips = set()
    results = []

    for idx, (ip_counts, is_actual_attack, phase) in enumerate(merged_traffic):
        interval_num = idx + 1
        n_unique_ips = len(ip_counts)
        total_reqs = sum(ip_counts.values())

        if n_unique_ips == 0 or total_reqs == 0:
            results.append({
                "interval": interval_num,
                "phase": phase,
                "unique_ips": 0,
                "total_reqs": 0,
                "h_norm": 0.0,
                "h_score": 0.0,
                "vol_factor": 1.0,
                "beta_lower": 0.5,
                "detected": False,
                "actual_attack": is_actual_attack,
                "kmeans_attackers": 0,
                "ratio_confirmed": 0,
                "ratio_cleared": 0,
                "newly_blocked": 0,
            })
            continue

        # 1. Shannon Entropy
        entropy = calculate_shannon_entropy(ip_counts)
        h_max = math.log2(n_unique_ips) if n_unique_ips > 1 else 1.0
        h_norm = entropy / h_max if h_max > 0 else 0.0

        # Volume-Weighted Entropy (แนวทางที่ 2)
        if ENABLE_VOLUME_WEIGHTING and len(request_history) >= 3:
            baseline_reqs = float(np.mean(request_history[-20:]))
            # ถ้า request พุ่งเกิน baseline * tolerance จะคำนวณ penalty factor (< 1.0)
            volume_factor = min(1.0, (baseline_reqs * VOLUME_TOLERANCE) / max(total_reqs, 1))
            h_score = h_norm * volume_factor
        else:
            volume_factor = 1.0
            h_score = h_norm

        # 2. Dynamic Threshold (beta_lower)
        if len(entropy_history) < 3:
            beta_lower = 0.5000
        else:
            mean_h = np.mean(entropy_history[-20:])
            std_h = max(np.std(entropy_history[-20:]), 0.05)  # min std floor
            beta_lower = min(max(mean_h - (STD_MULTIPLIER * std_h), 0.1), 0.70)  # cap ceiling

        # 3. Warmup Phase vs Detection Phase
        is_warmup = interval_num <= WARMUP_INTERVALS

        if is_warmup:
            # ช่วง Warmup (ฝึก): ไม่ detect attack เลย สะสม baseline H_score และ total_reqs เข้า history
            is_detected_attack = False
            if n_unique_ips >= MIN_IPS_FOR_HISTORY and total_reqs >= MIN_REQUESTS_FOR_HISTORY:
                entropy_history.append(h_score)
                request_history.append(total_reqs)
                if len(entropy_history) > 20:
                    entropy_history = entropy_history[-20:]
                if len(request_history) > 20:
                    request_history = request_history[-20:]
        else:
            # ช่วงทดสอบจริง: ตรวจจับ attack เมื่อ H_score < beta_lower
            is_detected_attack = h_score < beta_lower

            # อัปเดตประวัติเฉพาะช่วงที่เป็น Normal Traffic เท่านั้น
            if not is_detected_attack and n_unique_ips >= MIN_IPS_FOR_HISTORY and total_reqs >= MIN_REQUESTS_FOR_HISTORY:
                entropy_history.append(h_score)
                request_history.append(total_reqs)
                if len(entropy_history) > 20:
                    entropy_history = entropy_history[-20:]
                if len(request_history) > 20:
                    request_history = request_history[-20:]

        # 5. K-Means + Ratio Verification (only when attack detected)
        kmeans_attackers = 0
        ratio_confirmed = 0
        ratio_cleared = 0
        newly_blocked = 0
        ratio_details = []

        if is_detected_attack and n_unique_ips >= 3:
            cluster_result = cluster_users_kmeans(ip_counts)
            kmeans_attackers = len(cluster_result["attackers"])

            # แยก normal cluster ip_counts
            normal_ip_counts = {
                ip: ip_counts[ip]
                for ip in cluster_result.get("normal", [])
                if ip in ip_counts
            }

            # Ratio Verification: ทดสอบทุก IP จาก Attacker + Suspicious
            suspects = []
            for ip in cluster_result["attackers"]:
                suspects.append((ip, ip_counts[ip], "attacker", DELTA_ATTACK))
            for ip in cluster_result["suspicious"]:
                suspects.append((ip, ip_counts[ip], "suspicious", DELTA_SUSPICIOUS))

            for suspect_ip, suspect_count, cluster_name, delta in suspects:
                if len(normal_ip_counts) > 0:
                    ratio = verify_entropy_ratio(normal_ip_counts, suspect_ip, suspect_count)
                else:
                    ratio = 0.0  # ไม่มี normal cluster -> ถือว่าทุกคนผิดปกติ

                if ratio < delta:
                    # Confirmed Attacker
                    ratio_confirmed += 1
                    if suspect_ip not in all_blocked_ips:
                        all_blocked_ips.add(suspect_ip)
                        newly_blocked += 1
                    ratio_details.append((suspect_ip, suspect_count, cluster_name, ratio, "BLOCKED"))
                else:
                    # Cleared
                    ratio_cleared += 1
                    ratio_details.append((suspect_ip, suspect_count, cluster_name, ratio, "CLEARED"))

        results.append({
            "interval": interval_num,
            "phase": f"{phase} (warmup)" if is_warmup else phase,
            "unique_ips": n_unique_ips,
            "total_reqs": total_reqs,
            "h_norm": round(h_norm, 4),
            "h_score": round(h_score, 4),
            "vol_factor": round(volume_factor, 4),
            "beta_lower": round(beta_lower, 4),
            "detected": is_detected_attack,
            "actual_attack": is_actual_attack,
            "kmeans_attackers": kmeans_attackers,
            "ratio_confirmed": ratio_confirmed,
            "ratio_cleared": ratio_cleared,
            "newly_blocked": newly_blocked,
        })

        # Logging per interval
        status = "WARMUP" if is_warmup else ("ATTACK" if is_detected_attack else "Normal")
        actual = "EDoS-ON" if is_actual_attack else phase
        marker = ""
        if is_warmup:
            marker = " WARMUP (TN)"
        elif is_detected_attack and is_actual_attack:
            marker = " TP"
        elif is_detected_attack and not is_actual_attack:
            marker = " FP ***"
        elif not is_detected_attack and is_actual_attack:
            marker = " FN !!!"
        else:
            marker = " TN"

        vf_str = f" H_score={h_score:.4f} (vf={volume_factor:.2f})" if ENABLE_VOLUME_WEIGHTING else ""
        print(f"  [{interval_num:3d}] {phase:15s} | IPs={n_unique_ips:4d} Reqs={total_reqs:6d} | "
              f"H_norm={h_norm:.4f}{vf_str} beta={beta_lower:.4f} | "
              f"Detect={status:6s} Actual={actual:12s} |{marker}")

        if ratio_details:
            for s_ip, s_count, s_cluster, s_ratio, s_verdict in ratio_details:
                is_true_attacker = s_ip in attacker_ips_set
                ip_label = "ATK" if is_true_attacker else "NRM"
                print(f"        ratio: {s_ip} ({s_cluster}, {s_count} reqs, [{ip_label}]) "
                      f"-> ratio={s_ratio:.4f} -> {s_verdict}")

    return results, all_blocked_ips


# ═══════════════════════════════════════════════════════════════
# Metrics & Output
# ═══════════════════════════════════════════════════════════════

def print_metrics(results, all_blocked_ips, attacker_ips_set):
    """คำนวณและแสดง Confusion Matrix + Metrics"""
    res_df = pd.DataFrame(results)

    print("\n" + "=" * 110)
    print("FULL INTERVAL RESULTS:")
    print("=" * 110)
    display_cols = ["interval", "phase", "unique_ips", "total_reqs", "h_norm",
                    "h_score", "vol_factor", "beta_lower", "detected", "actual_attack",
                    "kmeans_attackers", "ratio_confirmed", "ratio_cleared", "newly_blocked"]
    print(res_df[display_cols].to_string(index=False))

    # Interval-level Confusion Matrix
    tp = len(res_df[(res_df['detected']) & (res_df['actual_attack'])])
    fp = len(res_df[(res_df['detected']) & (~res_df['actual_attack'])])
    tn = len(res_df[(~res_df['detected']) & (~res_df['actual_attack'])])
    fn = len(res_df[(~res_df['detected']) & (res_df['actual_attack'])])

    total = len(res_df)
    accuracy  = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    print("\n" + "=" * 110)
    print("INTERVAL-LEVEL METRICS (ALL INTERVALS):")
    print("=" * 110)
    print(f"  Total Intervals    : {total}")
    print(f"    BENIGN intervals : {len(res_df[~res_df['actual_attack']])}")
    print(f"    EDoS-ON intervals: {len(res_df[res_df['actual_attack']])}")
    print(f"  True Positives (TP)  : {tp}")
    print(f"  False Positives (FP) : {fp}")
    print(f"  True Negatives (TN)  : {tn}")
    print(f"  False Negatives (FN) : {fn}")
    print(f"  Accuracy             : {accuracy*100:.2f}%")
    print(f"  Precision            : {precision*100:.2f}%")
    print(f"  Recall (TPR)         : {recall*100:.2f}%")
    print(f"  F1-Score             : {f1*100:.2f}%")
    print(f"  False Positive Rate  : {fpr*100:.2f}%")

    # Post-warmup metrics (Evaluation Phase strictly after training)
    eval_df = res_df[res_df["interval"] > WARMUP_INTERVALS]
    if len(eval_df) > 0:
        tp_e = len(eval_df[(eval_df['detected']) & (eval_df['actual_attack'])])
        fp_e = len(eval_df[(eval_df['detected']) & (~eval_df['actual_attack'])])
        tn_e = len(eval_df[(~eval_df['detected']) & (~eval_df['actual_attack'])])
        fn_e = len(eval_df[(~eval_df['detected']) & (eval_df['actual_attack'])])
        total_e = len(eval_df)
        acc_e  = (tp_e + tn_e) / total_e if total_e > 0 else 0
        prec_e = tp_e / (tp_e + fp_e) if (tp_e + fp_e) > 0 else 0
        rec_e  = tp_e / (tp_e + fn_e) if (tp_e + fn_e) > 0 else 0
        f1_e   = 2 * (prec_e * rec_e) / (prec_e + rec_e) if (prec_e + rec_e) > 0 else 0
        fpr_e  = fp_e / (fp_e + tn_e) if (fp_e + tn_e) > 0 else 0

        print("\n" + "=" * 110)
        print(f"POST-WARMUP EVALUATION METRICS (Intervals {WARMUP_INTERVALS+1} to {total}):")
        print("=" * 110)
        print(f"  Test Intervals     : {total_e}")
        print(f"  True Positives (TP)  : {tp_e}")
        print(f"  False Positives (FP) : {fp_e}")
        print(f"  True Negatives (TN)  : {tn_e}")
        print(f"  False Negatives (FN) : {fn_e}")
        print(f"  Accuracy             : {acc_e*100:.2f}%")
        print(f"  Precision            : {prec_e*100:.2f}%")
        print(f"  Recall (TPR)         : {rec_e*100:.2f}%")
        print(f"  F1-Score             : {f1_e*100:.2f}%")
        print(f"  False Positive Rate  : {fpr_e*100:.2f}%")

    # Entity-level (IP) Metrics
    blocked_true_attackers = all_blocked_ips & attacker_ips_set
    blocked_normal_ips = all_blocked_ips - attacker_ips_set

    print("\n" + "=" * 110)
    print("ENTITY-LEVEL (PER IP) METRICS:")
    print("=" * 110)
    print(f"  Total Attacker IPs (ground truth) : {len(attacker_ips_set)}")
    print(f"  Attacker IPs blocked (TP)         : {len(blocked_true_attackers)}")
    if attacker_ips_set:
        print(f"  Entity-level Recall               : {len(blocked_true_attackers)/len(attacker_ips_set)*100:.2f}%")
    print(f"  Normal IPs falsely blocked (FP)   : {len(blocked_normal_ips)}")
    if blocked_normal_ips:
        print(f"    FP IPs: {sorted(blocked_normal_ips)}")
    print(f"  Total blocked IPs                 : {len(all_blocked_ips)}")

    # Parameters Summary
    print("\n" + "=" * 110)
    print("PARAMETERS USED:")
    print("=" * 110)
    print(f"  WARMUP_INTERVALS       = {WARMUP_INTERVALS}")
    print(f"  ENABLE_VOLUME_WEIGHTING= {ENABLE_VOLUME_WEIGHTING}")
    print(f"  VOLUME_TOLERANCE       = {VOLUME_TOLERANCE}")
    print(f"  INTERVAL_SECONDS       = {INTERVAL_SECONDS}")
    print(f"  STD_MULTIPLIER         = {STD_MULTIPLIER}")
    print(f"  DELTA_ATTACK           = {DELTA_ATTACK}")
    print(f"  DELTA_SUSPICIOUS       = {DELTA_SUSPICIOUS}")
    print(f"  N_EDOS_IPS             = {N_EDOS_IPS}")
    print(f"  EDOS_REQS_PER_IP_ON    = {EDOS_REQS_PER_IP_ON}")
    print(f"  EDOS_CYCLE_ON          = {EDOS_CYCLE_ON}")
    print(f"  EDOS_CYCLE_OFF         = {EDOS_CYCLE_OFF}")
    print(f"  EDOS_DURATION_CYCLES   = {EDOS_DURATION_CYCLES}")
    print(f"  EDOS_START_INTERVAL    = {EDOS_START_INTERVAL}")
    print(f"  TOTAL_DATASET_INTERVALS= {len(res_df)}")
    print("=" * 110)

    # Save CSV
    output_csv = "edos_detection_results.csv"
    res_df.to_csv(output_csv, index=False)
    print(f"\nSaved results to: {output_csv}")

    return res_df


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def main():
    print("=" * 110)
    print("EDoS Detection Test Script (v3 - Full 93-Interval Timeline)")
    print("Pattern: [BENIGN ก่อน] -> [EDoS Yo-Yo + Background] -> [BENIGN หลังจนจบ Dataset]")
    print("=" * 110)

    # 1. Load BENIGN traffic
    file_path = sys.argv[1] if len(sys.argv) > 1 else "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    benign_intervals = load_benign_intervals(file_path)

    # 2. Generate EDoS Yo-Yo traffic
    edos_intervals, attacker_ips = generate_edos_yoyo_traffic()
    attacker_ips_set = set(attacker_ips)

    # 3. Merge: Full 93 intervals timeline
    merged = merge_traffic(benign_intervals, edos_intervals)

    total_intervals = len(merged)
    n_edos_on = sum(1 for _, actual, phase in merged if actual)
    n_benign = total_intervals - n_edos_on
    n_edos_off = sum(1 for _, _, phase in merged if phase == "edos_off")

    print(f"\n--- Merged Traffic Layout ---")
    print(f"  Total intervals   : {total_intervals}")
    print(f"  BENIGN intervals  : {n_benign} (including {n_edos_off} EDoS-OFF)")
    print(f"  EDoS-ON intervals : {n_edos_on}")
    print(f"  Attacker IPs      : {attacker_ips[0]} - {attacker_ips[-1]} ({len(attacker_ips)} IPs)")
    print()

    # 4. Run Detection Pipeline
    print("--- Running Detection Pipeline ---")
    results, all_blocked_ips = run_detection(merged, attacker_ips_set)

    # 5. Print Metrics
    print_metrics(results, all_blocked_ips, attacker_ips_set)


if __name__ == "__main__":
    main()
