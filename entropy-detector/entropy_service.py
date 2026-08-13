"""
Entropy-Based DDoS/EDoS Detection Service

อ้างอิงจาก Paper: "An entropy and machine learning based approach for DDoS attacks
detection in software defined networks" (PMC11300888)

การทำงาน:
1. อ่าน access log จาก Envoy sidecar ผ่าน kubectl logs
2. แบ่ง traffic เป็น time interval (T = 30 วินาที)
3. คำนวณ Shannon Entropy ของ source IP distribution
4. ถ้า Entropy < β_lower threshold → ตรวจพบการโจมตี
5. ใช้ K-means clustering แบ่ง users เป็น 3 กลุ่ม
6. อัพเดท blocked IP list
"""

import json
import math
import time
import os
import subprocess
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone

import numpy as np
from sklearn.cluster import KMeans

# ─── Configuration ────────────────────────────────────────────
INTERVAL_SECONDS = int(os.environ.get("INTERVAL_SECONDS", "30"))
ENTROPY_LOWER_THRESHOLD = float(os.environ.get("ENTROPY_LOWER_THRESHOLD", "0"))  # 0 = auto-calculate
BLOCKED_IPS_FILE = "/data/blocked_ips.json"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# K8s label selector for envoy sidecar pods
ENVOY_POD_LABEL = os.environ.get("ENVOY_POD_LABEL", "app=nginx-sidecar-target")
ENVOY_CONTAINER = os.environ.get("ENVOY_CONTAINER", "envoy-sidecar")
NAMESPACE = os.environ.get("NAMESPACE", "default")

# ─── Logging Setup ────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("entropy-detector")


# ─── Core Functions ───────────────────────────────────────────

def calculate_shannon_entropy(ip_counts: dict) -> float:
    """
    คำนวณ Shannon Entropy จาก IP request counts

    สูตร: H(X) = -Σ p_i * log2(p_i)

    โดย p_i = จำนวน request ของ IP_i / จำนวน request ทั้งหมด

    Parameters:
        ip_counts: dict ของ {ip: request_count}

    Returns:
        ค่า entropy (float) ยิ่งสูง = traffic กระจายสม่ำเสมอ (ปกติ)
                                 ยิ่งต่ำ = traffic ถูกครอบงำโดย IP น้อยตัว (โจมตี)
    """
    total_requests = sum(ip_counts.values())
    if total_requests == 0:
        return 0.0

    entropy = 0.0
    for count in ip_counts.values():
        if count > 0:
            p_i = count / total_requests
            entropy -= p_i * math.log2(p_i)

    return entropy


def calculate_max_entropy(n_unique_ips: int) -> float:
    """
    คำนวณค่า Entropy สูงสุดที่เป็นไปได้ (กรณีทุก IP ส่งเท่ากันหมด)

    H_max = log2(n)

    Parameters:
        n_unique_ips: จำนวน unique IPs

    Returns:
        ค่า max entropy
    """
    if n_unique_ips <= 1:
        return 0.0
    return math.log2(n_unique_ips)


def normalize_entropy(entropy: float, n_unique_ips: int) -> float:
    """
    Normalize entropy เป็นค่า 0-1

    H_normalized = H(X) / H_max = H(X) / log2(n)

    Parameters:
        entropy: ค่า entropy ที่คำนวณได้
        n_unique_ips: จำนวน unique IPs

    Returns:
        ค่า normalized entropy (0-1)
        1.0 = กระจายสม่ำเสมอสมบูรณ์
        0.0 = IP เดียวครอบงำทั้งหมด
    """
    max_ent = calculate_max_entropy(n_unique_ips)
    if max_ent == 0:
        return 0.0
    return entropy / max_ent


def calculate_dynamic_threshold(history: list, std_multiplier: float = 2.0) -> float:
    """
    คำนวณ β_lower threshold แบบ dynamic จาก entropy history

    β_lower = mean(H) - (std_multiplier * std(H))

    ใช้หลักการ: ถ้า entropy ลดลงต่ำกว่า 2 standard deviations
    จากค่าเฉลี่ย → ถือว่าผิดปกติ

    Parameters:
        history: list ของค่า normalized entropy ย้อนหลัง
        std_multiplier: จำนวนเท่าของ standard deviation

    Returns:
        ค่า threshold (β_lower)
    """
    if len(history) < 3:
        return 0.5  # default threshold ก่อนมีข้อมูลเพียงพอ

    mean_h = np.mean(history)
    std_h = np.std(history)

    threshold = mean_h - (std_multiplier * std_h)
    return max(threshold, 0.1)  # ต่ำสุด 0.1 ไม่ให้ threshold ติดลบ


def cluster_users_kmeans(ip_counts: dict) -> dict:
    """
    ใช้ K-means clustering แบ่ง users เป็น 3 กลุ่ม ตาม paper:
    - Cluster 0: Normal users (request rate ต่ำ)
    - Cluster 1: Suspicious users (request rate กลาง)
    - Cluster 2: Attackers (request rate สูง)

    Parameters:
        ip_counts: dict ของ {ip: request_count}

    Returns:
        dict ของ {ip: cluster_label}
        พร้อม metadata ของแต่ละ cluster
    """
    ips = list(ip_counts.keys())

    # กรณีมี IP น้อยกว่า 3 ตัว (เช่น โดน IP เดียวถล่ม 30,000 requests)
    if len(ips) < 3:
        return {
            "clusters": {ip: "attacker" for ip in ips},
            "labels": {},
            "attackers": ips,
            "suspicious": [],
            "centroids": {"attacker": sum(ip_counts.values()) / len(ips)},
        }

    counts = np.array(list(ip_counts.values())).reshape(-1, 1)

    # Normalize counts (Min-Max normalization ตาม paper)
    count_min = counts.min()
    count_max = counts.max()
    if count_max == count_min:
        # ทุก IP ส่งเท่ากัน
        return {
            "clusters": {ip: "normal" for ip in ips},
            "labels": {},
            "attackers": [],
            "suspicious": [],
        }

    counts_normalized = (counts - count_min) / (count_max - count_min)

    # K-means with k=3
    kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
    labels = kmeans.fit_predict(counts_normalized)

    # จัดกลุ่มตาม centroid: cluster ที่ centroid สูงสุด = attackers
    centroids = kmeans.cluster_centers_.flatten()
    sorted_indices = np.argsort(centroids)  # ascending

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


def collect_envoy_logs(since_seconds: int) -> list:
    """
    เก็บ access log จาก Envoy sidecar pods ผ่าน kubectl

    Parameters:
        since_seconds: ดึง log ย้อนหลังกี่วินาที

    Returns:
        list ของ parsed log entries
    """
    logs = []

    try:
        # ดึง pod names
        cmd_pods = [
            "kubectl", "get", "pods",
            "-n", NAMESPACE,
            "-l", ENVOY_POD_LABEL,
            "-o", "jsonpath={.items[*].metadata.name}",
        ]
        result = subprocess.run(cmd_pods, capture_output=True, text=True, timeout=10)
        pod_names = result.stdout.strip().split()

        if not pod_names:
            logger.warning("No envoy pods found with label: %s", ENVOY_POD_LABEL)
            return logs

        logger.info("Found %d envoy pods", len(pod_names))

        for pod in pod_names:
            try:
                cmd_logs = [
                    "kubectl", "logs", pod,
                    "-n", NAMESPACE,
                    "-c", ENVOY_CONTAINER,
                    f"--since={since_seconds}s",
                ]
                result = subprocess.run(
                    cmd_logs, capture_output=True, text=True, timeout=30
                )

                for line in result.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        if "downstream_remote_address_no_port" in entry:
                            logs.append(entry)
                    except json.JSONDecodeError:
                        continue

            except subprocess.TimeoutExpired:
                logger.warning("Timeout collecting logs from pod: %s", pod)
            except Exception as e:
                logger.error("Error collecting logs from pod %s: %s", pod, e)

    except Exception as e:
        logger.error("Error listing pods: %s", e)

    return logs


def extract_ip_counts(log_entries: list) -> dict:
    """
    นับจำนวน request ต่อ source IP จาก log entries

    Parameters:
        log_entries: list ของ parsed JSON log entries

    Returns:
        dict ของ {source_ip: request_count}
    """
    ip_counts = Counter()
    for entry in log_entries:
        # ใช้ downstream_remote_address_no_port เป็น source IP
        src_ip = entry.get("downstream_remote_address_no_port", "")
        if src_ip and src_ip != "-":
            ip_counts[src_ip] += 1
    return dict(ip_counts)


def save_blocked_ips(blocked_ips: list):
    """บันทึก blocked IPs ลงไฟล์ JSON"""
    os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
    data = {
        "blocked_ips": blocked_ips,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    logger.info("Saved %d blocked IPs to %s", len(blocked_ips), BLOCKED_IPS_FILE)


def load_blocked_ips() -> list:
    """โหลด blocked IPs จากไฟล์"""
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            data = json.load(f)
            return data.get("blocked_ips", [])
    return []


# เก็บรายชื่อ IP ที่ถูกอัปเดตลง Envoy RBAC ไปแล้ว เพื่อไม่ให้สั่ง rollout restart ซ้ำ
applied_blocked_ips = set()


def load_currently_applied_ips_from_configmap() -> set:
    """อ่านรายชื่อ IP ที่มีอยู่ใน Envoy ConfigMap ปัจจุบัน"""
    configmap_name = os.environ.get("ENVOY_CONFIGMAP", "envoy-sidecar-config")
    existing_ips = set()
    try:
        cmd_get = ["kubectl", "get", "configmap", configmap_name, "-n", NAMESPACE, "-o", "json"]
        res = subprocess.run(cmd_get, capture_output=True, text=True, timeout=15)
        if res.returncode == 0:
            cm_data = json.loads(res.stdout)
            envoy_yaml_raw = cm_data.get("data", {}).get("envoy.yaml", "")
            if envoy_yaml_raw:
                import yaml
                envoy_config = yaml.safe_load(envoy_yaml_raw)
                listeners = envoy_config.get("static_resources", {}).get("listeners", [])
                for listener in listeners:
                    for chain in listener.get("filter_chains", []):
                        for f in chain.get("filters", []):
                            if f.get("name") == "envoy.filters.network.http_connection_manager":
                                for hf in f.get("typed_config", {}).get("http_filters", []):
                                    if hf.get("name") == "envoy.filters.http.rbac":
                                        policies = hf.get("typed_config", {}).get("rules", {}).get("policies", {})
                                        for pol in policies.values():
                                            for p in pol.get("principals", []):
                                                prefix = p.get("remote_ip", {}).get("address_prefix")
                                                if prefix:
                                                    existing_ips.add(prefix)
    except Exception as e:
        logger.warning("Could not pre-load applied IPs from ConfigMap: %s", e)
    return existing_ips


def apply_envoy_rbac_block(blocked_ips: list):
    """
    นำรายชื่อ blocked_ips ไปเพิ่มใน Envoy Sidecar ConfigMap (envoy.filters.http.rbac)
    และสั่ง rollout restart เฉพาะเมื่อมี IP ใหม่ที่ยังไม่เคยโดนบล็อกเท่านั้น!
    """
    global applied_blocked_ips

    if not blocked_ips:
        return

    # เช็คว่ามี IP ใหม่จริงหรือไม่
    new_ips = set(blocked_ips) - applied_blocked_ips
    if not new_ips:
        logger.info("ℹ️ IPs %s already blocked in Envoy. Skipping rollout restart.", blocked_ips)
        return

    logger.info("🚫 Found %d NEW IPs to block: %s. Updating Envoy RBAC...", len(new_ips), list(new_ips))

    configmap_name = os.environ.get("ENVOY_CONFIGMAP", "envoy-sidecar-config")
    target_deployment = os.environ.get("TARGET_DEPLOYMENT", "nginx-edos-sidecar-target")

    try:
        # 1. ดึง ConfigMap ปัจจุบัน
        cmd_get = ["kubectl", "get", "configmap", configmap_name, "-n", NAMESPACE, "-o", "json"]
        res = subprocess.run(cmd_get, capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            logger.error("Failed to fetch ConfigMap %s: %s", configmap_name, res.stderr)
            return

        cm_data = json.loads(res.stdout)
        envoy_yaml_raw = cm_data.get("data", {}).get("envoy.yaml", "")
        if not envoy_yaml_raw:
            logger.error("No envoy.yaml found in ConfigMap %s", configmap_name)
            return

        # 2. Parse YAML
        import yaml
        envoy_config = yaml.safe_load(envoy_yaml_raw)

        # รวม IP เก่าและ IP ใหม่ทั้งหมด
        all_target_ips = sorted(list(applied_blocked_ips.union(set(blocked_ips))))

        # 3. สร้าง RBAC filter principals
        principals = []
        for ip in all_target_ips:
            clean_ip = ip.split("/")[0]
            principals.append({
                "remote_ip": {
                    "address_prefix": clean_ip,
                    "prefix_len": 32
                }
            })

        rbac_filter = {
            "name": "envoy.filters.http.rbac",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
                "rules": {
                    "action": "DENY",
                    "policies": {
                        "entropy_blocked_attackers": {
                            "permissions": [{"any": True}],
                            "principals": principals
                        }
                    }
                }
            }
        }

        # 4. ค้นหา http_filters ใน envoy_config
        listeners = envoy_config.get("static_resources", {}).get("listeners", [])
        updated = False
        for listener in listeners:
            filter_chains = listener.get("filter_chains", [])
            for chain in filter_chains:
                filters = chain.get("filters", [])
                for f in filters:
                    if f.get("name") == "envoy.filters.network.http_connection_manager":
                        http_filters = f.get("typed_config", {}).get("http_filters", [])

                        # ลบ rbac filter เก่าถ้ามีอยู่แล้ว
                        http_filters = [hf for hf in http_filters if hf.get("name") != "envoy.filters.http.rbac"]

                        # แทรก rbac filter เป็นตัวแรกสุด
                        http_filters.insert(0, rbac_filter)

                        f["typed_config"]["http_filters"] = http_filters
                        updated = True

        if not updated:
            logger.error("Could not locate http_connection_manager in envoy.yaml")
            return

        # 5. แปลงกลับเป็น YAML string และอัปเดต ConfigMap
        updated_yaml_str = yaml.dump(envoy_config, default_flow_style=False)
        cm_data["data"]["envoy.yaml"] = updated_yaml_str

        # เขียน JSON ชั่วคราวไปอัปเดต
        temp_cm_file = "/tmp/updated_cm.json"
        with open(temp_cm_file, "w") as tf:
            json.dump(cm_data, tf)

        cmd_apply = ["kubectl", "apply", "-f", temp_cm_file]
        res_apply = subprocess.run(cmd_apply, capture_output=True, text=True, timeout=15)
        if res_apply.returncode == 0:
            logger.info("Successfully updated Envoy ConfigMap with %d blocked IPs!", len(all_target_ips))

            # อัปเดตชุดข้อมูล IP ที่บล็อกสำเร็จแล้ว
            applied_blocked_ips.update(all_target_ips)

            # 6. สั่ง Rollout Restart ให้ Envoy Pods โหลด Config ใหม่ (กระทำเฉพาะเมื่อมี IP ใหม่เพิ่มเข้ามาเท่านั้น)
            cmd_restart = ["kubectl", "rollout", "restart", f"deployment/{target_deployment}", "-n", NAMESPACE]
            subprocess.run(cmd_restart, capture_output=True, text=True, timeout=15)
            logger.info("Triggered rollout restart for %s to enforce NEW 403 blocks!", target_deployment)
        else:
            logger.error("Failed to apply updated ConfigMap: %s", res_apply.stderr)

    except Exception as e:
        logger.error("Error applying Envoy RBAC block: %s", e)


# ─── Main Detection Loop ─────────────────────────────────────

def main():
    global applied_blocked_ips

    logger.info("=" * 60)
    logger.info("Entropy-Based DDoS/EDoS Detection Service")
    logger.info("=" * 60)
    logger.info("Interval: %d seconds", INTERVAL_SECONDS)
    logger.info("Pod label: %s", ENVOY_POD_LABEL)
    logger.info("Container: %s", ENVOY_CONTAINER)
    logger.info("Namespace: %s", NAMESPACE)
    logger.info("=" * 60)

    # โหลด IP ที่เคยบล็อกไว้แล้วจาก ConfigMap ตั้งแต่เริ่มต้น
    applied_blocked_ips = load_currently_applied_ips_from_configmap()
    if applied_blocked_ips:
        logger.info("Pre-loaded %d already blocked IPs from ConfigMap: %s",
                    len(applied_blocked_ips), list(applied_blocked_ips))

    entropy_history = []      # เก็บ normalized entropy ย้อนหลัง
    all_blocked_ips = set()   # เก็บ blocked IPs สะสม
    interval_count = 0

    while True:
        interval_count += 1
        logger.info("-" * 40)
        logger.info("Interval #%d - Collecting logs...", interval_count)

        # 1. เก็บ log จาก envoy pods
        log_entries = collect_envoy_logs(since_seconds=INTERVAL_SECONDS)
        logger.info("Collected %d log entries", len(log_entries))

        if len(log_entries) == 0:
            logger.info("No traffic in this interval, sleeping...")
            time.sleep(INTERVAL_SECONDS)
            continue

        # 2. นับ request ต่อ IP
        ip_counts = extract_ip_counts(log_entries)
        n_unique_ips = len(ip_counts)
        total_requests = sum(ip_counts.values())

        logger.info("Unique IPs: %d, Total requests: %d", n_unique_ips, total_requests)

        # แสดง top 10 IPs
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        logger.info("Top 10 IPs:")
        for ip, count in sorted_ips[:10]:
            logger.info("  %s: %d requests (%.1f%%)", ip, count, count / total_requests * 100)

        # 3. คำนวณ Shannon Entropy
        entropy = calculate_shannon_entropy(ip_counts)
        max_entropy = calculate_max_entropy(n_unique_ips)
        norm_entropy = normalize_entropy(entropy, n_unique_ips)

        logger.info("Shannon Entropy: %.4f", entropy)
        logger.info("Max possible Entropy: %.4f", max_entropy)
        logger.info("Normalized Entropy: %.4f (0=concentrated, 1=uniform)", norm_entropy)

        # 4. คำนวณ dynamic threshold จากประวัติที่มีอยู่ก่อนหน้า
        if ENTROPY_LOWER_THRESHOLD > 0:
            beta_lower = ENTROPY_LOWER_THRESHOLD
            logger.info("Using fixed β_lower: %.4f", beta_lower)
        else:
            beta_lower = calculate_dynamic_threshold(entropy_history)
            logger.info("Dynamic β_lower: %.4f (from %d historical intervals)",
                        beta_lower, len(entropy_history))

        # 5. ตรวจสอบว่าเป็นการโจมตีหรือไม่
        is_attack = norm_entropy < beta_lower

        # 6. อัปเดต history เฉพาะช่วง Normal Traffic เท่านั้น (ไม่ปนเปื้อนช่วง attack)
        MIN_IPS_FOR_HISTORY = int(os.environ.get("MIN_IPS_FOR_HISTORY", "5"))
        MIN_REQUESTS_FOR_HISTORY = int(os.environ.get("MIN_REQUESTS_FOR_HISTORY", "30"))

        if not is_attack and n_unique_ips >= MIN_IPS_FOR_HISTORY and total_requests >= MIN_REQUESTS_FOR_HISTORY:
            entropy_history.append(norm_entropy)
            logger.info("Added to normal history (IPs=%d, reqs=%d). History size: %d",
                        n_unique_ips, total_requests, len(entropy_history))
        else:
            if is_attack:
                logger.warning("Skipped history update: ATTACK DETECTED (h_norm=%.4f < beta_lower=%.4f)", norm_entropy, beta_lower)
            else:
                logger.warning("Skipped history update: insufficient traffic (IPs=%d < %d or reqs=%d < %d)",
                               n_unique_ips, MIN_IPS_FOR_HISTORY, total_requests, MIN_REQUESTS_FOR_HISTORY)

        # เก็บแค่ 20 intervals ล่าสุด
        if len(entropy_history) > 20:
            entropy_history = entropy_history[-20:]

        if is_attack:
            logger.warning("⚠️  ATTACK DETECTED! Normalized Entropy %.4f < β_lower %.4f",
                           norm_entropy, beta_lower)

            # 6. K-means clustering
            cluster_result = cluster_users_kmeans(ip_counts)

            if cluster_result["attackers"]:
                logger.warning("🔴 Attackers (%d IPs):", len(cluster_result["attackers"]))
                for ip in cluster_result["attackers"]:
                    logger.warning("    → %s (%d requests)", ip, ip_counts.get(ip, 0))
                    all_blocked_ips.add(ip)

            if cluster_result["suspicious"]:
                logger.warning("🟡 Suspicious (%d IPs):", len(cluster_result["suspicious"]))
                for ip in cluster_result["suspicious"]:
                    logger.warning("    ? %s (%d requests)", ip, ip_counts.get(ip, 0))

            # 7. บันทึก blocked IPs
            save_blocked_ips(list(all_blocked_ips))

            # 8. บล็อกทราฟฟิกจริงผ่าน Envoy RBAC Filter
            apply_envoy_rbac_block(list(all_blocked_ips))

            logger.warning("Total blocked IPs: %d", len(all_blocked_ips))

        else:
            logger.info("✅ Traffic normal. Entropy %.4f >= β_lower %.4f",
                        norm_entropy, beta_lower)

        # Summary
        logger.info("Interval #%d Summary: H=%.4f, H_norm=%.4f, β=%.4f, attack=%s, blocked=%d",
                     interval_count, entropy, norm_entropy, beta_lower,
                     is_attack, len(all_blocked_ips))

        # รอ interval ถัดไป
        logger.info("Sleeping %d seconds until next interval...", INTERVAL_SECONDS)
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()

