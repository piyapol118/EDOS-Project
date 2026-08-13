"""
Proof Dataset Attackers Script (CSV & Parquet Support with Source IP Priority)
พิสูจน์จำนวน Unique Source IPs ที่เป็น Attacker จริงใน Dataset (เช่น CIC-IDS2017 Friday DDoS)
"""

import sys
import pandas as pd

def prove_attackers(file_path: str):
    print("=" * 85)
    print(f"📊 PROOF OF ATTACKERS IN DATASET: {file_path}")
    print("=" * 85)

    if file_path.endswith('.parquet'):
        df = pd.read_parquet(file_path)
    else:
        df = pd.read_csv(file_path, low_memory=False)

    # ตัดช่องว่างหน้า-หลังคอลัมน์ (เช่น ' Source IP' -> 'Source IP')
    df.columns = df.columns.str.strip()

    # ค้นหาคอลัมน์ Source IP เป็นหลัก
    src_ip_col = None
    for col in ['Source IP', 'source_ip', 'src_ip', 'Source.IP', 'Src IP', 'IPV4_SRC_ADDR', 'src_addr', 'src']:
        if col in df.columns:
            src_ip_col = col
            break

    if not src_ip_col:
        for col in ['src_port', 'Source Port', 'Port']:
            if col in df.columns:
                src_ip_col = col
                break

    label_col = None
    for col in ['Label', 'label', 'Attack', 'Class', 'activity']:
        if col in df.columns:
            label_col = col
            break

    print(f"🔹 Total Dataset Rows   : {len(df):,}")
    print(f"🔹 Selected Feature     : '{src_ip_col}'")
    print(f"🔹 Label Column used    : '{label_col}'\n")

    # 1. ศึกษาแยกตาม Label
    labels = df[label_col].unique()
    for lbl in labels:
        sub_df = df[df[label_col] == lbl]
        unique_ips = sub_df[src_ip_col].nunique()
        print(f"📌 [{str(lbl).upper()}] Phase Statistics:")
        print(f"   - Total Packets/Flows : {len(sub_df):,} rows ({len(sub_df)/len(df)*100:.1f}%)")
        print(f"   - Unique {src_ip_col}s    : {unique_ips:,} unique IPs/Ports")
        print(f"   - Avg Packets per IP   : {len(sub_df)/max(unique_ips,1):.2f} reqs/IP")

        # Top 5 Most Active Source IPs in this Label
        top5 = sub_df[src_ip_col].value_counts().head(5)
        print(f"   - Top 5 Most Active IPs in [{lbl}]:")
        for ip, count in top5.items():
            print(f"       • IP {ip}: {count:,} requests ({count/len(sub_df)*100:.2f}%)")
        print("-" * 85)

    # 2. วิเคราะห์ส่วนเจาะจง Attack Phase
    attack_df = df[df[label_col].astype(str).str.lower().str.contains('ddos|dos|attack', na=False)]
    if not attack_df.empty:
        total_attack_ips = attack_df[src_ip_col].nunique()
        counts_per_ip = attack_df[src_ip_col].value_counts()
        heavy_attackers = counts_per_ip[counts_per_ip >= 10]
        light_attackers = counts_per_ip[counts_per_ip < 10]

        print("\n🔥 DETAILED PROOF OF ATTACKERS (ช่วงเกิด Attack จริง):")
        print(f"   - จำนวน Unique Attacker IPs ทั้งหมด : {total_attack_ips:,} IPs")
        print(f"   - Heavy Attackers (ยิงซ้ำตั้งแต่ 10 ครั้งขึ้นไป) : {len(heavy_attackers):,} IPs (รวม {heavy_attackers.sum():,} requests)")
        print(f"   - Light/Randomized Attackers (ยิงสุ่มไม่เกิน 10 ครั้ง)  : {len(light_attackers):,} IPs (รวม {light_attackers.sum():,} requests)")
        print("=" * 85)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "Friday-WorkingHours-afternoon-DDos.pcap_ISCX.csv"
    prove_attackers(path)
