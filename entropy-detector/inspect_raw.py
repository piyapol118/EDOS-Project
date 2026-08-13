"""
Inspect Raw Parquet/CSV Dataset
ดูข้อมูลดิบ ตัวอย่างแถว และสรุปข้อมูลใน Dataset
"""

import sys
import pandas as pd

# กำหนดขนาดการแสดงผลของ Pandas ให้เห็นครบทุกคอลัมน์
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', 20)
pd.set_option('display.width', 1000)

def inspect_file(file_path: str):
    print(f"📂 Opening raw file: {file_path} ...\n")

    if file_path.endswith('.parquet'):
        df = pd.read_parquet(file_path)
    else:
        df = pd.read_csv(file_path)

    print("=" * 80)
    print(f"📊 DATASET OVERVIEW:")
    print(f"   - Total Rows   : {len(df):,}")
    print(f"   - Total Columns: {len(df.columns)}")
    print("=" * 80)

    print("\n🔍 FIRST 5 ROWS (ตัวอย่าง 5 แถวแรก):")
    print("-" * 80)
    print(df.head(5))

    print("\n🏷️ LABEL DISTRIBUTION (สรุปประเภททราฟฟิกที่มีในไฟล์):")
    print("-" * 80)
    if 'label' in df.columns:
        print(df['label'].value_counts())
    elif 'Label' in df.columns:
        print(df['Label'].value_counts())
    elif 'activity' in df.columns:
        print(df['activity'].value_counts())
    else:
        print("No explicit label column found.")

    print("\n" + "=" * 80)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "bccc-cpacket-cloud-ddos-2024-merged.parquet"
    inspect_file(path)
