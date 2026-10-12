"""
Debug Script: พิสูจน์การเดินทางของ entropy_history และ beta_lower ทีละ interval
จำลองกระบวนการเดียวกับ test_kaggle_entropy_benign.py แต่แสดง
"สิ่งที่อยู่ใน sliding window 20 ค่า ณ ขณะนั้น" ให้เห็นชัดเจน
"""

import math

def mean(lst):
    return sum(lst) / len(lst) if lst else 0.0

def std(lst):
    if len(lst) < 2:
        return 0.0
    m = mean(lst)
    return math.sqrt(sum((x - m) ** 2 for x in lst) / len(lst))

STD_MULTIPLIER = 2.0
MIN_IPS_FOR_HISTORY = 5
MIN_REQUESTS_FOR_HISTORY = 30

# ข้อมูลจาก benign_entropy.txt (interval, unique_ips, total_reqs, h_norm, detected_attack)
data = [
    (1,  122, 1728, 0.4291, True),
    (2,  159, 1905, 0.4912, True),
    (3,   66,  386, 0.7540, False),
    (4,  123, 1402, 0.5181, False),
    (5,  105,  873, 0.5805, False),
    (6,   79,  566, 0.5922, False),
    (7,   75,  673, 0.4958, False),
    (8,   80,  995, 0.5251, False),
    (9,  110, 1040, 0.4958, False),
    (10,  87,  591, 0.6038, False),
    (11,  94, 1386, 0.5379, False),
    (12,  88,  832, 0.5073, False),
    (13,  81,  976, 0.5091, False),
    (14,  39,  198, 0.7636, False),
    (15,  29,  103, 0.8840, False),
    (16,  37,  400, 0.6023, False),
    (17,  41,  757, 0.4281, False),
    (18,  29,  188, 0.7157, False),
    (19,  24,  309, 0.5587, False),
    (20,  33,  253, 0.7365, False),
    (21,  32,  198, 0.6874, False),
    (22,  65, 1210, 0.4924, False),
    (23,  29,  114, 0.8452, False),
    (24,  47,  973, 0.4611, False),
    (25,  56,  212, 0.8162, False),
    (26,  18,  601, 0.3101, True),   # detected_attack=True → ไม่เข้า history
    (27,  55, 1233, 0.4574, False),
    (28,  56, 2525, 0.3456, False),
    (29, 117, 3155, 0.3550, False),
    (30,  86, 2853, 0.3816, False),
    (31, 105, 2631, 0.3651, False),
    (32,  70, 2304, 0.3329, False),
    (33,  78, 1485, 0.2204, False),
    (34,  55, 2010, 0.2698, False),
    (35,  35, 1730, 0.2225, False),
    (36,  33, 2283, 0.3016, False),
    (37,  24, 2253, 0.1742, False),
    (38,  42, 2746, 0.2884, False),
    (39,  89, 2625, 0.3222, False),
    (40,  55, 2707, 0.3064, False),
    (41,  43, 2274, 0.1442, False),
    (42,  67, 3138, 0.3100, False),
    (43,  47, 2295, 0.2662, False),
    (44, 135, 4785, 0.4354, False),
    (45, 104, 2819, 0.3319, False),
    (46,  87, 2777, 0.2816, False),
    (47,  90, 1461, 0.4673, False),
    (48,  63,  274, 0.6762, False),
    (49,  49,  394, 0.3456, False),  # *** total_reqs=394 >= 30 ✓, unique_ips=49 >= 5 ✓
    (50,  72,  763, 0.6185, False),
    (51,  70,  857, 0.4035, False),
    (52,  39,  346, 0.6738, False),
    (53,  81,  706, 0.5995, False),
    (54,  97, 1565, 0.4551, False),
    (55,  62,  202, 0.8541, False),
    (56,  64,  375, 0.6599, False),
    (57,  42,  256, 0.8372, False),
    (58,  30,  650, 0.5882, False),
    (59,  42,  229, 0.7879, False),
    (60, 102, 1830, 0.2896, False),
]

entropy_history = []

print("=" * 140)
print(f"{'Int':>4} | {'H_norm':>7} | {'Detected':>8} | {'ips':>4} {'reqs':>5} | {'Saved?':>7} | {'History Len':>11} | {'Mean':>7} {'Std':>7} {'Mean-2Std':>9} | {'beta':>7} | Window Contents (20 values)")
print("=" * 140)

for interval, unique_ips, total_reqs, h_norm, detected_attack in data:
    # 1. คำนวณ beta_lower จาก history ที่มีอยู่ ณ ตอนนั้น (BEFORE update)
    if len(entropy_history) < 3:
        beta_lower = 0.5000
        mean_h = 0
        std_h = 0
        raw_calc = 0
    else:
        mean_h = mean(entropy_history[-20:])
        std_h = std(entropy_history[-20:])
        raw_calc = mean_h - (STD_MULTIPLIER * std_h)
        beta_lower = max(raw_calc, 0.1)

    # 2. เช็คเงื่อนไขว่าจะเก็บเข้า history หรือไม่
    saved = False
    reason = ""
    if detected_attack:
        reason = "SKIP (detected=True)"
    elif unique_ips < MIN_IPS_FOR_HISTORY:
        reason = f"SKIP (ips={unique_ips} < {MIN_IPS_FOR_HISTORY})"
    elif total_reqs < MIN_REQUESTS_FOR_HISTORY:
        reason = f"SKIP (reqs={total_reqs} < {MIN_REQUESTS_FOR_HISTORY})"
    else:
        entropy_history.append(h_norm)
        if len(entropy_history) > 20:
            entropy_history = entropy_history[-20:]
        saved = True
        reason = "SAVED"

    # 3. แสดงผล
    window_str = "[" + ", ".join(f"{v:.4f}" for v in entropy_history[-20:]) + "]"
    
    # เน้น interval ที่สนใจ
    marker = ""
    if 36 <= interval <= 60:
        marker = " <<<" if interval in [54, 55, 56, 57] else " <"
    
    print(f"{interval:4d} | {h_norm:7.4f} | {str(detected_attack):>8} | {unique_ips:4d} {total_reqs:5d} | {reason:>7} | {len(entropy_history):11d} | {mean_h:7.4f} {std_h:7.4f} {raw_calc:9.4f} | {beta_lower:7.4f} | {window_str}{marker}")

print("\n")
print("=" * 140)
print("ANALYSIS SUMMARY: Interval 54-57")
print("=" * 140)
print("""
ข้อสรุป: ทำไม Interval 54-57 มี H_norm สูง (0.45-0.85) แต่ beta_lower ยังคงเป็น 0.1000

1. beta_lower คำนวณจาก entropy_history[-20:] ซึ่งเป็น "ข้อมูลย้อนหลังที่เก็บสะสมมาก่อนหน้า"
   ไม่ใช่จากค่า H_norm ของ interval ปัจจุบัน

2. ตั้งแต่ Interval 28-46 มีค่า H_norm ต่ำมากติดกันยาวนาน (0.14-0.43)
   ค่าเหล่านี้ถูกเก็บเข้า history จนเต็ม 20 ค่า ทำให้:
   - Mean ≈ 0.30
   - Std  ≈ 0.08
   - Mean - 2*Std ≈ 0.14 → max(0.14, 0.1) → ได้ beta_lower = 0.1000 บ้าง 0.15 บ้าง

3. เมื่อ Interval 54-57 เข้ามาด้วย H_norm สูง (0.45-0.85)
   ค่าเหล่านี้ "ถูกเก็บเข้า history" แต่ต้องรอให้ค่าต่ำเก่าๆ ถูก "เลื่อนออก" ไปก่อน
   ซึ่งต้องใช้เวลาหลาย interval กว่า Mean จะดันตัวสูงขึ้นพอที่ทำให้ beta_lower ขยับ

4. กว่า beta_lower จะเริ่มขยับขึ้นจาก 0.1000 ก็ต้องรอจนถึง Interval 59 (0.1053)
   เพราะตอนนั้นค่า H_norm ต่ำเก่าๆ เริ่มถูกเตะออกจาก window 20 ค่า
   และถูกแทนที่ด้วยค่าสูงใหม่ๆ จาก Interval 47-59

สรุป: beta_lower มี "ความเฉื่อย (Inertia)" เพราะคำนวณจาก 20 ค่าในอดีต
ไม่ใช่จากค่าปัจจุบัน ทำให้ต้องใช้เวลาหลาย interval กว่าจะปรับตัวตาม
""")
