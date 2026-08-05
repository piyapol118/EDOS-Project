# Entropy-Based DDoS/EDoS Detection - Knowledge Document

> อ้างอิงจาก Paper: *"An entropy and machine learning based approach for DDoS attacks detection in software defined networks"*
> (DOI: 10.1038/s41598-024-67984-w, PMC11300888)

---

## 1. หลักการ Shannon Entropy สำหรับตรวจจับ DDoS

### 1.1 Entropy คืออะไร?
**Entropy** (เอนโทรปี) คือการวัด **ความสุ่ม/ความไม่แน่นอน** ของข้อมูล ยิ่งข้อมูลกระจายสม่ำเสมอ → Entropy ยิ่งสูง

### 1.2 สูตร Shannon Entropy

```
H(X) = -Σ p_i * log2(p_i)
```

โดย:
- X = เซตของ active users (source IPs) ใน time interval
- p_i = สัดส่วน request ของ user i ต่อ request ทั้งหมด
- n = จำนวน unique source IPs

### 1.3 การตีความค่า Entropy

| สถานการณ์ | Source IPs | Distribution | Entropy | ความหมาย |
|-----------|-----------|-------------|---------|----------|
| ปกติ | หลาย IP | กระจายสม่ำเสมอ | **สูง** | ผู้ใช้หลายคนเข้าใช้งานปกติ |
| DDoS (IP เดียว) | IP น้อย | กระจุกตัว | **ต่ำ** | IP ไม่กี่ตัวครอบงำ traffic |
| DDoS (Spoof IP) | IP ปลอมเยอะ | กระจายสม่ำเสมอ | **สูง** | ตรวจจับยาก! |

### 1.4 Normalized Entropy (0-1)

```
H_norm(X) = H(X) / log2(n)
```

- H_norm = 1.0 → ทุก IP ส่ง request เท่ากันหมด (กระจายสมบูรณ์)
- H_norm = 0.0 → IP เดียวส่ง request ทั้งหมด
- H_norm < β_lower → **ตรวจพบการโจมตี!**

---

## 2. ตัวอย่างการคำนวณ

### 2.1 กรณี Traffic ปกติ (5 IPs, ส่งเท่ากัน)
```
IP_A: 20 req, IP_B: 20 req, IP_C: 20 req, IP_D: 20 req, IP_E: 20 req
Total: 100 req

p_i = 20/100 = 0.2 (ทุก IP)

H(X) = -5 * (0.2 * log2(0.2))
     = -5 * (0.2 * -2.322)
     = -5 * (-0.4644)
     = 2.322

H_max = log2(5) = 2.322
H_norm = 2.322 / 2.322 = 1.0  <-- ปกติสมบูรณ์
```

### 2.2 กรณี DDoS Attack (1 IP ครอบงำ)
```
IP_A: 80 req, IP_B: 5 req, IP_C: 5 req, IP_D: 5 req, IP_E: 5 req
Total: 100 req

p_A = 0.8, p_B = p_C = p_D = p_E = 0.05

H(X) = -(0.8 * log2(0.8) + 4 * 0.05 * log2(0.05))
     = -(0.8 * -0.322 + 4 * 0.05 * -4.322)
     = -(-0.258 + (-0.864))
     = 1.122

H_norm = 1.122 / 2.322 = 0.483  <-- ต่ำกว่า threshold = ตรวจพบ!
```

### 2.3 กรณี Locust 50 Pods (ยิงเท่ากันหมด)
```
50 IPs * 150 req ต่อ interval (5 req/s * 30 วินาที)
Total: 7,500 req

p_i = 1/50 = 0.02 (ทุก IP)

H(X) = -50 * (0.02 * log2(0.02))
     = -50 * (0.02 * -5.644)
     = 5.644

H_max = log2(50) = 5.644
H_norm = 5.644 / 5.644 = 1.0  <-- ดูเหมือนปกติ!
```

> ข้อจำกัด: เมื่อ attacker ยิงจาก 50 pods ที่แต่ละ pod ส่ง rate เท่ากัน
> Entropy จะสูงมาก (เหมือน traffic ปกติ) ทำให้ entropy-based detection ตรวจจับได้ยาก
> วิธีแก้: ต้องใช้ K-means clustering ร่วมด้วย หรือเปรียบเทียบกับ baseline entropy ของ normal traffic

---

## 3. Algorithm จาก Paper

### 3.1 Detection Procedure (Algorithm 3.1)

```
Input:  Traffic logs ใน interval T
Output: รายชื่อ attacker IPs

1. นับ request ต่อ source IP -> ip_counts
2. Normalize frequencies (Min-Max)
3. คำนวณ Shannon Entropy H(X)
4. คำนวณ Normalized Entropy H_norm
5. IF H_norm < beta_lower THEN
     6. ทำ K-means clustering (k=3) บน normalized frequencies
     7. จัดกลุ่มเป็น: normal, suspicious, attacker
     8. ตรวจสอบ suspicious/attacker clusters:
        - คำนวณ entropy ratio change
        - IF ratio < delta_attack -> ยืนยันว่าเป็น attacker
     9. Block attacker IPs
   ELSE
     10. Traffic ปกติ ไม่ต้องทำอะไร
   END IF
11. รอ interval ถัดไป -> กลับข้อ 1
```

### 3.2 K-means Clustering (k=3)

Paper ใช้ K-means แบ่ง active users เป็น 3 กลุ่ม:

| Cluster | ลักษณะ | Request Rate | Action |
|---------|--------|-------------|--------|
| **Normal** | Centroid ต่ำสุด | ต่ำ-ปกติ | ปล่อยผ่าน |
| **Suspicious** | Centroid กลาง | สูงกว่าปกติ | เฝ้าระวัง |
| **Attacker** | Centroid สูงสุด | สูงมาก | **Block** |

### 3.3 Training Parameters

| Parameter | คำอธิบาย | ค่าที่แนะนำ |
|-----------|---------|------------|
| **T** (interval) | ขนาดของ time window | 30-120 วินาที |
| **beta_lower** | Entropy threshold สำหรับตรวจจับ | Dynamic: mean - 2*std |
| **delta_attack** | Entropy change threshold สำหรับ attacker cluster | 0.3-0.7 |
| **delta_susp** | Entropy change threshold สำหรับ suspicious cluster | 0.5-0.9 |

---

## 4. สถาปัตยกรรมระบบ (Architecture)

### 4.1 โครงสร้าง

```
locust-attacker (50 pods)
  - ยิง POST /api/login-simple
  - 5 users/pod, wait_time 0.05-0.3s
         |
         v
nginx-edos-sidecar-target (HPA: 1-10 pods)
  +----------------------+  +---------------------+
  | Envoy Sidecar        |  | Crypto Backend App  |
  | - Local Rate Limit   |->| - /api/login-simple |
  | - Access Logging     |  | - scrypt hashing    |
  | - TLS Termination    |  | - ECDSA verify      |
  +----------------------+  +---------------------+
         | (access logs via stdout)
         v
entropy-detector (1 pod)
  - ทุก 30 วินาที:
    1. ดึง access log จาก envoy sidecar pods
    2. คำนวณ Shannon Entropy
    3. ถ้า Entropy ต่ำ -> K-means clustering
    4. Block attacker IPs
```

### 4.2 Data Flow & Enforcement Mechanism

```
Envoy Access Log (JSON) -> kubectl logs -> Entropy Service
                                              |
                            +-----------------+
                            |                 |
                    +-------v-------+  +------v------+
                    |  IP Counting  |  |  Entropy    |
                    |  per interval |  |  Calculation|
                    +-------+-------+  +------+------+
                            |                 |
                            |     +-----------v-----------+
                            |     |  H_norm < beta_lower? |
                            |     +-----+----------+------+
                            |       Yes |          | No
                            |     +-----v-----+    |
                            +---->|  K-means  |    |
                                  |  (k=3)    |    |
                                  +-----+-----+    |
                                        |          |
                                  +-----v-----+    |
                                  | Attacker  |    |
                                  | Detected  |    |
                                  +-----+-----+    |
                                        |          |
                           +------------v------------+
                           |   Has NEW Attacker IP?  |
                           +-----+-------------+-----+
                             Yes |             | No
                +────────────────v─+         +─v────────────────────────+
                | 1. Update Envoy  |         | Skip Rollout Restart     |
                |    ConfigMap RBAC|         | (Prevent pod disruption) |
                | 2. Rollout       |         +──────────────────────────+
                |    Restart Envoy |
                |    (403 Block)   |
                +──────────────────+
```

---

## 5. ไฟล์ในโปรเจค

| ไฟล์ | คำอธิบาย |
|------|---------|
| `entropy-detector/entropy_service.py` | Python service หลัก - คำนวณ entropy + K-means |
| `entropy-detector/Dockerfile` | Docker image สำหรับ build |
| `entropy-detector/requirements.txt` | Python dependencies (numpy, scikit-learn) |
| `entropy-detector/entropy-detector.yaml` | K8s Deployment + RBAC |
| `locust-attacker.yaml` | Locust pods (50 replicas, 5 users/pod) |
| `nginx-edos-target.yaml` | Target pods (crypto backend + envoy sidecar) |
| `envoy-config.yaml` | Envoy sidecar config (access logging + local rate limit) |

---

## 6. Deploy Steps

### 6.1 Build Docker Image
```bash
cd entropy-detector
docker build -t entropy-detector:latest .
```

### 6.2 Deploy to K8s
```bash
kubectl apply -f entropy-detector.yaml
```

### 6.3 ดู Log ของ Entropy Detector
```bash
kubectl logs -f -l app=entropy-detector
```

### 6.4 ทดสอบ
```bash
# 1. Deploy locust attacker (50 pods)
kubectl apply -f locust-attacker.yaml

# 2. ดู entropy detector log
kubectl logs -f -l app=entropy-detector

# 3. ดูผลลัพธ์ - ค่า entropy ควรลดลงเมื่อ attack เริ่ม
```

---

## 7. ข้อจำกัดและข้อควรระวัง

### 7.1 Entropy ตรวจจับ Distributed Attack ได้ยาก
เมื่อ attacker ใช้หลาย IP (เช่น 50 pods) ยิงใน rate ใกล้เคียงกัน:
- Entropy จะสูง (เหมือน traffic ปกติ)
- ต้องเปรียบเทียบกับ **baseline entropy** ของ normal traffic
- ต้องดูการเปลี่ยนแปลงของ **จำนวน unique IPs** ร่วมด้วย

### 7.2 Dynamic Threshold
ใช้สูตร: `beta_lower = mean(H) - 2 * std(H)`
- ต้องมี historical data อย่างน้อย 3 intervals
- ช่วง 3 intervals แรกใช้ default threshold = 0.5

### 7.3 IP Spoofing
- ถ้า attacker spoof IP ด้วย X-Forwarded-For -> entropy สูง -> ตรวจไม่เจอ
- ต้องใช้ `use_remote_address: true` + `xff_num_trusted_hops: 0` ที่ envoy

### 7.4 ข้อจำกัดของ Paper
- Paper ใช้ dataset offline (CIC-IDS2017) ไม่ใช่ real-time traffic
- ค่า parameters ที่ optimal จะแตกต่างกันไปตาม traffic pattern ของแต่ละระบบ
- ต้อง tune parameters (beta_lower, delta_attack, delta_susp) ให้เหมาะกับ environment
