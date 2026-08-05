import http from 'k6/http';

function randomIP() {
  const r = () => Math.floor(Math.random() * 255);
  return `${Math.floor(Math.random() * 223) + 1}.${r()}.${r()}.${Math.floor(Math.random() * 254) + 1}`;
}

export const options = {
  insecureSkipTLSVerify: true,   // <-- ย้ายมาไว้ตรงนี้ ระดับ global
  discardResponseBodies: true,
  scenarios: {
    calibrate: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '60s',
      preAllocatedVUs: 200,
      maxVUs: 500,
    },
  },
};

export default function () {
  const spoofedIp = randomIP();
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'X-Forwarded-For': spoofedIp,
    'X-Real-IP': spoofedIp,
  };
  http.get('https://10.0.24.35:30221/heavy-logic/', { headers });
}

export function handleSummary(data) {
  const reqRate = data.metrics.http_reqs.values.rate.toFixed(2);
  const totalReqs = data.metrics.http_reqs.values.count;
  const iterCompleted = data.metrics.iterations.values.count;

  console.log(`\n===== SUMMARY =====`);
  console.log(`Total requests   : ${totalReqs}`);
  console.log(`Req/s (avg)      : ${reqRate}`);
  console.log(`Iterations done  : ${iterCompleted}`);
  console.log(`====================\n`);

  return {
    stdout: JSON.stringify(data, null, 2), // เก็บ full raw ไว้ดูย้อนหลังด้วย
  };
}