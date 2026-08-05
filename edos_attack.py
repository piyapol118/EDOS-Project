import urllib3
from locust import HttpUser, constant, task

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EDoSAttacker(HttpUser):
    wait_time = constant(0.1)

    @task
    def attack_heavy_endpoint(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        with self.client.get(
            "/heavy-logic/", headers=headers, verify=False, catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 429:
                response.failure(f"Blocked by Envoy (429 Too Many Requests)")
            else:
                response.failure(
                    f"Unexpected status code: {response.status_code}"
                )