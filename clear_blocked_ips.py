#!/usr/bin/env python3
"""
Script to clear/reset/delete blocked_ips.json
Supports running:
1. Inside Docker container (/data/blocked_ips.json)
2. On Host via kubectl exec into entropy-detector Pod
3. Locally on the current machine
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime, timezone

# Ensure stdout handles utf-8 safely on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_PATHS = [
    os.environ.get("BLOCKED_IPS_FILE", "/data/blocked_ips.json"),
    "./data/blocked_ips.json",
    "./blocked_ips.json",
]


def clear_local_file(file_path: str, mode: str = "reset"):
    if not os.path.exists(file_path):
        return False

    if mode == "delete":
        os.remove(file_path)
        print(f"[OK] Deleted local file: {file_path}")
    else:
        empty_data = {
            "blocked_ips": [],
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(empty_data, f, indent=2)
        print(f"[OK] Reset local file: {file_path} -> 0 blocked IPs")
    return True


def clear_k8s_pod(namespace: str = "default", mode: str = "reset"):
    try:
        cmd_get = [
            "kubectl", "get", "pods",
            "-n", namespace,
            "-l", "app=entropy-detector",
            "-o", "jsonpath={.items[*].metadata.name}"
        ]
        res = subprocess.run(cmd_get, capture_output=True, text=True, timeout=10)
        if res.returncode != 0 or not res.stdout.strip():
            return False

        pods = res.stdout.strip().split()
        for pod in pods:
            if mode == "delete":
                cmd_exec = [
                    "kubectl", "exec", "-n", namespace, pod, "--",
                    "rm", "-f", "/data/blocked_ips.json"
                ]
                subprocess.run(cmd_exec, capture_output=True, text=True, timeout=10)
                print(f"[OK] Deleted /data/blocked_ips.json inside K8s Pod: {pod}")
            else:
                empty_json = '{"blocked_ips": [], "updated_at": ""}'
                cmd_exec = [
                    "kubectl", "exec", "-n", namespace, pod, "--",
                    "sh", "-c", f'echo \'{empty_json}\' > /data/blocked_ips.json'
                ]
                subprocess.run(cmd_exec, capture_output=True, text=True, timeout=10)
                print(f"[OK] Reset /data/blocked_ips.json inside K8s Pod: {pod} -> 0 blocked IPs")
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="Clear or delete blocked_ips.json")
    parser.add_argument(
        "--mode",
        choices=["reset", "delete"],
        default="reset",
        help="reset = set to empty [] (recommended), delete = delete file completely"
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Specific path to blocked_ips.json"
    )
    parser.add_argument(
        "--namespace",
        type=str,
        default="default",
        help="Kubernetes Namespace (default: default)"
    )
    args = parser.parse_args()

    found = False

    # 1. Custom path
    if args.file:
        if clear_local_file(args.file, args.mode):
            found = True

    # 2. Local default paths
    for p in DEFAULT_PATHS:
        if clear_local_file(p, args.mode):
            found = True

    # 3. K8s Pods
    if clear_k8s_pod(namespace=args.namespace, mode=args.mode):
        found = True

    if found:
        print("[SUCCESS] Blocked IPs cleared successfully!")
    else:
        print("[INFO] No blocked_ips.json found locally or in Kubernetes pods.")


if __name__ == "__main__":
    main()
