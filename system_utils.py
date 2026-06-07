"""
System utilities.
VULNERABLE: Multiple command injection patterns (CWE-78)
"""
import os
import subprocess
from flask import request


def run_diagnostics(host: str) -> str:
    """
    Run network diagnostics.
    VULNERABLE: CWE-78 — os.system with user input
    Exploit: run_diagnostics("localhost; cat flag.txt")
    """
    # VULNERABLE: os.system with user-controlled input
    os.system(f"ping -c 1 {host} > /tmp/diag_output.txt")
    with open("/tmp/diag_output.txt") as f:
        return f.read()


def check_service(service_name: str) -> dict:
    """
    Check if a system service is running.
    VULNERABLE: CWE-78 — subprocess with shell=True and user input
    Exploit: check_service("nginx; cat /tmp/secret_flag.txt")
    """
    # VULNERABLE: shell=True with f-string
    result = subprocess.run(
        f"systemctl status {service_name}",
        shell=True,
        capture_output=True,
        text=True
    )
    return {"service": service_name, "output": result.stdout}


def process_image(image_path: str) -> str:
    """
    Process an uploaded image with ImageMagick.
    VULNERABLE: CWE-78 — os.popen with user-controlled path
    Exploit: process_image("x.jpg; cat flag.txt")
    """
    # VULNERABLE: os.popen with user input
    output = os.popen(f"identify {image_path}").read()
    return output
