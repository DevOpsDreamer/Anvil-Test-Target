"""
File handling utilities.
VULNERABLE: Multiple path traversal issues (CWE-22)
"""
import os
from flask import request, send_file


def serve_user_file(filename: str) -> str:
    """
    Serve a file from the uploads directory.
    VULNERABLE: CWE-22 — Path traversal via os.path.join with user input
    Exploit: serve_user_file("../../etc/passwd")
    """
    # VULNERABLE: no path validation before open
    base_dir = "uploads"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "r") as f:
        return f.read()


def get_template(template_name: str) -> str:
    """
    Load a template file.
    VULNERABLE: CWE-22 — open() with unvalidated user-controlled path
    Exploit: get_template("../app.py") reads source code
    """
    # VULNERABLE: direct open with user input, no sanitization
    with open(request.args.get("template", template_name), "r") as f:
        return f.read()


def download_report(report_id: str):
    """
    Download a generated report.
    VULNERABLE: CWE-22 — send_file with user-controlled path
    Exploit: download_report("../../flag.txt")
    """
    report_path = f"reports/{report_id}.pdf"
    # VULNERABLE: send_file with user-controlled path
    return send_file(report_path)
