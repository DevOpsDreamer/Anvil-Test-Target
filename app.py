"""
Anvil-Test-Target — Deliberately Vulnerable Flask Application
WARNING: This application contains REAL security vulnerabilities.
For AEGIS research testing ONLY. Never deploy in production.
Each vulnerability is documented with its CWE reference.
"""

from flask import Flask, request, render_template_string, jsonify, session
import sqlite3
import subprocess
import pickle
import base64
import os
import hashlib

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_12345"  # VULN 5: Hardcoded secret

# Initialize database
conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )
""")
conn.execute("""
    CREATE TABLE products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price REAL,
        description TEXT
    )
""")
conn.execute("INSERT INTO users VALUES (1, 'admin', 'supersecret_admin_pass', 'admin')")
conn.execute("INSERT INTO users VALUES (2, 'alice', 'alice_password_456', 'user')")
conn.execute("INSERT INTO users VALUES (3, 'bob', 'bob_password_789', 'user')")
conn.execute("INSERT INTO products VALUES (1, 'Widget', 9.99, 'A basic widget')")
conn.execute("INSERT INTO products VALUES (2, 'Gadget', 19.99, 'A fancy gadget')")
conn.commit()

# Create the secret flag file
os.makedirs("/tmp", exist_ok=True)
with open("/tmp/secret_flag.txt", "w") as f:
    f.write("FLAG{aegis_confirmed_rce_on_test_target}")

# Also create local flag for Windows
with open("flag.txt", "w") as f:
    f.write("FLAG{aegis_confirmed_rce_on_test_target}")


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 1: SQL Injection (CWE-89)
# How to exploit: GET /login?username=admin'--
# What happens: bypasses password check, returns admin credentials
# ─────────────────────────────────────────────────────────────
@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    # VULNERABLE: f-string directly in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        result = conn.execute(query).fetchall()
        if result:
            return jsonify({"status": "success", "user": result[0][1], "role": result[0][3]})
        return jsonify({"status": "failed"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 2: SQL Injection via search (CWE-89)
# How to exploit: GET /search?q=' UNION SELECT username,password,role,4 FROM users--
# What happens: dumps entire users table including passwords
# ─────────────────────────────────────────────────────────────
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: string concatenation in SQL
    sql = "SELECT name, price, description FROM products WHERE name LIKE '%" + query + "%'"
    try:
        results = conn.execute(sql).fetchall()
        return jsonify({"results": [{"name": r[0], "price": r[1]} for r in results]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 3: Command Injection (CWE-78)
# How to exploit: GET /ping?host=localhost;cat flag.txt
# What happens: executes arbitrary system commands
# ─────────────────────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # VULNERABLE: shell=True with user input
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    return jsonify({
        "host": host,
        "output": result.stdout + result.stderr
    })


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 4: Path Traversal (CWE-22)
# How to exploit: GET /file?name=../../etc/passwd
# OR on Windows:  GET /file?name=../../flag.txt
# What happens: reads arbitrary files from the filesystem
# ─────────────────────────────────────────────────────────────
@app.route("/file")
def read_file():
    filename = request.args.get("name", "readme.txt")
    # VULNERABLE: open() with unvalidated user input
    try:
        with open(filename, "r") as f:
            content = f.read()
        return jsonify({"filename": filename, "content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 5: XSS via Template Injection (CWE-79)
# How to exploit: GET /greet?name=<script>alert(document.cookie)</script>
# OR: GET /greet?name={{config.SECRET_KEY}} (SSTI)
# What happens: reflects unsanitized input, leaks secrets
# ─────────────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "stranger")
    # VULNERABLE: render_template_string with f-string and user input
    template = f"""
    <html>
    <body>
        <h1>Hello, {name}!</h1>
        <p>Welcome to the application.</p>
    </body>
    </html>
    """
    return render_template_string(template)


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 6: Insecure Deserialization (CWE-502)
# How to exploit: POST /load with base64-encoded pickle payload
# Malicious payload: pickle.dumps(os.system("cat flag.txt"))
# What happens: executes arbitrary Python code
# ─────────────────────────────────────────────────────────────
@app.route("/load", methods=["POST"])
def load_data():
    try:
        raw = request.data
        # VULNERABLE: pickle.loads on untrusted data
        data = base64.b64decode(raw)
        obj = pickle.loads(data)
        return jsonify({"loaded": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 7: SSRF (CWE-918)
# How to exploit: GET /fetch?url=http://169.254.169.254/metadata
# OR: GET /fetch?url=file:///etc/passwd
# What happens: server makes requests to internal/local resources
# ─────────────────────────────────────────────────────────────
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # VULNERABLE: requests.get with user-controlled URL
    import requests as req
    try:
        response = req.get(url, timeout=5)
        return jsonify({
            "status": response.status_code,
            "content": response.text[:500]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# VULNERABILITY 8: Broken Authentication (CWE-287)
# How to exploit: GET /admin — no auth check at all
# What happens: admin panel accessible without login
# ─────────────────────────────────────────────────────────────
@app.route("/admin")
def admin_panel():
    # VULNERABLE: no authentication check whatsoever
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify({
        "message": "Admin panel — all users",
        "users": [{"id": u[0], "username": u[1], "role": u[2]} for u in users]
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "anvil-test-target"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9999, debug=True)
