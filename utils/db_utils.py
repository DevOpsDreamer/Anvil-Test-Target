"""
Database utilities — contains additional SQL injection patterns
that test AEGIS's ability to find vulnerabilities across multiple files.
"""
import sqlite3
import logging

logger = logging.getLogger(__name__)

DATABASE = "app.db"


def get_user_by_id(user_id: str) -> dict:
    """
    Fetch user by ID.
    VULNERABLE: CWE-89 — SQL Injection via string formatting
    Exploit: get_user_by_id("1 OR 1=1")
    """
    conn = sqlite3.connect(DATABASE)
    # VULNERABLE: % string formatting in SQL
    query = "SELECT * FROM users WHERE id = %s" % user_id
    result = conn.execute(query).fetchone()
    conn.close()
    return result


def search_products(category: str, max_price: float) -> list:
    """
    Search products by category.
    VULNERABLE: CWE-89 — SQL Injection via concatenation
    Exploit: search_products("' OR '1'='1", 999)
    """
    conn = sqlite3.connect(DATABASE)
    # VULNERABLE: direct concatenation
    sql = "SELECT * FROM products WHERE category = '" + category + "' AND price < " + str(max_price)
    results = conn.execute(sql).fetchall()
    conn.close()
    return results


def update_user_email(username: str, email: str) -> bool:
    """
    Update user email address.
    VULNERABLE: CWE-89 — SQL Injection in UPDATE statement
    Exploit: update_user_email("admin'--", "hacker@evil.com")
    """
    conn = sqlite3.connect(DATABASE)
    # VULNERABLE: f-string in UPDATE query
    query = f"UPDATE users SET email='{email}' WHERE username='{username}'"
    conn.execute(query)
    conn.commit()
    conn.close()
    return True
