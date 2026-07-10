#!/usr/bin/env python3
"""
== 测试目标: 故意含有常见漏洞的 Web 应用 ==
用于验证安全审计系统的检测能力

安全警告: 此文件包含故意引入的安全漏洞，仅供测试使用！
"""

import os
import sqlite3
import subprocess
import pickle
import json
from flask import Flask, request, render_template_string

app = Flask(__name__)


# ============================================================
# 漏洞 1: SQL 注入 (CWE-89)
# ============================================================
@app.route("/user")
def get_user():
    """从 URL 参数获取用户ID并拼接 SQL 查询 — SQL注入漏洞"""
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 漏洞: 直接拼接用户输入到 SQL 查询
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)  # SQL 注入!
    return str(cursor.fetchall())


@app.route("/search")
def search_users():
    """搜索用户 — SQL注入漏洞"""
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 漏洞: 拼接用户输入
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")  # SQL 注入!
    return str(cursor.fetchall())


# ============================================================
# 漏洞 2: 命令注入 (CWE-78)
# ============================================================
@app.route("/ping")
def ping_host():
    """Ping 一个目标主机 — 命令注入漏洞"""
    host = request.args.get("host", "127.0.0.1")
    # 漏洞: 直接拼接用户输入到系统命令
    result = os.system(f"ping -c 3 {host}")  # 命令注入!
    return f"Ping result: {result}"


@app.route("/exec")
def run_command():
    """执行系统命令 — 命令注入漏洞"""
    cmd = request.args.get("cmd", "ls")
    # 漏洞: 直接执行用户输入
    output = subprocess.check_output(cmd, shell=True)  # 命令注入!
    return output.decode()


# ============================================================
# 漏洞 3: 路径遍历 (CWE-22)
# ============================================================
@app.route("/read")
def read_file():
    """读取文件 — 路径遍历漏洞"""
    filename = request.args.get("file", "README.md")
    # 漏洞: 未对路径进行安全校验
    filepath = os.path.join("data", filename)
    with open(filepath, "r") as f:  # 路径遍历!
        return f.read()


# ============================================================
# 漏洞 4: 硬编码密钥 (CWE-798)
# ============================================================

# 直接硬编码的 AWS 密钥
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 硬编码的 API 密钥
API_SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
DB_PASSWORD = "SuperSecretPassword123!@#"
JWT_SECRET = "my-secret-key-change-in-production-12345"

# ============================================================
# 漏洞 5: 不安全的反序列化 (CWE-502)
# ============================================================
@app.route("/deserialize")
def unsafe_deserialize():
    """不安全的反序列化 — Pickle 反序列化漏洞"""
    data = request.args.get("data", "")
    if data:
        # 漏洞: 对不可信数据进行 pickle 反序列化
        obj = pickle.loads(bytes.fromhex(data))  # 不安全反序列化!
        return str(obj)
    return "No data"


# ============================================================
# 漏洞 6: XSS (CWE-79)
# ============================================================
@app.route("/hello")
def hello():
    """简单的问候页面 — XSS 漏洞"""
    name = request.args.get("name", "World")
    # 漏洞: 未转义直接渲染用户输入
    html = f"<h1>Hello, {name}!</h1>"  # XSS!
    return render_template_string(html)


# ============================================================
# 漏洞 7: SSRF (CWE-918)
# ============================================================
import requests

@app.route("/fetch")
def fetch_url():
    """获取远程URL内容 — SSRF漏洞"""
    url = request.args.get("url", "https://example.com")
    # 漏洞: 未对目标URL做白名单校验
    resp = requests.get(url, timeout=5)  # SSRF!
    return resp.text


# ============================================================
# 漏洞 8: 危险文件操作
# ============================================================
@app.route("/delete")
def delete_file():
    """删除文件 — 危险文件操作"""
    path = request.args.get("path", "")
    if path:
        os.remove(path)  # 危险的文件删除操作
        return f"Deleted: {path}"
    return "No path"


# ============================================================
# 正常代码（用于对比）
# ============================================================
def safe_query(user_id):
    """安全的参数化查询（非漏洞）"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # 安全的
    return cursor.fetchall()


if __name__ == "__main__":
    app.run(debug=True, port=8080)
